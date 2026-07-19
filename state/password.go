package state

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// BENCO addition. Upstream stores MD5 password *equivalents* — single-round
// MD5(salt‖pass‖const) values that the BUCP challenge-response handshake needs
// the server to be able to reproduce. Anyone holding a copy of the database can
// therefore sign in as any user without cracking anything, because the stored
// value IS the credential.
//
// BENCO drops BUCP (see CLAUDE.md), which removes the only reason to keep a
// reproducible hash. Every remaining auth path already has the cleartext
// password in hand at verification time, so a one-way KDF drops straight in.

// Argon2id parameters.
//
// argon2id rather than argon2i or argon2d: it is the hybrid, and the variant
// RFC 9106 recommends when you have no specific reason to choose otherwise. It
// resists GPU cracking through memory hardness and side-channel attacks through
// the data-independent first pass.
//
// These are OWASP's recommended argon2id configuration.
//
// An earlier draft used 64 MiB on the reasoning that sign-ins are rare and
// human-paced. That reasoning is wrong, and the way it is wrong is worth
// recording: the login rate is not ours to choose. Every unauthenticated login
// attempt makes the server allocate this much memory before any password is
// checked, so the memory cost is an amplification factor handed to whoever is
// sending the attempts. At 64 MiB a trivial trickle of concurrent sign-on frames
// exhausts a small VPS; at 19 MiB the same trickle is survivable. The parameter
// that protects a stolen database is also a parameter an attacker can pull on.
//
// 19 MiB / t=2 / p=1 keeps offline cracking expensive while keeping the online
// cost bounded, and it is the configuration OWASP names first.
//
// Changing these does NOT invalidate existing hashes — the parameters are stored
// inside each encoded hash and used when verifying it. Raising the cost affects
// passwords hashed from then on.
const (
	argon2Time    = 2
	argon2Memory  = 19 * 1024 // KiB, so 19 MiB
	argon2Threads = 1
	argon2SaltLen = 16
	argon2KeyLen  = 32
)

// ErrPasswordHashInvalid is returned when a stored hash cannot be parsed.
var ErrPasswordHashInvalid = errors.New("password hash is malformed")

// NewPasswordHash derives an argon2id hash of password and returns it in PHC
// string format:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<base64 salt>$<base64 hash>
//
// The format is self-describing: the variant, version, and cost parameters
// travel with each hash. That is what allows the constants above to be raised
// later without a migration and without locking anyone out — an old hash is
// still verifiable with the parameters it was created under.
//
// Named NewPasswordHash rather than HashPassword to stay distinct from the
// (*User).HashPassword method, which validates length and assigns the result.
func NewPasswordHash(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate password salt: %w", err)
	}
	return encodeArgon2Hash(password, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen), nil
}

func encodeArgon2Hash(password string, salt []byte, time, memory uint32, threads uint8, keyLen uint32) string {
	key := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		memory, time, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

// VerifyPassword reports whether password matches the PHC-encoded hash.
//
// It returns false rather than an error for every failure mode, including a
// malformed or empty stored hash. Callers are auth paths deciding whether to let
// someone in, and for that decision "the stored hash is corrupt" and "the
// password is wrong" have to reach the same answer. ParsePasswordHash is
// available where the distinction matters, such as diagnostics.
//
// A user row with no password hash — for instance one migrated from the old MD5
// columns, which cannot be converted — therefore fails every login until the
// password is reset through the management API. That is the intended behaviour:
// the alternative is an account that authenticates against nothing.
func VerifyPassword(encoded, password string) bool {
	params, salt, want, err := ParsePasswordHash(encoded)
	if err != nil {
		return false
	}

	got := argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, uint32(len(want)))

	// Constant time: a timing-variable comparison leaks how many leading bytes
	// of the derived key matched, which is enough to reconstruct it byte by byte.
	return subtle.ConstantTimeCompare(got, want) == 1
}

// Argon2Params are the cost parameters recovered from an encoded hash.
type Argon2Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
}

// ParsePasswordHash splits a PHC-encoded argon2id hash into its parameters, salt
// and derived key.
func ParsePasswordHash(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// Leading "$" produces an empty first element, so a well-formed hash splits
	// into exactly six parts.
	if len(parts) != 6 || parts[0] != "" {
		return Argon2Params{}, nil, nil, ErrPasswordHashInvalid
	}
	if parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: unsupported variant %q", ErrPasswordHashInvalid, parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: bad version field", ErrPasswordHashInvalid)
	}
	if version != argon2.Version {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: unsupported argon2 version %d", ErrPasswordHashInvalid, version)
	}

	var params Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Time, &params.Threads); err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: bad parameter field", ErrPasswordHashInvalid)
	}
	// A hash claiming absurd cost would let a malformed or hostile row stall the
	// server for minutes and exhaust memory on every login attempt. Reject
	// anything demanding more than 1 GiB.
	if params.Memory == 0 || params.Memory > 1024*1024 || params.Time == 0 || params.Threads == 0 {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: implausible cost parameters", ErrPasswordHashInvalid)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: bad salt encoding", ErrPasswordHashInvalid)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: bad key encoding", ErrPasswordHashInvalid)
	}
	if len(salt) == 0 || len(key) == 0 {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: empty salt or key", ErrPasswordHashInvalid)
	}

	return params, salt, key, nil
}
