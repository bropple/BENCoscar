package state

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BENCO addition — see password.go.

func TestNewPasswordHash_ProducesVerifiableHash(t *testing.T) {
	hash, err := NewPasswordHash("correct horse battery")
	require.NoError(t, err)
	require.NotEmpty(t, hash)

	assert.True(t, strings.HasPrefix(hash, "$argon2id$v=19$"),
		"expected a PHC-format argon2id hash, got %q", hash)
	assert.True(t, VerifyPassword(hash, "correct horse battery"))
	assert.False(t, VerifyPassword(hash, "correct horse batterz"))
}

func TestNewPasswordHash_SaltsAreUnique(t *testing.T) {
	// Two hashes of the same password must differ. A per-hash random salt is
	// what stops identical passwords being visibly identical in the database,
	// and what makes precomputed tables useless. Upstream's scheme reused one
	// stored AuthKey per user, so this property is new.
	a, err := NewPasswordHash("same password")
	require.NoError(t, err)
	b, err := NewPasswordHash("same password")
	require.NoError(t, err)

	assert.NotEqual(t, a, b)
	assert.True(t, VerifyPassword(a, "same password"))
	assert.True(t, VerifyPassword(b, "same password"))
}

func TestVerifyPassword_RejectsUnusableHashes(t *testing.T) {
	// Every one of these must be a rejection rather than a panic or an accept.
	// The empty case is the important one: a user row migrated from the old MD5
	// columns has no hash, and must fail every login rather than authenticate
	// against nothing.
	cases := []struct {
		name   string
		hash   string
		passwd string
	}{
		{name: "empty hash", hash: "", passwd: "anything"},
		{name: "empty hash and empty password", hash: "", passwd: ""},
		{name: "not a PHC string", hash: "hunter2", passwd: "hunter2"},
		{name: "too few fields", hash: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA", passwd: "x"},
		{name: "wrong variant", hash: "$argon2i$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA", passwd: "x"},
		{name: "bad version field", hash: "$argon2id$vNINETEEN$m=65536,t=3,p=2$c2FsdA$aGFzaA", passwd: "x"},
		{name: "unsupported version", hash: "$argon2id$v=16$m=65536,t=3,p=2$c2FsdA$aGFzaA", passwd: "x"},
		{name: "bad parameter field", hash: "$argon2id$v=19$m=lots$c2FsdA$aGFzaA", passwd: "x"},
		{name: "zero memory", hash: "$argon2id$v=19$m=0,t=3,p=2$c2FsdA$aGFzaA", passwd: "x"},
		{name: "zero time", hash: "$argon2id$v=19$m=65536,t=0,p=2$c2FsdA$aGFzaA", passwd: "x"},
		{name: "zero threads", hash: "$argon2id$v=19$m=65536,t=3,p=0$c2FsdA$aGFzaA", passwd: "x"},
		{name: "bad salt encoding", hash: "$argon2id$v=19$m=65536,t=3,p=2$!!!$aGFzaA", passwd: "x"},
		{name: "bad key encoding", hash: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$!!!", passwd: "x"},
		{name: "empty salt", hash: "$argon2id$v=19$m=65536,t=3,p=2$$aGFzaA", passwd: "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, VerifyPassword(tc.hash, tc.passwd))
		})
	}
}

func TestParsePasswordHash_RejectsImplausibleCost(t *testing.T) {
	// A hash claiming absurd memory would let one malformed or hostile row stall
	// the server and exhaust memory on every login attempt against that account.
	_, _, _, err := ParsePasswordHash("$argon2id$v=19$m=99999999,t=3,p=2$c2FsdA$aGFzaA")
	assert.ErrorIs(t, err, ErrPasswordHashInvalid)
}

func TestVerifyPassword_HonoursParametersInTheHash(t *testing.T) {
	// The cost parameters are read from the stored hash, not from the current
	// constants. This is what allows argon2Time/argon2Memory to be raised later
	// without a migration and without locking existing users out — the claim
	// made in password.go and docs/BENCO_TLS.md's sibling docs.
	//
	// Deliberately weaker-than-current parameters, standing in for a hash
	// written before a cost increase.
	weak := encodeArgon2Hash("legacy password", []byte("0123456789abcdef"), 1, 8*1024, 1, 32)

	params, _, _, err := ParsePasswordHash(weak)
	require.NoError(t, err)
	require.Equal(t, uint32(1), params.Time)
	require.Equal(t, uint32(8*1024), params.Memory)
	require.NotEqual(t, uint32(argon2Memory), params.Memory, "fixture should differ from current cost")

	assert.True(t, VerifyPassword(weak, "legacy password"))
	assert.False(t, VerifyPassword(weak, "wrong password"))
}

func TestUser_PasswordRoundTripsThroughEveryAuthPath(t *testing.T) {
	// Each remaining auth path undoes its own transport-level obfuscation and
	// then verifies the same argon2id hash. This asserts they all agree, which
	// is the property that let BUCP be dropped: every one of these receives (or
	// recovers) the cleartext, so none needs a reproducible server-side hash.
	const password = "the_password"

	u := User{}
	require.NoError(t, u.HashPassword(password))

	t.Run("plaintext", func(t *testing.T) {
		assert.True(t, u.ValidatePlaintextPass([]byte(password)))
		assert.False(t, u.ValidatePlaintextPass([]byte("wrong")))
	})

	t.Run("BUCP is refused regardless of input", func(t *testing.T) {
		// Not "returns false because the hash mismatches" — false always, by
		// construction. BUCP is unsupported in this fork.
		assert.False(t, u.ValidateHash([]byte(password)))
		assert.False(t, u.ValidateHash(nil))
	})
}

func TestUser_HashPassword_LeavesNoPasswordEquivalent(t *testing.T) {
	// The point of the whole change: what lands in the database must not itself
	// be usable to sign in. Assert the stored value is not the password, and
	// does not contain it.
	const password = "the_password"

	u := User{}
	require.NoError(t, u.HashPassword(password))

	assert.NotEqual(t, password, u.PasswordHash)
	assert.NotContains(t, u.PasswordHash, password)
	assert.True(t, VerifyPassword(u.PasswordHash, password))
}
