package foodgroup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// BENCO addition: the device key directory service (foodgroup 0xBE00).
// See wire/benco_keydir.go for the protocol and why it exists.

// KeyDirManager is storage for signed device manifests and identity backups.
type KeyDirManager interface {
	// KeyManifest returns an account's published manifest, or (nil, nil) if it
	// has published none.
	KeyManifest(ctx context.Context, screenName state.IdentScreenName) (*state.KeyManifest, error)
	// PublishManifest stores a manifest, returning the counter now held. It
	// returns state.ErrStaleCounter if the counter did not move forward under
	// an unchanged identity.
	PublishManifest(ctx context.Context, screenName state.IdentScreenName, m state.KeyManifest) (uint64, error)
	// IdentityBackup returns an account's encrypted identity key, or (nil, nil).
	IdentityBackup(ctx context.Context, screenName state.IdentScreenName) (*state.IdentityBackup, error)
	// SetIdentityBackup stores or replaces an account's encrypted identity key.
	SetIdentityBackup(ctx context.Context, screenName state.IdentScreenName, b state.IdentityBackup) error
}

// NewBENCOKeyDirService returns a device key directory service.
func NewBENCOKeyDirService(logger *slog.Logger, keyDirManager KeyDirManager) BENCOKeyDirService {
	return BENCOKeyDirService{
		logger:        logger,
		keyDirManager: keyDirManager,
	}
}

// BENCOKeyDirService serves the device key directory.
//
// It handles only PUBLIC keys and ciphertext. The server cannot read any message
// this directory helps encrypt, cannot open the identity backup it stores, and
// nothing here would help it — which is the property that makes a server-side
// key directory compatible with end-to-end encryption in the first place.
//
// What it does NOT provide, and this is worth being blunt about because a
// protocol carrying signatures is easy to misread as making the server
// trustworthy:
//
//   - It cannot tell which DEVICE is talking to it. A session authenticates with
//     an account password, so every check in this file is advisory. The
//     signatures are what actually bind anything.
//   - It can still refuse service, drop a publish, or serve an old manifest.
//     Signatures prove authenticity, not availability or freshness.
//   - It sees all the metadata: who queries whom, how many devices exist, and
//     their labels when set.
//
// The design accounts for all three. Clients verify signatures themselves and
// track counters themselves, so a server that lies is caught rather than
// believed.
type BENCOKeyDirService struct {
	logger        *slog.Logger
	keyDirManager KeyDirManager
}

// PublishManifest stores the sending account's signed device manifest.
//
// The screen name comes from the session, never from the request. There is no
// field for one out here, and the one INSIDE the signed manifest is checked
// against the session rather than trusted: a manifest is a valid signed object
// no matter whose account it is presented on, so without that check a manifest
// lifted from one account could be replayed onto another and would verify
// perfectly.
func (s BENCOKeyDirService) PublishManifest(
	ctx context.Context,
	sess *state.Session,
	inFrame wire.SNACFrame,
	inBody wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest,
) (wire.SNACMessage, error) {

	screenName := sess.IdentScreenName()

	manifest, err := s.validatePublish(screenName, inBody)
	if err != nil {
		s.logger.DebugContext(ctx, "rejecting manifest",
			"screen_name", screenName, "err", err.Error())
		return errSNAC(inFrame, wire.ErrorCodeInvalidSnac), nil
	}

	stored := state.KeyManifest{
		IdentityAlg: manifest.Identity.Alg,
		IdentityKey: manifest.Identity.Key,
		Counter:     manifest.Counter,
		IssuedAt:    time.Unix(int64(manifest.IssuedAt), 0),
		// Verbatim. The decoded struct above was used to CHECK this blob and is
		// then discarded; re-encoding it would break the signature. See the
		// storage layer.
		Manifest:  inBody.Manifest,
		SigAlg:    inBody.SigAlg,
		Signature: inBody.Signature,
	}

	counter, err := s.keyDirManager.PublishManifest(ctx, screenName, stored)
	if err != nil {
		if errors.Is(err, state.ErrStaleCounter) || errors.Is(err, state.ErrCounterOutOfRange) {
			// Not a server fault, and the reply still carries the counter the
			// server holds so a client that lost a race learns what to beat
			// without having to re-query.
			s.logger.DebugContext(ctx, "refusing stale manifest",
				"screen_name", screenName, "err", err.Error())
			return wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BENCOKeyDir,
					SubGroup:  wire.BENCOKeyDirPublishReply,
					RequestID: inFrame.RequestID,
				},
				Body: wire.SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply{
					Accepted: 0,
					Counter:  counter,
				},
			}, nil
		}
		return wire.SNACMessage{}, err
	}

	s.logger.InfoContext(ctx, "published a device manifest",
		"screen_name", screenName, "counter", counter, "devices", len(manifest.Devices))

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BENCOKeyDir,
			SubGroup:  wire.BENCOKeyDirPublishReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply{
			Accepted: 1,
			Counter:  counter,
		},
	}, nil
}

// QueryManifest returns an account's signed manifest.
//
// Any signed-in user may query any account. A manifest is public by
// construction — it is a list of public keys whose whole purpose is to be handed
// out, and a peer learns the same keys the moment they exchange a message.
// Withholding it would break encrypting to a user without protecting anything.
//
// The manifest is returned byte-for-byte as it was published. Anything else
// would invalidate the signature the caller is about to check.
func (s BENCOKeyDirService) QueryManifest(
	ctx context.Context,
	inFrame wire.SNACFrame,
	inBody wire.SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest,
) (wire.SNACMessage, error) {

	screenName := state.NewIdentScreenName(inBody.ScreenName)

	m, err := s.keyDirManager.KeyManifest(ctx, screenName)
	if err != nil {
		return wire.SNACMessage{}, err
	}

	out := wire.SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply{
		ScreenName: inBody.ScreenName,
	}
	if m != nil {
		out.Present = 1
		out.Manifest = m.Manifest
		out.SigAlg = m.SigAlg
		out.Signature = m.Signature
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BENCOKeyDir,
			SubGroup:  wire.BENCOKeyDirQueryReply,
			RequestID: inFrame.RequestID,
		},
		Body: out,
	}, nil
}

// PutBackup stores the sending account's encrypted identity key.
//
// Scoped to the session's own account, like publishing. The blob is ciphertext,
// but letting one account write another's backup would let an attacker replace
// an identity key with one they can open, which is an account takeover dressed
// up as a storage write.
func (s BENCOKeyDirService) PutBackup(
	ctx context.Context,
	sess *state.Session,
	inFrame wire.SNACFrame,
	inBody wire.SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest,
) (wire.SNACMessage, error) {

	if err := validateBackup(inBody); err != nil {
		s.logger.DebugContext(ctx, "rejecting identity backup",
			"screen_name", sess.IdentScreenName(), "err", err.Error())
		return errSNAC(inFrame, wire.ErrorCodeInvalidSnac), nil
	}

	err := s.keyDirManager.SetIdentityBackup(ctx, sess.IdentScreenName(), state.IdentityBackup{
		KDF:    inBody.KDF,
		Params: inBody.Params,
		Salt:   inBody.Salt,
		Blob:   inBody.Blob,
	})
	if err != nil {
		return wire.SNACMessage{}, err
	}

	// Worth a log line: this is either an account bootstrapping an identity for
	// the first time or one re-keying its recovery phrase, and both are rare
	// enough that seeing them in a log is useful rather than noise.
	s.logger.InfoContext(ctx, "stored an identity backup",
		"screen_name", sess.IdentScreenName())

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BENCOKeyDir,
			SubGroup:  wire.BENCOKeyDirPutBackupReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0xBE00_0x0007_BENCOKeyDirPutBackupReply{Stored: 1},
	}, nil
}

// GetBackup returns the sending account's encrypted identity key.
//
// The screen name comes from the session and the request has no field for one.
// That is a real boundary, not tidiness: the blob is encrypted, but once someone
// holds it they can attack it offline with no rate limiting, so serving one
// account's backup to another would reduce a takeover to a dictionary attack run
// at leisure against a phrase the user wrote on paper years ago.
//
// Present = 0 for an account that has never bootstrapped an identity. That is
// the normal first-run answer, not an error, and it is what tells a client to
// generate an identity rather than prompt for a recovery phrase.
func (s BENCOKeyDirService) GetBackup(
	ctx context.Context,
	sess *state.Session,
	inFrame wire.SNACFrame,
	_ wire.SNAC_0xBE00_0x0008_BENCOKeyDirGetBackupRequest,
) (wire.SNACMessage, error) {

	b, err := s.keyDirManager.IdentityBackup(ctx, sess.IdentScreenName())
	if err != nil {
		return wire.SNACMessage{}, err
	}

	out := wire.SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply{}
	if b != nil {
		out.Present = 1
		out.KDF = b.KDF
		out.Params = b.Params
		out.Salt = b.Salt
		out.Blob = b.Blob
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BENCOKeyDir,
			SubGroup:  wire.BENCOKeyDirGetBackupReply,
			RequestID: inFrame.RequestID,
		},
		Body: out,
	}, nil
}

// validatePublish decodes and checks a publish request, returning the decoded
// manifest for its metadata only.
//
// The returned struct is used to read the counter, timestamp and identity key,
// and is then thrown away. The BYTES are what gets stored. Nothing in this
// package may re-encode a manifest.
func (s BENCOKeyDirService) validatePublish(
	screenName state.IdentScreenName,
	in wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest,
) (wire.BENCOManifest, error) {

	var m wire.BENCOManifest

	if in.Version != wire.BENCOKeyDirVersion {
		return m, fmt.Errorf("unsupported payload version %d", in.Version)
	}
	if len(in.Manifest) == 0 {
		return m, errors.New("manifest is empty")
	}
	if len(in.Manifest) > wire.BENCOKeyDirMaxManifestLen {
		return m, fmt.Errorf("manifest is %d bytes, limit is %d", len(in.Manifest), wire.BENCOKeyDirMaxManifestLen)
	}

	if err := wire.UnmarshalBE(&m, bytes.NewReader(in.Manifest)); err != nil {
		return m, fmt.Errorf("manifest does not decode: %w", err)
	}
	if m.Version != wire.BENCOKeyDirVersion {
		return m, fmt.Errorf("unsupported manifest version %d", m.Version)
	}

	// The screen name inside the signature must be the session's. Without this,
	// a manifest is a portable signed object: lift Alice's, present it on a
	// session for an account you control, and the signature still verifies. The
	// check is what binds the statement to the account it was made for.
	if state.NewIdentScreenName(m.ScreenName) != screenName {
		return m, fmt.Errorf("manifest names %q but the session is %q", m.ScreenName, screenName)
	}

	// Counter 0 is refused so that "no manifest" and "the first manifest" cannot
	// be confused by anything downstream that treats a zero value as unset.
	if m.Counter == 0 {
		return m, errors.New("counter must start at 1")
	}

	if len(m.Devices) > state.MaxDevicesPerAccount {
		return m, fmt.Errorf("manifest has %d devices, limit is %d", len(m.Devices), state.MaxDevicesPerAccount)
	}
	for i, d := range m.Devices {
		if err := validateDeviceKey(d.Box, wire.BENCOAlgX25519); err != nil {
			return m, fmt.Errorf("device %d box key: %w", i, err)
		}
		if err := validateDeviceKey(d.Sign, wire.BENCOAlgEd25519); err != nil {
			return m, fmt.Errorf("device %d signing key: %w", i, err)
		}
	}

	if err := verifyManifestSignature(m.Identity, in.SigAlg, in.Signature, in.Manifest); err != nil {
		return m, err
	}

	return m, nil
}

// verifyManifestSignature checks the detached signature over the manifest bytes.
//
// # This is NOT a security boundary
//
// It is a cheap filter that keeps garbage out of the table, and that is all it
// is. A server that wanted to serve a forged manifest would simply not run this
// check, so a client learns nothing from the fact that the server performed it.
// Clients MUST verify independently, against an identity key they already trust
// from their own trust store — that verification is the one that decides
// anything. The value of doing it here is that an account cannot fill the
// directory with unverifiable blobs that every peer then has to fetch and reject.
//
// The identity key vouching for its own manifest is not circular. It proves the
// manifest was issued by whoever holds that identity; whether the client should
// trust that identity at all is a separate question, and one the server has no
// standing to answer.
//
// Only Ed25519 is accepted. The reserved post-quantum identifiers exist so a
// future migration is a version bump, but a signature the server cannot verify
// would mean storing an unchecked blob under the pretence of having checked it,
// which is worse than refusing it.
func verifyManifestSignature(identity wire.BENCOKey, sigAlg uint8, sig, manifest []byte) error {
	if identity.Alg != wire.BENCOAlgEd25519 {
		return fmt.Errorf("identity key algorithm %#x is not supported for signing", identity.Alg)
	}
	if len(identity.Key) != wire.BENCOEd25519KeyLen {
		return fmt.Errorf("identity key must be %d bytes", wire.BENCOEd25519KeyLen)
	}
	if sigAlg != wire.BENCOAlgEd25519 {
		return fmt.Errorf("signature algorithm %#x is not supported", sigAlg)
	}
	if len(sig) != wire.BENCOEd25519SigLen {
		return fmt.Errorf("signature must be %d bytes", wire.BENCOEd25519SigLen)
	}
	if !ed25519.Verify(ed25519.PublicKey(identity.Key), manifest, sig) {
		return errors.New("signature does not verify against the identity key in the manifest")
	}
	return nil
}

// validateDeviceKey rejects malformed key material before it reaches storage.
//
// Length is checked rather than trusted because these values are handed to
// clients as encryption keys: a wrong-length "key" stored here would produce
// undecryptable messages for everyone who fetched it, and the failure would look
// like a client bug a long way from its cause.
//
// A key is optional — a device that has not generated a signing key publishes an
// empty one, encoded as algorithm 0 with a zero-length key — but a present one
// must name the expected algorithm and be the right size for it. The reserved
// post-quantum identifiers are refused here too: accepting a key for a scheme
// nothing implements would put material in the directory that no client can use
// and no server can check.
func validateDeviceKey(k wire.BENCOKey, want uint8) error {
	if k.Alg == 0 && len(k.Key) == 0 {
		return nil // absent, which is legitimate
	}
	if k.Alg != want {
		return fmt.Errorf("algorithm %#x is not supported here, expected %#x", k.Alg, want)
	}
	if len(k.Key) != wire.BENCOX25519KeyLen {
		// X25519 and Ed25519 public keys are both 32 bytes, so one constant
		// covers both branches; they are named separately in wire so that stops
		// being true silently if either ever changes.
		return fmt.Errorf("key must be %d bytes, got %d", wire.BENCOX25519KeyLen, len(k.Key))
	}
	return nil
}

// validateBackup bounds an identity backup before storing it.
//
// The server cannot check that the blob decrypts — it has neither the phrase nor
// the derived key, which is the entire point — so validation is limited to what
// is checkable: a KDF identifier that means something, and sizes that keep this
// from becoming a general-purpose file host.
func validateBackup(in wire.SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest) error {
	if in.Version != wire.BENCOKeyDirVersion {
		return fmt.Errorf("unsupported payload version %d", in.Version)
	}
	if in.KDF != wire.BENCOKDFArgon2id {
		return fmt.Errorf("unsupported KDF %#x", in.KDF)
	}
	if len(in.Salt) == 0 || len(in.Blob) == 0 {
		return errors.New("salt and blob must be present")
	}
	for _, f := range []struct {
		name string
		val  []byte
	}{
		{"params", in.Params},
		{"salt", in.Salt},
		{"blob", in.Blob},
	} {
		if len(f.val) > wire.BENCOKeyDirMaxBackupLen {
			return fmt.Errorf("%s is %d bytes, limit is %d", f.name, len(f.val), wire.BENCOKeyDirMaxBackupLen)
		}
	}
	return nil
}

// errSNAC builds a foodgroup error reply.
func errSNAC(inFrame wire.SNACFrame, code uint16) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BENCOKeyDir,
			SubGroup:  wire.BENCOKeyDirErr,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNACError{Code: code},
	}
}
