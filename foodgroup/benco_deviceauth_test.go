package foodgroup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// fakeManifests serves a prepared manifest blob.
type fakeManifests struct {
	stored *state.KeyManifest
	err    error
}

func (f fakeManifests) KeyManifest(context.Context, state.IdentScreenName) (*state.KeyManifest, error) {
	return f.stored, f.err
}

func mustNonce(t *testing.T) []byte {
	t.Helper()
	n := make([]byte, wire.BENCOAttestNonceLen)
	if _, err := rand.Read(n); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return n
}

// manifestWith builds a stored manifest naming the given signing keys.
func manifestWith(t *testing.T, signKeys ...ed25519.PublicKey) *state.KeyManifest {
	t.Helper()
	m := wire.BENCOManifest{Version: wire.BENCOKeyDirVersion, Counter: 1}
	for _, k := range signKeys {
		m.Devices = append(m.Devices, wire.BENCODevice{
			Box:   wire.BENCOKey{Alg: 1, Key: make([]byte, 32)},
			Sign:  wire.BENCOKey{Alg: 1, Key: k},
			Label: "device",
		})
	}
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(m, buf); err != nil {
		t.Fatalf("MarshalBE: %v", err)
	}
	return &state.KeyManifest{Manifest: buf.Bytes(), Counter: 1}
}

// TestAttestAcceptsAnEnrolledDevice is the happy path.
func TestAttestAcceptsAnEnrolledDevice(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sn := state.NewIdentScreenName("alice")
	svc := NewDeviceAuthService(fakeManifests{stored: manifestWith(t, pub)})

	nonce := mustNonce(t)
	sig := SignAttestation(sn, nonce, priv)

	if err := svc.Verify(context.Background(), sn, nonce, pub, sig); err != nil {
		t.Fatalf("an enrolled device was refused: %v", err)
	}
}

// TestAttestRefusesARemovedDevice is the finding this exists to close.
//
// A device dropped from the manifest kept full account access, because it signed
// in with the same password as before and the server had no way to tell.
func TestAttestRefusesARemovedDevice(t *testing.T) {
	staying, _, _ := ed25519.GenerateKey(rand.Reader)
	removedPub, removedPriv, _ := ed25519.GenerateKey(rand.Reader)
	sn := state.NewIdentScreenName("alice")

	// The manifest names only the device that remains.
	svc := NewDeviceAuthService(fakeManifests{stored: manifestWith(t, staying)})

	nonce := mustNonce(t)
	sig := SignAttestation(sn, nonce, removedPriv)

	err := svc.Verify(context.Background(), sn, nonce, removedPub, sig)
	if !errors.Is(err, ErrDeviceNotEnrolled) {
		t.Errorf("a removed device got %v, want ErrDeviceNotEnrolled", err)
	}
}

// TestAttestBootstrapsAnAccountWithNoDevices: a freshly provisioned account has
// published nothing, so its first device must be able to get in to publish
// itself. This is also the recovery path for somebody who lost every device —
// an operator clears the list and the account is here again.
func TestAttestBootstrapsAnAccountWithNoDevices(t *testing.T) {
	sn := state.NewIdentScreenName("newcomer")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	for name, mgr := range map[string]fakeManifests{
		"never published": {stored: nil},
		"empty manifest":  {stored: &state.KeyManifest{}},
		"no devices":      {stored: manifestWith(t)},
	} {
		svc := NewDeviceAuthService(mgr)
		nonce := mustNonce(t)
		err := svc.Verify(context.Background(), sn, nonce, pub, SignAttestation(sn, nonce, priv))
		if !errors.Is(err, ErrNoDevicesEnrolled) {
			t.Errorf("%s: got %v, want ErrNoDevicesEnrolled", name, err)
		}
	}
}

// TestAttestRefusesAForgedSignature: holding an enrolled PUBLIC key proves
// nothing — anybody can read one out of the directory.
func TestAttestRefusesAForgedSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	sn := state.NewIdentScreenName("alice")
	svc := NewDeviceAuthService(fakeManifests{stored: manifestWith(t, pub)})

	nonce := mustNonce(t)
	// Signed with a key that is not the one being claimed.
	sig := SignAttestation(sn, nonce, otherPriv)

	if err := svc.Verify(context.Background(), sn, nonce, pub, sig); !errors.Is(err, ErrAttestSignature) {
		t.Errorf("got %v, want ErrAttestSignature", err)
	}
}

// TestAttestBindsTheAccount: a signature collected for one account must not be
// replayable onto another that happens to enrol the same device key.
func TestAttestBindsTheAccount(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	alice := state.NewIdentScreenName("alice")
	mallory := state.NewIdentScreenName("mallory")
	svc := NewDeviceAuthService(fakeManifests{stored: manifestWith(t, pub)})

	nonce := mustNonce(t)
	sigForAlice := SignAttestation(alice, nonce, priv)

	if err := svc.Verify(context.Background(), mallory, nonce, pub, sigForAlice); !errors.Is(err, ErrAttestSignature) {
		t.Errorf("a signature for alice was accepted for mallory: %v", err)
	}
}

// TestAttestBindsTheNonce: a signature from an earlier session must not be
// replayable into a later one.
func TestAttestBindsTheNonce(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sn := state.NewIdentScreenName("alice")
	svc := NewDeviceAuthService(fakeManifests{stored: manifestWith(t, pub)})

	old := mustNonce(t)
	sig := SignAttestation(sn, old, priv)

	if err := svc.Verify(context.Background(), sn, mustNonce(t), pub, sig); !errors.Is(err, ErrAttestSignature) {
		t.Errorf("a signature over a previous nonce was accepted: %v", err)
	}
}

// TestAttestRefusesWhenTheManifestIsUnreadable is the fail-closed case.
//
// A stored manifest that will not decode is a bug or a corrupt row, and it must
// NOT read as "this account has no devices" — that turns a storage fault into an
// open door for every device that was ever removed.
func TestAttestRefusesWhenTheManifestIsUnreadable(t *testing.T) {
	sn := state.NewIdentScreenName("alice")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	svc := NewDeviceAuthService(fakeManifests{
		stored: &state.KeyManifest{Manifest: []byte{0xff, 0xff, 0xff}},
	})

	nonce := mustNonce(t)
	err := svc.Verify(context.Background(), sn, nonce, pub, SignAttestation(sn, nonce, priv))
	if err == nil {
		t.Fatal("a corrupt manifest admitted the session")
	}
	if errors.Is(err, ErrNoDevicesEnrolled) {
		t.Error("a corrupt manifest was treated as an account with no devices")
	}
}

// TestAttestRejectsAWrongSizedNonce: the nonce is ours, so a response naming a
// different one is either a bug or somebody steering the signed bytes.
func TestAttestRejectsAWrongSizedNonce(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sn := state.NewIdentScreenName("alice")
	svc := NewDeviceAuthService(fakeManifests{stored: manifestWith(t, pub)})

	short := []byte("too short")
	if err := svc.Verify(context.Background(), sn, short, pub, SignAttestation(sn, short, priv)); err == nil {
		t.Error("a short nonce was accepted")
	}
}

// TestAttestIsNotARoomSignature: a device signing key also signs room messages,
// and the two constructions must not collide.
//
// Before the domain tag they did: a room signature covers `room || 0x00 ||
// message` and an attestation covered `account || 0x00 || nonce`, which are the
// same bytes when a room is named after an account and carries the nonce as its
// text. This test fails if they ever line up again — and it has to exist on BOTH
// sides, because the two constants must agree.
func TestAttestIsNotARoomSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sn := state.NewIdentScreenName("alice")
	svc := NewDeviceAuthService(fakeManifests{stored: manifestWith(t, pub)})
	nonce := mustNonce(t)

	// The room-message construction, as internal/e2ee builds it.
	roomCtx := append(append([]byte("alice"), 0x00), nonce...)
	roomSig := ed25519.Sign(priv, roomCtx)

	if err := svc.Verify(context.Background(), sn, nonce, pub, roomSig); err == nil {
		t.Error("a room-message signature was accepted as a device attestation")
	}
}

// TestAttestContextsMatchAcrossImplementations pins the exact bytes.
//
// The client and server build this independently. If they drift, every session
// fails to attest and the symptom is "nobody can sign in", which is a long way
// from "somebody changed a string constant".
func TestAttestContextsMatchAcrossImplementations(t *testing.T) {
	got := attestContext(state.NewIdentScreenName("alice"), []byte{1, 2, 3})
	want := append(append(append([]byte("BENCO-ATTEST-v1"), 0x00), []byte("alice")...), 0x00, 1, 2, 3)
	if !bytes.Equal(got, want) {
		t.Errorf("attest context = %q, want %q", got, want)
	}
}
