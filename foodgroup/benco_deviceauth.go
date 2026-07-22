package foodgroup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// Device attestation.
//
// A password proves an ACCOUNT; this proves a DEVICE. Every membership check in
// benco_keydir.go carries a comment saying it is advisory, and the reason is
// that the server could not tell one device of an account from another: a device
// removed from the manifest kept signing in with the same password and kept full
// access, and nothing on the server was in a position to notice.
//
// The rule is one sentence. **An account with no devices may sign in with a
// password alone; an account with devices must prove it holds one of them.**
//
// That covers bootstrap and enforcement together. A freshly provisioned account
// has published no manifest, so its first device can get in to publish itself.
// From the moment a manifest exists, a session must answer a challenge with a
// signature from a device the manifest names.
//
// It also supplies its own recovery path, which is the part worth noticing:
// somebody who loses every device cannot get in, and the fix is for an operator
// to clear the account's device list, returning it to the zero-device state and
// therefore to password auth. That is the same operation as provisioning rather
// than a backdoor added for the purpose.

// DeviceAuthMode is how strictly attestation is applied.
type DeviceAuthMode int

const (
	// DeviceAuthOff does not challenge at all.
	DeviceAuthOff DeviceAuthMode = iota
	// DeviceAuthLog challenges and records the outcome but admits either way.
	//
	// This exists for the first deploy, and it is not timidity. Enforcing from
	// the outset means a bug locks out every account that has a device — which
	// is all of them — leaving the management API on its unix socket as the only
	// way back in. Run in log until real sessions are seen passing, then enforce.
	DeviceAuthLog
	// DeviceAuthEnforce closes sessions that cannot prove a device.
	DeviceAuthEnforce
)

// ErrNoDevicesEnrolled means the account has published no manifest, so there is
// nothing to prove and password auth stands alone. Not a failure.
var ErrNoDevicesEnrolled = errors.New("account has no enrolled devices")

// ErrDeviceNotEnrolled means the key offered is not in the account's manifest —
// a device that was removed, or never belonged.
var ErrDeviceNotEnrolled = errors.New("signing key is not in the account's manifest")

// ErrAttestSignature means the signature did not verify against the offered key.
var ErrAttestSignature = errors.New("attestation signature does not verify")

// manifestReader is the slice of the key directory this needs.
type manifestReader interface {
	KeyManifest(ctx context.Context, screenName state.IdentScreenName) (*state.KeyManifest, error)
}

// DeviceAuthService verifies that a session holds a device the account enrolled.
type DeviceAuthService struct {
	manifests manifestReader
}

// NewDeviceAuthService constructs one.
func NewDeviceAuthService(m manifestReader) *DeviceAuthService {
	return &DeviceAuthService{manifests: m}
}

// EnrolledSigningKeys returns the device signing keys named by an account's
// current manifest.
//
// Read back out of the stored manifest rather than from an index built beside
// it. The blob is already kept and the server already decodes and validates one
// at publish time, so a denormalised copy would be a second thing to keep honest
// for no gain — and a second thing to disagree with the signature.
func (s *DeviceAuthService) EnrolledSigningKeys(ctx context.Context, screenName state.IdentScreenName) ([]ed25519.PublicKey, error) {
	stored, err := s.manifests.KeyManifest(ctx, screenName)
	if err != nil {
		return nil, err
	}
	if stored == nil || len(stored.Manifest) == 0 {
		return nil, ErrNoDevicesEnrolled
	}

	var m wire.BENCOManifest
	if err := wire.UnmarshalBE(&m, bytes.NewReader(stored.Manifest)); err != nil {
		// A manifest the server accepted but can no longer decode is a bug or a
		// corrupt row, and it must NOT read as "no devices" — that would turn a
		// storage fault into an open door.
		return nil, fmt.Errorf("stored manifest does not decode: %w", err)
	}
	if len(m.Devices) == 0 {
		return nil, ErrNoDevicesEnrolled
	}

	out := make([]ed25519.PublicKey, 0, len(m.Devices))
	for _, d := range m.Devices {
		if len(d.Sign.Key) == ed25519.PublicKeySize {
			out = append(out, ed25519.PublicKey(d.Sign.Key))
		}
	}
	if len(out) == 0 {
		// Devices exist but none carries a usable signing key. Refuse rather
		// than admit: this is an account that cannot attest, not one exempt
		// from attesting.
		return nil, ErrDeviceNotEnrolled
	}
	return out, nil
}

// Verify checks an attestation response against the account's manifest.
//
// Returns nil when the session is proven, ErrNoDevicesEnrolled when the account
// has nothing to prove against (which the caller admits), and an error otherwise.
func (s *DeviceAuthService) Verify(
	ctx context.Context,
	screenName state.IdentScreenName,
	nonce []byte,
	offered ed25519.PublicKey,
	signature []byte,
) error {
	if len(nonce) != wire.BENCOAttestNonceLen {
		return fmt.Errorf("nonce is %d bytes, want %d", len(nonce), wire.BENCOAttestNonceLen)
	}
	enrolled, err := s.EnrolledSigningKeys(ctx, screenName)
	if err != nil {
		return err
	}

	// Membership FIRST, then the signature. The offered key is attacker-chosen,
	// so verifying against it before checking it belongs would prove only that
	// somebody can sign with a key they just made up.
	var known bool
	for _, k := range enrolled {
		if bytes.Equal(k, offered) {
			known = true
			break
		}
	}
	if !known {
		return ErrDeviceNotEnrolled
	}
	if len(signature) != ed25519.SignatureSize {
		return ErrAttestSignature
	}
	if !ed25519.Verify(offered, attestContext(screenName, nonce), signature) {
		return ErrAttestSignature
	}
	return nil
}

// attestContext is what gets signed: the account and the nonce, separated by a
// byte that cannot occur in a screen name.
//
// The account is included so a signature collected from one session cannot be
// replayed onto another account that happens to share a device key — and, more
// usefully, so a signature can never be mistaken for a signature over anything
// else this device signs. Room messages use their own context for the same
// reason.
func attestContext(screenName state.IdentScreenName, nonce []byte) []byte {
	name := screenName.String()
	out := make([]byte, 0, len(attestDomain)+1+len(name)+1+len(nonce))
	out = append(out, attestDomain...)
	out = append(out, 0x00)
	out = append(out, name...)
	out = append(out, 0x00)
	out = append(out, nonce...)
	return out
}

// attestDomain separates an attestation from everything else a device signing
// key signs — room messages above all.
//
// Without it the constructions collide: a room signature covers
// `room || 0x00 || message`, and an attestation without a domain tag covers
// `account || 0x00 || nonce`. Those are the same bytes when a room is named
// after an account and carries the nonce as its text, so a room message could be
// replayed as proof of device possession. It MUST match the client's constant.
const attestDomain = "BENCO-ATTEST-v1"

// SignAttestation produces the response a client sends. Here so the server's own
// tests exercise the same construction a client must.
func SignAttestation(screenName state.IdentScreenName, nonce []byte, priv ed25519.PrivateKey) []byte {
	return ed25519.Sign(priv, attestContext(screenName, nonce))
}

// ParseDeviceAuthMode turns the config string into a mode. Anything unrecognised
// is treated as log, which is the safe reading: a typo must not silently disable
// attestation, and must not silently lock everybody out either.
func ParseDeviceAuthMode(s string) DeviceAuthMode {
	switch s {
	case "off":
		return DeviceAuthOff
	case "enforce":
		return DeviceAuthEnforce
	default:
		return DeviceAuthLog
	}
}

// Challenge builds the SNAC asking a session to prove its device, and returns
// the nonce to remember.
//
// Returns ok=false when there is nothing to ask: the mode is off, or the account
// has enrolled no devices and password auth stands alone.
func (s *DeviceAuthService) Challenge(
	ctx context.Context,
	mode DeviceAuthMode,
	screenName state.IdentScreenName,
) (msg wire.SNACMessage, nonce []byte, ok bool) {

	if mode == DeviceAuthOff {
		return msg, nil, false
	}
	if _, err := s.EnrolledSigningKeys(ctx, screenName); err != nil {
		if errors.Is(err, ErrNoDevicesEnrolled) {
			return msg, nil, false
		}
		// Any other failure — an unreadable manifest, a storage fault — still
		// gets a challenge. Refusing to ask would admit the session, which is
		// the wrong direction for a fault we do not understand.
	}

	nonce = make([]byte, wire.BENCOAttestNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return msg, nil, false
	}
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BENCOKeyDir,
			SubGroup:  wire.BENCOKeyDirAttestChallenge,
		},
		Body: wire.SNAC_0xBE00_0x000A_BENCOKeyDirAttestChallenge{
			Version: wire.BENCOKeyDirVersion,
			Nonce:   nonce,
		},
	}, nonce, true
}

// AttestResponse handles a session's answer to a challenge.
func (s *DeviceAuthService) AttestResponse(
	ctx context.Context,
	instance *state.SessionInstance,
	inFrame wire.SNACFrame,
	inBody wire.SNAC_0xBE00_0x000B_BENCOKeyDirAttestResponse,
) (wire.SNACMessage, error) {

	accepted := uint8(0)
	nonce := instance.AttestNonce()

	switch {
	case inBody.Version != wire.BENCOKeyDirVersion:
		// Wrong payload version: not an answer we can evaluate.
	case len(nonce) == 0:
		// Answering a challenge that was never issued.
	default:
		err := s.Verify(ctx, instance.IdentScreenName(), nonce,
			ed25519.PublicKey(inBody.SignKey.Key), inBody.Signature)
		switch {
		case err == nil, errors.Is(err, ErrNoDevicesEnrolled):
			instance.SetAttested()
			accepted = 1
		default:
			// Left unattested. What happens next is the caller's decision, and
			// depends on the mode.
		}
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BENCOKeyDir,
			SubGroup:  wire.BENCOKeyDirAttestReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0xBE00_0x000C_BENCOKeyDirAttestReply{
			Version:  wire.BENCOKeyDirVersion,
			Accepted: accepted,
		},
	}, nil
}
