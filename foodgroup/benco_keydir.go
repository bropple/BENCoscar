package foodgroup

import (
	"context"
	"errors"
	"log/slog"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// BENCO addition: the device key directory service (foodgroup 0xBE00).
// See wire/benco_keydir.go for the protocol and why it exists.

// DeviceKeyManager is storage for published device keys.
type DeviceKeyManager interface {
	// DeviceKeys returns an account's active devices. An account that has
	// published nothing returns an empty slice, not an error.
	DeviceKeys(ctx context.Context, screenName state.IdentScreenName) ([]state.DeviceKey, error)
	// PublishDeviceKeys replaces an account's device set, returning any keys
	// refused because they are revoked.
	PublishDeviceKeys(ctx context.Context, screenName state.IdentScreenName, devices []state.DeviceKey) ([]state.DeviceKey, error)
	// RevokeDeviceKey tombstones a device, reporting whether anything changed.
	RevokeDeviceKey(ctx context.Context, screenName state.IdentScreenName, boxKey []byte) (bool, error)
}

// NewBENCOKeyDirService returns a device key directory service.
func NewBENCOKeyDirService(logger *slog.Logger, deviceKeyManager DeviceKeyManager) BENCOKeyDirService {
	return BENCOKeyDirService{
		logger:           logger,
		deviceKeyManager: deviceKeyManager,
	}
}

// BENCOKeyDirService serves the device key directory.
//
// It handles only PUBLIC keys. The server cannot read any message this directory
// helps encrypt, and nothing here would help it — which is the property that
// makes a server-side key directory compatible with end-to-end encryption in the
// first place. What the server does provide is the one thing clients cannot do
// for themselves: an authority that says a revoked device stays revoked.
type BENCOKeyDirService struct {
	logger           *slog.Logger
	deviceKeyManager DeviceKeyManager
}

// PublishKeys stores the sending account's device set.
//
// The screen name comes from the session, never from the request: an account may
// only publish its own keys, and there is deliberately no field to name someone
// else. Letting a client publish for an arbitrary screen name would let anyone
// insert a device into anyone's account, which is a complete break of the
// encryption this directory serves.
func (s BENCOKeyDirService) PublishKeys(
	ctx context.Context,
	sess *state.Session,
	inFrame wire.SNACFrame,
	inBody wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest,
) (wire.SNACMessage, error) {

	devices := make([]state.DeviceKey, 0, len(inBody.Devices))
	for _, d := range inBody.Devices {
		if err := validateDevice(d); err != nil {
			s.logger.DebugContext(ctx, "rejecting malformed device key",
				"screen_name", sess.IdentScreenName(), "err", err.Error())
			return errSNAC(inFrame, wire.ErrorCodeInvalidSnac), nil
		}
		devices = append(devices, state.DeviceKey{BoxKey: d.BoxKey, SignKey: d.SignKey})
	}

	refused, err := s.deviceKeyManager.PublishDeviceKeys(ctx, sess.IdentScreenName(), devices)
	if err != nil {
		if errors.Is(err, state.ErrTooManyDevices) {
			return errSNAC(inFrame, wire.ErrorCodeInvalidSnac), nil
		}
		return wire.SNACMessage{}, err
	}

	out := wire.SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply{
		Accepted: uint16(len(devices) - len(refused)),
	}
	for _, d := range refused {
		out.Refused = append(out.Refused, wire.BENCODevice{BoxKey: d.BoxKey, SignKey: d.SignKey})
	}

	if len(refused) > 0 {
		// Worth a log line: this is a machine the user removed announcing
		// itself again, which is exactly the event the tombstone exists for.
		s.logger.InfoContext(ctx, "refused revoked device keys on publish",
			"screen_name", sess.IdentScreenName(), "count", len(refused))
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BENCOKeyDir,
			SubGroup:  wire.BENCOKeyDirPublishReply,
			RequestID: inFrame.RequestID,
		},
		Body: out,
	}, nil
}

// QueryKeys returns an account's active devices.
//
// Any signed-in user may query any account. These are public keys whose whole
// purpose is to be handed out — withholding them would break encrypting to a
// user without protecting anything, since a peer learns the same keys the moment
// they exchange a message.
func (s BENCOKeyDirService) QueryKeys(
	ctx context.Context,
	inFrame wire.SNACFrame,
	inBody wire.SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest,
) (wire.SNACMessage, error) {

	screenName := state.NewIdentScreenName(inBody.ScreenName)

	devices, err := s.deviceKeyManager.DeviceKeys(ctx, screenName)
	if err != nil {
		return wire.SNACMessage{}, err
	}

	out := wire.SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply{
		ScreenName: inBody.ScreenName,
	}
	for _, d := range devices {
		out.Devices = append(out.Devices, wire.BENCODevice{BoxKey: d.BoxKey, SignKey: d.SignKey})
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

// RevokeKey tombstones one of the sending account's own devices.
//
// As with publishing, the screen name comes from the session. Allowing a client
// to revoke another account's device would be a denial-of-service against that
// user's ability to read their own messages.
func (s BENCOKeyDirService) RevokeKey(
	ctx context.Context,
	sess *state.Session,
	inFrame wire.SNACFrame,
	inBody wire.SNAC_0xBE00_0x0006_BENCOKeyDirRevokeRequest,
) (wire.SNACMessage, error) {

	if len(inBody.BoxKey) != wire.BENCOKeyDirBoxKeyLen {
		return errSNAC(inFrame, wire.ErrorCodeInvalidSnac), nil
	}

	revoked, err := s.deviceKeyManager.RevokeDeviceKey(ctx, sess.IdentScreenName(), inBody.BoxKey)
	if err != nil {
		return wire.SNACMessage{}, err
	}

	var flag uint8
	if revoked {
		flag = 1
		s.logger.InfoContext(ctx, "revoked a device key",
			"screen_name", sess.IdentScreenName())
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BENCOKeyDir,
			SubGroup:  wire.BENCOKeyDirRevokeReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0xBE00_0x0007_BENCOKeyDirRevokeReply{Revoked: flag},
	}, nil
}

// validateDevice rejects malformed key material before it reaches storage.
//
// Length is checked rather than trusted because these values are handed to
// clients as encryption keys: a wrong-length "key" stored here would produce
// undecryptable messages for everyone who fetched it, and the failure would look
// like a client bug a long way from its cause.
func validateDevice(d wire.BENCODevice) error {
	if len(d.BoxKey) != wire.BENCOKeyDirBoxKeyLen {
		return errors.New("box key must be 32 bytes")
	}
	// A signing key is optional — a client that has not generated one publishes
	// an empty field — but a present one must be the right size.
	if len(d.SignKey) != 0 && len(d.SignKey) != wire.BENCOKeyDirSignKeyLen {
		return errors.New("signing key must be 32 bytes when present")
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
