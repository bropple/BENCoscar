package foodgroup

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// BENCO addition — device key directory service. See benco_keydir.go.

// fakeDeviceKeyManager is a hand-written stub rather than a mockery mock.
//
// mockery is not installed in this environment and the generated mocks are
// committed, so generating one here would produce a file the next `mockery` run
// might not reproduce identically. The behaviour needed is a map, and recording
// the screen name each call was made with is precisely what the important test
// in this file asserts.
type fakeDeviceKeyManager struct {
	devices map[string][]state.DeviceKey
	refuse  []state.DeviceKey
	err     error

	// Recorded arguments, so tests can prove the service passes the SESSION's
	// screen name rather than anything a client supplied.
	publishedFor state.IdentScreenName
	queriedFor   state.IdentScreenName
	revokedFor   state.IdentScreenName
	revokedKey   []byte
	restoredFor  state.IdentScreenName
	restoredKey  []byte
}

func (f *fakeDeviceKeyManager) DeviceKeys(_ context.Context, sn state.IdentScreenName) ([]state.DeviceKey, error) {
	f.queriedFor = sn
	if f.err != nil {
		return nil, f.err
	}
	return f.devices[sn.String()], nil
}

func (f *fakeDeviceKeyManager) PublishDeviceKeys(_ context.Context, sn state.IdentScreenName, d []state.DeviceKey) ([]state.DeviceKey, error) {
	f.publishedFor = sn
	if f.err != nil {
		return nil, f.err
	}
	if f.devices == nil {
		f.devices = map[string][]state.DeviceKey{}
	}
	f.devices[sn.String()] = d
	return f.refuse, nil
}

func (f *fakeDeviceKeyManager) RevokeDeviceKey(_ context.Context, sn state.IdentScreenName, boxKey []byte) (bool, error) {
	f.revokedFor = sn
	f.revokedKey = boxKey
	if f.err != nil {
		return false, f.err
	}
	return true, nil
}

func (f *fakeDeviceKeyManager) RestoreDeviceKey(_ context.Context, sn state.IdentScreenName, boxKey []byte) (bool, error) {
	f.restoredFor = sn
	f.restoredKey = boxKey
	if f.err != nil {
		return false, f.err
	}
	return true, nil
}

func devKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func testSession(screenName string) *state.Session {
	sess := state.NewSession()
	sess.SetIdentScreenName(state.NewIdentScreenName(screenName))
	sess.SetDisplayScreenName(state.DisplayScreenName(screenName))
	return sess
}

// The security property of the whole foodgroup: an account can only publish its
// own keys. If a client could publish for an arbitrary screen name it could
// insert its own device into anyone's account and read their messages, which
// would defeat the encryption this directory exists to serve.
func TestBENCOKeyDir_PublishUsesSessionScreenName(t *testing.T) {
	mgr := &fakeDeviceKeyManager{}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	out, err := svc.PublishKeys(context.Background(), testSession("alice"), wire.SNACFrame{RequestID: 7},
		wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
			Version: wire.BENCOKeyDirVersion,
			Devices: []wire.BENCODevice{{BoxKey: devKey(1), SignKey: devKey(2)}},
		})
	require.NoError(t, err)

	assert.Equal(t, state.NewIdentScreenName("alice"), mgr.publishedFor)
	assert.Equal(t, wire.BENCOKeyDirPublishReply, out.Frame.SubGroup)
	assert.Equal(t, uint32(7), out.Frame.RequestID)

	body := out.Body.(wire.SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply)
	assert.Equal(t, uint16(1), body.Accepted)
	assert.Empty(t, body.Refused)
}

// A revoked device republishing is reported back rather than silently accepted
// or hard-rejected, so the client can put it through the approval flow.
func TestBENCOKeyDir_PublishReportsRefusals(t *testing.T) {
	mgr := &fakeDeviceKeyManager{refuse: []state.DeviceKey{{BoxKey: devKey(9)}}}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	out, err := svc.PublishKeys(context.Background(), testSession("alice"), wire.SNACFrame{},
		wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
			Devices: []wire.BENCODevice{{BoxKey: devKey(1)}, {BoxKey: devKey(9)}},
		})
	require.NoError(t, err)

	body := out.Body.(wire.SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply)
	assert.Equal(t, uint16(1), body.Accepted)
	require.Len(t, body.Refused, 1)
	assert.Equal(t, devKey(9), body.Refused[0].BoxKey)
}

func TestBENCOKeyDir_PublishRejectsMalformedKeys(t *testing.T) {
	cases := []struct {
		name   string
		device wire.BENCODevice
	}{
		{name: "short box key", device: wire.BENCODevice{BoxKey: []byte{1, 2, 3}}},
		{name: "empty box key", device: wire.BENCODevice{}},
		{name: "wrong-length signing key", device: wire.BENCODevice{BoxKey: devKey(1), SignKey: []byte{1}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mgr := &fakeDeviceKeyManager{}
			svc := NewBENCOKeyDirService(slog.Default(), mgr)

			out, err := svc.PublishKeys(context.Background(), testSession("alice"), wire.SNACFrame{},
				wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
					Devices: []wire.BENCODevice{tc.device},
				})
			require.NoError(t, err)

			// Wrong-length key material stored here would be handed to peers as
			// an encryption key and produce undecryptable messages far from the
			// cause, so it must never reach storage.
			assert.Equal(t, wire.BENCOKeyDirErr, out.Frame.SubGroup)
			assert.Empty(t, mgr.publishedFor.String(), "malformed keys must not reach storage")
		})
	}
}

// A device that has not generated a signing key is legitimate, not malformed.
func TestBENCOKeyDir_PublishAcceptsMissingSigningKey(t *testing.T) {
	mgr := &fakeDeviceKeyManager{}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	out, err := svc.PublishKeys(context.Background(), testSession("alice"), wire.SNACFrame{},
		wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
			Devices: []wire.BENCODevice{{BoxKey: devKey(1)}},
		})
	require.NoError(t, err)
	assert.Equal(t, wire.BENCOKeyDirPublishReply, out.Frame.SubGroup)
}

// Querying reads storage, not a session — which is the whole reason the
// directory exists. An offline user and the caller's own account both work.
func TestBENCOKeyDir_QueryReturnsDevices(t *testing.T) {
	mgr := &fakeDeviceKeyManager{devices: map[string][]state.DeviceKey{
		"bob": {{BoxKey: devKey(1), SignKey: devKey(2)}, {BoxKey: devKey(3)}},
	}}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	out, err := svc.QueryKeys(context.Background(), wire.SNACFrame{RequestID: 3},
		wire.SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest{ScreenName: "bob"})
	require.NoError(t, err)

	assert.Equal(t, state.NewIdentScreenName("bob"), mgr.queriedFor)
	body := out.Body.(wire.SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply)
	assert.Equal(t, "bob", body.ScreenName)
	require.Len(t, body.Devices, 2)
	assert.Equal(t, devKey(1), body.Devices[0].BoxKey)
}

// An account that published nothing is a normal answer, not a failure: it just
// means they run a client that does not do encryption.
func TestBENCOKeyDir_QueryUnknownUserIsEmptyNotError(t *testing.T) {
	svc := NewBENCOKeyDirService(slog.Default(), &fakeDeviceKeyManager{})

	out, err := svc.QueryKeys(context.Background(), wire.SNACFrame{},
		wire.SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest{ScreenName: "nobody"})
	require.NoError(t, err)

	body := out.Body.(wire.SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply)
	assert.Equal(t, wire.BENCOKeyDirQueryReply, out.Frame.SubGroup)
	assert.Empty(t, body.Devices)
}

// Revocation is likewise scoped to the caller. Letting a client revoke someone
// else's device would deny that user the ability to read their own messages.
func TestBENCOKeyDir_RevokeUsesSessionScreenName(t *testing.T) {
	mgr := &fakeDeviceKeyManager{}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	out, err := svc.RevokeKey(context.Background(), testSession("alice"), wire.SNACFrame{},
		wire.SNAC_0xBE00_0x0006_BENCOKeyDirRevokeRequest{BoxKey: devKey(4)})
	require.NoError(t, err)

	assert.Equal(t, state.NewIdentScreenName("alice"), mgr.revokedFor)
	assert.Equal(t, devKey(4), mgr.revokedKey)

	body := out.Body.(wire.SNAC_0xBE00_0x0007_BENCOKeyDirRevokeReply)
	assert.Equal(t, uint8(1), body.Revoked)
}

func TestBENCOKeyDir_RevokeRejectsMalformedKey(t *testing.T) {
	mgr := &fakeDeviceKeyManager{}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	out, err := svc.RevokeKey(context.Background(), testSession("alice"), wire.SNACFrame{},
		wire.SNAC_0xBE00_0x0006_BENCOKeyDirRevokeRequest{BoxKey: []byte{1, 2}})
	require.NoError(t, err)

	assert.Equal(t, wire.BENCOKeyDirErr, out.Frame.SubGroup)
	assert.Empty(t, mgr.revokedFor.String())
}

// Storage failures surface as errors rather than being reported to the client as
// an empty key set: "this user has no devices" would make a peer silently send
// in plaintext, which is the worst possible reading of a database outage.
func TestBENCOKeyDir_StorageErrorsPropagate(t *testing.T) {
	boom := errors.New("database is on fire")
	svc := NewBENCOKeyDirService(slog.Default(), &fakeDeviceKeyManager{err: boom})

	_, err := svc.QueryKeys(context.Background(), wire.SNACFrame{},
		wire.SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest{ScreenName: "bob"})
	assert.ErrorIs(t, err, boom)

	_, err = svc.PublishKeys(context.Background(), testSession("alice"), wire.SNACFrame{},
		wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
			Devices: []wire.BENCODevice{{BoxKey: devKey(1)}},
		})
	assert.ErrorIs(t, err, boom)
}

// Too many devices is a client error, not a server error: it gets a SNAC error
// reply rather than tearing down the connection.
func TestBENCOKeyDir_TooManyDevicesIsAClientError(t *testing.T) {
	svc := NewBENCOKeyDirService(slog.Default(), &fakeDeviceKeyManager{err: state.ErrTooManyDevices})

	out, err := svc.PublishKeys(context.Background(), testSession("alice"), wire.SNACFrame{},
		wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
			Devices: []wire.BENCODevice{{BoxKey: devKey(1)}},
		})
	require.NoError(t, err)
	assert.Equal(t, wire.BENCOKeyDirErr, out.Frame.SubGroup)
}

// Restore is scoped to the caller's own account for the same reason revoke is:
// lifting someone else's revocation would undo exactly the removal a user
// performed to lock an attacker out.
func TestBENCOKeyDir_RestoreUsesSessionScreenName(t *testing.T) {
	mgr := &fakeDeviceKeyManager{}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	out, err := svc.RestoreKey(context.Background(), testSession("alice"), wire.SNACFrame{RequestID: 11},
		wire.SNAC_0xBE00_0x0008_BENCOKeyDirRestoreRequest{BoxKey: devKey(4)})
	require.NoError(t, err)

	assert.Equal(t, state.NewIdentScreenName("alice"), mgr.restoredFor)
	assert.Equal(t, devKey(4), mgr.restoredKey)
	assert.Equal(t, wire.BENCOKeyDirRestoreReply, out.Frame.SubGroup)
	assert.Equal(t, uint32(11), out.Frame.RequestID)

	body := out.Body.(wire.SNAC_0xBE00_0x0009_BENCOKeyDirRestoreReply)
	assert.Equal(t, uint8(1), body.Restored)
}

func TestBENCOKeyDir_RestoreRejectsMalformedKey(t *testing.T) {
	mgr := &fakeDeviceKeyManager{}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	out, err := svc.RestoreKey(context.Background(), testSession("alice"), wire.SNACFrame{},
		wire.SNAC_0xBE00_0x0008_BENCOKeyDirRestoreRequest{BoxKey: []byte{1, 2}})
	require.NoError(t, err)

	assert.Equal(t, wire.BENCOKeyDirErr, out.Frame.SubGroup)
	assert.Empty(t, mgr.restoredFor.String(), "a malformed key must not reach storage")
}
