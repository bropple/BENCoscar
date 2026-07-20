package state

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BENCO addition — the device key directory store. See device_keys.go.
//
// These run against a real SQLite database, like the rest of this package's
// store tests, because the behaviour under test is mostly SQL: what a publish
// deletes, what it leaves alone, and what a revocation survives.

// newDeviceKeyStore returns a store with a user row to hang devices off, since
// deviceKeys has a foreign key onto users.
func newDeviceKeyStore(t *testing.T, screenName string) (*SQLiteUserStore, IdentScreenName) {
	t.Helper()

	f, err := NewSQLiteUserStore(testFile)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, os.Remove(testFile))
	})

	sn := NewIdentScreenName(screenName)
	u := User{
		IdentScreenName:   sn,
		DisplayScreenName: DisplayScreenName(screenName),
	}
	require.NoError(t, u.HashPassword("the_password"))
	require.NoError(t, f.InsertUser(context.Background(), u))

	return f, sn
}

func key(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestDeviceKeys_PublishAndQuery(t *testing.T) {
	ctx := context.Background()
	f, sn := newDeviceKeyStore(t, "someuser")

	// Nothing published yet is an empty answer, not an error: "this user runs a
	// client that does not do encryption" is normal.
	got, err := f.DeviceKeys(ctx, sn)
	require.NoError(t, err)
	assert.Empty(t, got)

	refused, err := f.PublishDeviceKeys(ctx, sn, []DeviceKey{
		{BoxKey: key(1), SignKey: key(0x11)},
		{BoxKey: key(2)}, // no signing key — a client that hasn't made one
	})
	require.NoError(t, err)
	assert.Empty(t, refused)

	got, err = f.DeviceKeys(ctx, sn)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, key(1), got[0].BoxKey)
	assert.Equal(t, key(0x11), got[0].SignKey)
	assert.Equal(t, key(2), got[1].BoxKey)
	assert.Empty(t, got[1].SignKey)
	assert.False(t, got[0].Revoked())
}

func TestDeviceKeys_PublishReplacesTheSet(t *testing.T) {
	ctx := context.Background()
	f, sn := newDeviceKeyStore(t, "someuser")

	_, err := f.PublishDeviceKeys(ctx, sn, []DeviceKey{{BoxKey: key(1)}, {BoxKey: key(2)}})
	require.NoError(t, err)

	// A client sends its complete list every time, so a device simply absent
	// from a later publish is gone. That is NOT a revocation — it leaves no
	// tombstone, and the device may publish itself again.
	_, err = f.PublishDeviceKeys(ctx, sn, []DeviceKey{{BoxKey: key(2)}})
	require.NoError(t, err)

	got, err := f.DeviceKeys(ctx, sn)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, key(2), got[0].BoxKey)

	_, err = f.PublishDeviceKeys(ctx, sn, []DeviceKey{{BoxKey: key(1)}, {BoxKey: key(2)}})
	require.NoError(t, err)
	got, err = f.DeviceKeys(ctx, sn)
	require.NoError(t, err)
	assert.Len(t, got, 2, "a merely-absent device must be republishable")
}

// The point of the whole design: a revoked device must not come back on its own.
func TestDeviceKeys_RevocationSurvivesRepublish(t *testing.T) {
	ctx := context.Background()
	f, sn := newDeviceKeyStore(t, "someuser")

	_, err := f.PublishDeviceKeys(ctx, sn, []DeviceKey{{BoxKey: key(1)}, {BoxKey: key(2)}})
	require.NoError(t, err)

	revoked, err := f.RevokeDeviceKey(ctx, sn, key(1))
	require.NoError(t, err)
	assert.True(t, revoked)

	got, err := f.DeviceKeys(ctx, sn)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, key(2), got[0].BoxKey)

	// The removed machine keeps its keypair and republishes on next sign-on.
	// Without the tombstone this silently restores it and removal means nothing.
	refused, err := f.PublishDeviceKeys(ctx, sn, []DeviceKey{{BoxKey: key(1)}, {BoxKey: key(2)}})
	require.NoError(t, err)
	require.Len(t, refused, 1, "a revoked device republishing must be refused")
	assert.Equal(t, key(1), refused[0].BoxKey)

	got, err = f.DeviceKeys(ctx, sn)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, key(2), got[0].BoxKey, "the revoked device must not be back")
}

func TestDeviceKeys_RevokeIsIdempotentAndScoped(t *testing.T) {
	ctx := context.Background()
	f, sn := newDeviceKeyStore(t, "someuser")

	_, err := f.PublishDeviceKeys(ctx, sn, []DeviceKey{{BoxKey: key(1)}})
	require.NoError(t, err)

	revoked, err := f.RevokeDeviceKey(ctx, sn, key(1))
	require.NoError(t, err)
	assert.True(t, revoked)

	// Revoking again reports no change rather than erroring — the caller wanted
	// it gone and it is gone.
	revoked, err = f.RevokeDeviceKey(ctx, sn, key(1))
	require.NoError(t, err)
	assert.False(t, revoked)

	// Revoking something never published is likewise a no-op.
	revoked, err = f.RevokeDeviceKey(ctx, sn, key(9))
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestDeviceKeys_AccountsAreIsolated(t *testing.T) {
	ctx := context.Background()
	f, alice := newDeviceKeyStore(t, "alice")

	bob := NewIdentScreenName("bob")
	u := User{IdentScreenName: bob, DisplayScreenName: "bob"}
	require.NoError(t, u.HashPassword("the_password"))
	require.NoError(t, f.InsertUser(ctx, u))

	_, err := f.PublishDeviceKeys(ctx, alice, []DeviceKey{{BoxKey: key(1)}})
	require.NoError(t, err)
	_, err = f.PublishDeviceKeys(ctx, bob, []DeviceKey{{BoxKey: key(1)}})
	require.NoError(t, err)

	// Same key bytes under two accounts are two independent rows, so revoking
	// one must not disturb the other. The primary key is (account, key).
	revoked, err := f.RevokeDeviceKey(ctx, alice, key(1))
	require.NoError(t, err)
	assert.True(t, revoked)

	got, err := f.DeviceKeys(ctx, bob)
	require.NoError(t, err)
	assert.Len(t, got, 1, "revoking alice's device must not touch bob's")
}

func TestDeviceKeys_RejectsTooManyDevices(t *testing.T) {
	ctx := context.Background()
	f, sn := newDeviceKeyStore(t, "someuser")

	devices := make([]DeviceKey, MaxDevicesPerAccount+1)
	for i := range devices {
		devices[i] = DeviceKey{BoxKey: key(byte(i))}
	}

	_, err := f.PublishDeviceKeys(ctx, sn, devices)
	assert.ErrorIs(t, err, ErrTooManyDevices)

	got, err := f.DeviceKeys(ctx, sn)
	require.NoError(t, err)
	assert.Empty(t, got, "a rejected publish must not partially apply")
}

// The dead end this fixes: without Restore, a tombstone is permanent. The
// removed machine keeps its keypair and republishes on every sign-on, so it is
// refused forever with no way back — "remove device" would really mean "destroy
// device", and reinstalling a laptop would require deleting the account.
func TestDeviceKeys_RestoreLetsARemovedDevicePublishAgain(t *testing.T) {
	ctx := context.Background()
	f, sn := newDeviceKeyStore(t, "someuser")

	_, err := f.PublishDeviceKeys(ctx, sn, []DeviceKey{{BoxKey: key(1)}, {BoxKey: key(2)}})
	require.NoError(t, err)

	revoked, err := f.RevokeDeviceKey(ctx, sn, key(1))
	require.NoError(t, err)
	require.True(t, revoked)

	// Still refused while the tombstone stands.
	refused, err := f.PublishDeviceKeys(ctx, sn, []DeviceKey{{BoxKey: key(1)}, {BoxKey: key(2)}})
	require.NoError(t, err)
	require.Len(t, refused, 1)

	restored, err := f.RestoreDeviceKey(ctx, sn, key(1))
	require.NoError(t, err)
	assert.True(t, restored)

	// And now it publishes normally again.
	refused, err = f.PublishDeviceKeys(ctx, sn, []DeviceKey{{BoxKey: key(1)}, {BoxKey: key(2)}})
	require.NoError(t, err)
	assert.Empty(t, refused, "a restored device must publish like any other")

	got, err := f.DeviceKeys(ctx, sn)
	require.NoError(t, err)
	assert.Len(t, got, 2)
}

func TestDeviceKeys_RestoreIsANoOpWhenNothingWasRevoked(t *testing.T) {
	ctx := context.Background()
	f, sn := newDeviceKeyStore(t, "someuser")

	_, err := f.PublishDeviceKeys(ctx, sn, []DeviceKey{{BoxKey: key(1)}})
	require.NoError(t, err)

	// An active device: nothing to lift, and it must not be disturbed.
	restored, err := f.RestoreDeviceKey(ctx, sn, key(1))
	require.NoError(t, err)
	assert.False(t, restored)

	got, err := f.DeviceKeys(ctx, sn)
	require.NoError(t, err)
	assert.Len(t, got, 1, "restoring an active device must not remove it")

	// A key this account never published.
	restored, err = f.RestoreDeviceKey(ctx, sn, key(9))
	require.NoError(t, err)
	assert.False(t, restored)
}

func TestDeviceKeys_RestoreIsScopedToTheAccount(t *testing.T) {
	ctx := context.Background()
	f, alice := newDeviceKeyStore(t, "alice")

	bob := NewIdentScreenName("bob")
	u := User{IdentScreenName: bob, DisplayScreenName: "bob"}
	require.NoError(t, u.HashPassword("the_password"))
	require.NoError(t, f.InsertUser(ctx, u))

	for _, sn := range []IdentScreenName{alice, bob} {
		_, err := f.PublishDeviceKeys(ctx, sn, []DeviceKey{{BoxKey: key(1)}})
		require.NoError(t, err)
		_, err = f.RevokeDeviceKey(ctx, sn, key(1))
		require.NoError(t, err)
	}

	restored, err := f.RestoreDeviceKey(ctx, alice, key(1))
	require.NoError(t, err)
	require.True(t, restored)

	// Bob's identical key must still be revoked: restoring one account's device
	// must never lift another's, or an attacker could undo the removal a user
	// performed to lock them out.
	refused, err := f.PublishDeviceKeys(ctx, bob, []DeviceKey{{BoxKey: key(1)}})
	require.NoError(t, err)
	assert.Len(t, refused, 1, "bob's revocation must survive alice's restore")
}
