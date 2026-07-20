package state

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// BENCO addition: storage for the device key directory (foodgroup 0xBE00).
// See state/migrations/0035_device_keys.up.sql for why this table exists.

// ErrTooManyDevices is returned when an account tries to publish more devices
// than MaxDevicesPerAccount.
var ErrTooManyDevices = errors.New("account has too many devices")

// MaxDevicesPerAccount caps the published device set.
//
// It matches BENCchat's own client-side cap. The number is far above any real
// use; it exists so a malformed or hostile client cannot make the server store
// or return an unbounded list, and so a peer's per-message cost stays bounded —
// a sender wraps the message key once per recipient device.
const MaxDevicesPerAccount = 32

// DeviceKey is one machine belonging to an account.
//
// Only public keys are held. BoxKey is the X25519 key messages are sealed to and
// is the device's identity; SignKey is the Ed25519 key attributing chat-room
// messages to a sender, and may be nil for a client that has not generated one.
type DeviceKey struct {
	BoxKey      []byte
	SignKey     []byte
	PublishedAt time.Time
	// RevokedAt is non-zero for a tombstoned device. Revoked devices are never
	// returned by DeviceKeys; the tombstone exists so PublishDeviceKeys can
	// refuse a removed machine that republishes itself.
	RevokedAt time.Time
}

// Revoked reports whether this device has been removed.
func (d DeviceKey) Revoked() bool { return !d.RevokedAt.IsZero() }

// DeviceKeys returns an account's active (non-revoked) devices.
//
// It reads storage rather than a live session, which is the entire point of the
// directory: an offline user's keys are just as fetchable as an online one's,
// and an account can look up its own other devices.
//
// An account with nothing published returns an empty slice and no error. "This
// user runs a client that does not do encryption" is a normal answer.
func (f SQLiteUserStore) DeviceKeys(ctx context.Context, screenName IdentScreenName) ([]DeviceKey, error) {
	q := `
		SELECT boxKey, signKey, publishedAt
		FROM deviceKeys
		WHERE identScreenName = ? AND revokedAt IS NULL
		ORDER BY publishedAt, boxKey
	`
	rows, err := f.db.QueryContext(ctx, q, screenName.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DeviceKey
	for rows.Next() {
		var (
			d           DeviceKey
			publishedAt int64
		)
		if err := rows.Scan(&d.BoxKey, &d.SignKey, &publishedAt); err != nil {
			return nil, err
		}
		d.PublishedAt = time.Unix(publishedAt, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

// PublishDeviceKeys replaces an account's published device set.
//
// It returns the keys that were REFUSED because they are revoked. That is not an
// error: a revoked key reappearing means a machine the user removed has come
// back, which is a question for a human, so it is reported to the client to
// surface rather than being silently accepted or hard-rejected.
//
// Devices absent from the request are removed outright rather than tombstoned.
// A client sends its complete list every time, so absence means "this device is
// no longer in my set", which is different from "I revoked this device" — only
// the latter needs to survive as a tombstone.
func (f SQLiteUserStore) PublishDeviceKeys(ctx context.Context, screenName IdentScreenName, devices []DeviceKey) (refused []DeviceKey, err error) {
	if len(devices) > MaxDevicesPerAccount {
		return nil, fmt.Errorf("%w: %d requested, limit is %d", ErrTooManyDevices, len(devices), MaxDevicesPerAccount)
	}

	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, tx.Rollback())
		}
	}()

	// Which of this account's keys are tombstoned. Checked up front so a
	// revoked device is refused rather than resurrected.
	revoked := map[string]struct{}{}
	rows, err := tx.QueryContext(ctx,
		`SELECT boxKey FROM deviceKeys WHERE identScreenName = ? AND revokedAt IS NOT NULL`,
		screenName.String())
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var key []byte
		if err = rows.Scan(&key); err != nil {
			_ = rows.Close()
			return nil, err
		}
		revoked[string(key)] = struct{}{}
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}

	keep := make([]DeviceKey, 0, len(devices))
	for _, d := range devices {
		if _, bad := revoked[string(d.BoxKey)]; bad {
			refused = append(refused, d)
			continue
		}
		keep = append(keep, d)
	}

	// Drop the account's current ACTIVE rows and reinsert. Tombstones are left
	// alone — deleting them would undo the revocation this whole design exists
	// to make durable.
	if _, err = tx.ExecContext(ctx,
		`DELETE FROM deviceKeys WHERE identScreenName = ? AND revokedAt IS NULL`,
		screenName.String()); err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	for _, d := range keep {
		if _, err = tx.ExecContext(ctx,
			`INSERT INTO deviceKeys (identScreenName, boxKey, signKey, publishedAt) VALUES (?, ?, ?, ?)`,
			screenName.String(), d.BoxKey, d.SignKey, now); err != nil {
			return nil, err
		}
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return refused, nil
}

// RevokeDeviceKey tombstones one of an account's devices, reporting whether
// anything was revoked.
//
// The row is kept with revokedAt set rather than deleted. The removed machine
// still holds its keypair and republishes on next sign-on, so a deleted row
// would simply reappear and removal would mean nothing.
//
// Revoking a key the account never published is a no-op, not an error: the
// caller wanted it gone and it is gone.
func (f SQLiteUserStore) RevokeDeviceKey(ctx context.Context, screenName IdentScreenName, boxKey []byte) (bool, error) {
	res, err := f.db.ExecContext(ctx,
		`UPDATE deviceKeys SET revokedAt = ? WHERE identScreenName = ? AND boxKey = ? AND revokedAt IS NULL`,
		time.Now().Unix(), screenName.String(), boxKey)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n > 0 {
		return true, nil
	}

	// Nothing updated: either the key was never published, or it is already
	// tombstoned. Both mean "it is not active", which is what the caller asked
	// for, so report no change rather than an error.
	return false, nil
}

// RestoreDeviceKey lifts a revocation, letting a removed device publish again.
// It reports whether a tombstone was actually cleared.
//
// Revocation without this is not "removed", it is "destroyed": the machine keeps
// its keypair and republishes on every sign-on, so it would be refused forever
// with no way back. Reinstalling a laptop has to be recoverable.
//
// The row is deleted rather than un-marked. It carries a publishedAt from before
// the revocation, and the device is about to republish anyway — leaving a stale
// row would misreport when the key was last seen, which is what the eviction
// order depends on.
func (f SQLiteUserStore) RestoreDeviceKey(ctx context.Context, screenName IdentScreenName, boxKey []byte) (bool, error) {
	res, err := f.db.ExecContext(ctx,
		`DELETE FROM deviceKeys WHERE identScreenName = ? AND boxKey = ? AND revokedAt IS NOT NULL`,
		screenName.String(), boxKey)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
