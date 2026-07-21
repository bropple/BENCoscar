package state

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"
)

// BENCO addition: storage for key directory v2 (foodgroup 0xBE00).
// See state/migrations/0036_key_directory.up.sql for why these tables exist.

// ErrStaleCounter is returned when a publish would move an account's manifest
// counter backwards or leave it unchanged.
//
// This is the rollback defence, and it is the reason the counter exists. A
// manifest that removes a device is just a manifest at a higher counter, so
// accepting an older one would resurrect a machine the user had removed.
var ErrStaleCounter = errors.New("manifest counter is not newer than the stored one")

// ErrCounterOutOfRange is returned for a counter SQLite cannot store faithfully.
//
// The wire field is uint64 and SQLite's INTEGER is signed, so anything above the
// signed maximum would wrap to a negative and then compare BACKWARDS -- turning
// the rollback defence into a rollback assist. Refusing is safe: a legitimate
// counter increments once per device-list change, so it will not reach 2^63 in
// any timeframe that matters.
var ErrCounterOutOfRange = errors.New("manifest counter is out of range")

// MaxDevicesPerAccount caps the devices inside a manifest.
//
// It matches BENCchat's own client-side cap. The number is far above any real
// use; it exists so a malformed or hostile client cannot make the server store
// or return an unbounded list, and so a peer's per-message cost stays bounded --
// a sender wraps the message key once per recipient device.
const MaxDevicesPerAccount = 32

// KeyManifest is an account's signed device manifest as it is stored.
//
// Manifest is the bytes the client signed, and it is the only field that is
// authoritative. Everything else on this struct is a copy the server pulled out
// of those bytes when the manifest was published, kept so the counter and
// identity comparisons on the next publish do not require decoding a blob. If a
// copy ever disagreed with the blob, the blob is right -- but it cannot, because
// nothing rewrites either after the insert.
//
// The bytes are never re-encoded. See PublishManifest.
type KeyManifest struct {
	IdentityAlg uint8
	IdentityKey []byte
	Counter     uint64
	IssuedAt    time.Time
	Manifest    []byte
	SigAlg      uint8
	Signature   []byte
}

// IdentityBackup is an account's encrypted identity private key.
//
// The server holds ciphertext and the parameters needed to derive the key that
// opens it -- but not the recovery phrase those parameters are applied to, which
// exists only in the user's hands. So this is storage the operator cannot read
// without mounting an offline attack against a ~110-bit generated secret.
type IdentityBackup struct {
	KDF       uint8
	Params    []byte
	Salt      []byte
	Blob      []byte
	UpdatedAt time.Time
}

// KeyManifest returns an account's published manifest.
//
// A missing manifest is reported as (nil, nil), not an error. An account that
// has never bootstrapped an identity is a normal thing to query -- it is what
// every first sign-on looks like -- and making it an error would push routine
// handling into an error path on both sides.
//
// It reads storage rather than a live session, which is the point of the
// directory: an offline user's manifest is as fetchable as an online one's, and
// an account can look up its own devices.
func (f SQLiteUserStore) KeyManifest(ctx context.Context, screenName IdentScreenName) (*KeyManifest, error) {
	q := `
		SELECT identityAlg, identityKey, counter, issuedAt, manifest, sigAlg, signature
		FROM keyDirManifests
		WHERE identScreenName = ?
	`
	var (
		m        KeyManifest
		counter  int64
		issuedAt int64
	)
	err := f.db.QueryRowContext(ctx, q, screenName.String()).
		Scan(&m.IdentityAlg, &m.IdentityKey, &counter, &issuedAt, &m.Manifest, &m.SigAlg, &m.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m.Counter = uint64(counter)
	m.IssuedAt = time.Unix(issuedAt, 0)
	return &m, nil
}

// PublishManifest stores an account's signed manifest, replacing any previous
// one. It returns the counter the account holds afterwards.
//
// # The manifest bytes are stored verbatim
//
// m.Manifest goes into the database exactly as it arrived. It is never decoded
// and re-encoded, here or anywhere else. The detached signature covers those
// precise bytes, so a single byte of encoding drift -- a different field order,
// a different length-prefix width, a re-serialised string -- would invalidate
// the signature for every client that fetched it afterwards, and the failure
// would look like a client-side signature bug rather than a server one.
//
// # Counter and identity
//
// The comparison is scoped to the identity, not to the counter alone:
//
//   - SAME identity key as stored: the counter must be strictly greater. This is
//     the rollback defence. Removing a device is nothing more than publishing a
//     manifest without it at a higher counter, so accepting an equal or lower
//     one would let a replayed manifest bring a removed machine back.
//
//   - DIFFERENT identity key: the counter is reset to whatever the new manifest
//     carries, with no monotonicity requirement across the change. A new identity
//     legitimately starts at 1, and refusing that would mean an account that
//     bootstrapped a fresh identity could never publish until it had counted past
//     its own history.
//
// The server does NOT try to decide whether an identity change is legitimate,
// and could not. It is either the account holder who lost everything and
// bootstrapped again, or someone with the password who cleared the identity and
// installed their own -- and those two are cryptographically indistinguishable
// by construction. That is not a gap in the design, it is the property the design
// is for: an operator can destroy or replace an identity but cannot silently
// BECOME someone, because every contact sees the safety number move. Adjudicating
// it is the client's job, and the client's answer is to ask a human.
//
// The whole thing runs in one transaction because the read and the write are a
// compare-and-swap. Two concurrent publishes from an account's two devices would
// otherwise both read the old counter and both write, and the loser's manifest
// would win by arriving second.
func (f SQLiteUserStore) PublishManifest(ctx context.Context, screenName IdentScreenName, m KeyManifest) (counter uint64, err error) {
	if m.Counter > math.MaxInt64 {
		return 0, fmt.Errorf("%w: %d", ErrCounterOutOfRange, m.Counter)
	}

	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, tx.Rollback())
		}
	}()

	var (
		storedAlg     uint8
		storedKey     []byte
		storedCounter int64
	)
	err = tx.QueryRowContext(ctx,
		`SELECT identityAlg, identityKey, counter FROM keyDirManifests WHERE identScreenName = ?`,
		screenName.String()).Scan(&storedAlg, &storedKey, &storedCounter)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Nothing published yet. Any counter is acceptable -- there is no
		// history for it to contradict.
		err = nil
	case err != nil:
		return 0, err
	case storedAlg == m.IdentityAlg && bytes.Equal(storedKey, m.IdentityKey):
		// Same identity, so the counter must move forward.
		if m.Counter <= uint64(storedCounter) {
			return uint64(storedCounter), fmt.Errorf("%w: got %d, hold %d", ErrStaleCounter, m.Counter, storedCounter)
		}
	default:
		// A different identity. Accepted, and the counter starts over. See the
		// doc comment: the server has no basis to judge this and does not try.
	}

	// A plain REPLACE rather than an UPDATE-or-INSERT: publishing replaces the
	// manifest wholesale because the manifest IS the whole statement, and there
	// is no partial update that would make sense.
	if _, err = tx.ExecContext(ctx, `
		REPLACE INTO keyDirManifests
			(identScreenName, identityAlg, identityKey, counter, issuedAt, manifest, sigAlg, signature)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		screenName.String(), m.IdentityAlg, m.IdentityKey, int64(m.Counter),
		m.IssuedAt.Unix(), m.Manifest, m.SigAlg, m.Signature); err != nil {
		return 0, err
	}

	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return m.Counter, nil
}

// IdentityBackup returns an account's encrypted identity key, or (nil, nil) if
// none has been stored.
//
// Absence is the answer a first run depends on, not a failure: no backup means
// the account has never bootstrapped an identity, which is what tells a client
// to generate one and show a recovery phrase rather than prompt for it.
func (f SQLiteUserStore) IdentityBackup(ctx context.Context, screenName IdentScreenName) (*IdentityBackup, error) {
	var (
		b         IdentityBackup
		updatedAt int64
	)
	err := f.db.QueryRowContext(ctx,
		`SELECT kdf, params, salt, blob, updatedAt FROM keyDirIdentityBackups WHERE identScreenName = ?`,
		screenName.String()).Scan(&b.KDF, &b.Params, &b.Salt, &b.Blob, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	b.UpdatedAt = time.Unix(updatedAt, 0)
	return &b, nil
}

// SetIdentityBackup stores or replaces an account's encrypted identity key.
//
// Replacing is how re-keying works: the same identity private key wrapped under
// a new recovery phrase. That is deliberately NOT the same operation as taking a
// new identity -- the key inside is unchanged, so every device stays signed and
// no contact's safety number moves. A user who thinks their written-down phrase
// was seen can fix it without disturbing anybody.
//
// The server cannot tell a re-key from an identity replacement here, and does
// not need to: it is storing opaque ciphertext either way, and what actually
// distinguishes them is whether the manifests that follow are signed by the same
// identity key.
// The row it replaces is archived first. REPLACE INTO on its own made this a
// destructive write against the ONLY copy of an account's identity key -- and it
// is reachable by anyone holding the account password, since the server cannot
// tell a re-key from a hostile replacement. Losing that key does not break
// existing devices, but it means no manifest can ever be signed again, so the
// device set is frozen for the life of the account. Archiving makes that
// recoverable by an operator; see migration 0038 for why prevention does not
// belong here.
func (f SQLiteUserStore) SetIdentityBackup(ctx context.Context, screenName IdentScreenName, b IdentityBackup) error {
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()

	// Archive whatever is there. No row means the account is bootstrapping and
	// there is nothing to keep, which is the common case and not an error.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO keyDirIdentityBackupHistory
			(identScreenName, kdf, params, salt, blob, updatedAt, supersededAt)
		SELECT identScreenName, kdf, params, salt, blob, updatedAt, ?
		FROM keyDirIdentityBackups WHERE identScreenName = ?`,
		now, screenName.String()); err != nil {
		return err
	}

	// Keep the archive bounded. Every retained row is the same identity key
	// wrapped under a phrase that has since been retired -- sometimes retired
	// BECAUSE it may have been seen -- so holding them forever slowly widens what
	// a stolen database is worth, and the recovery this exists for uses the most
	// recent ones.
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM keyDirIdentityBackupHistory
		WHERE identScreenName = ? AND id NOT IN (
			SELECT id FROM keyDirIdentityBackupHistory
			WHERE identScreenName = ? ORDER BY id DESC LIMIT ?
		)`,
		screenName.String(), screenName.String(), identityBackupHistoryDepth); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		REPLACE INTO keyDirIdentityBackups (identScreenName, kdf, params, salt, blob, updatedAt)
		VALUES (?, ?, ?, ?, ?, ?)`,
		screenName.String(), b.KDF, b.Params, b.Salt, b.Blob, now); err != nil {
		return err
	}
	return tx.Commit()
}

// identityBackupHistoryDepth is how many superseded identity backups are kept
// per account. Deep enough to survive an attacker overwriting repeatedly to push
// the good row out, shallow enough that retired recovery phrases do not
// accumulate indefinitely.
const identityBackupHistoryDepth = 20

// SupersededIdentityBackup is an identity backup that has since been replaced.
type SupersededIdentityBackup struct {
	IdentityBackup
	// SupersededAt is when this row stopped being the live one. UpdatedAt, on the
	// embedded backup, is when it was written -- together they bound the window
	// in which this was the account's identity.
	SupersededAt time.Time
}

// IdentityBackupHistory returns an account's superseded identity backups, most
// recently replaced first.
//
// Deliberately NOT reachable over the wire. Nothing a client can authenticate as
// should be able to enumerate old wrappings of an identity key: a password-holder
// is exactly the attacker this exists to recover FROM, and handing them older
// ciphertexts to grind offline would trade the fix for a wider hole. This is for
// an operator with database access, restoring by hand after establishing what
// happened.
func (f SQLiteUserStore) IdentityBackupHistory(ctx context.Context, screenName IdentScreenName) ([]SupersededIdentityBackup, error) {
	rows, err := f.db.QueryContext(ctx, `
		SELECT kdf, params, salt, blob, updatedAt, supersededAt
		FROM keyDirIdentityBackupHistory
		WHERE identScreenName = ?
		ORDER BY id DESC`, screenName.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SupersededIdentityBackup
	for rows.Next() {
		var (
			b                       SupersededIdentityBackup
			updatedAt, supersededAt int64
		)
		if err := rows.Scan(&b.KDF, &b.Params, &b.Salt, &b.Blob, &updatedAt, &supersededAt); err != nil {
			return nil, err
		}
		b.UpdatedAt = time.Unix(updatedAt, 0)
		b.SupersededAt = time.Unix(supersededAt, 0)
		out = append(out, b)
	}
	return out, rows.Err()
}
