package state

import (
	"context"
	"errors"
	"math"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BENCO addition — the key directory v2 store. See key_directory.go.
//
// These run against a real SQLite database, like the rest of this package's
// store tests, because the behaviour under test is mostly SQL: what a publish
// replaces, what the counter comparison does under an unchanged identity, and
// what happens to it when the identity changes.

// newKeyDirStore returns a store with a user row to hang a manifest off, since
// both tables have a foreign key onto users.
func newKeyDirStore(t *testing.T, screenNames ...string) (*SQLiteUserStore, []IdentScreenName) {
	t.Helper()

	f, err := NewSQLiteUserStore(testFile)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, os.Remove(testFile))
	})

	var out []IdentScreenName
	for _, sn := range screenNames {
		ident := NewIdentScreenName(sn)
		u := User{
			IdentScreenName:   ident,
			DisplayScreenName: DisplayScreenName(sn),
		}
		require.NoError(t, u.HashPassword("the_password"))
		require.NoError(t, f.InsertUser(context.Background(), u))
		out = append(out, ident)
	}
	return f, out
}

func identKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

// manifest builds a stored manifest. The blob is deliberately NOT a real encoded
// manifest: the storage layer never decodes it, and using arbitrary bytes here
// proves that rather than relying on a comment saying so.
func manifest(identity byte, counter uint64, blob string) KeyManifest {
	return KeyManifest{
		IdentityAlg: 0x02,
		IdentityKey: identKey(identity),
		Counter:     counter,
		IssuedAt:    time.Unix(1752883200, 0),
		Manifest:    []byte(blob),
		SigAlg:      0x02,
		Signature:   []byte("signature-over-" + blob),
	}
}

func TestKeyDirectory_PublishAndQuery(t *testing.T) {
	ctx := context.Background()
	f, sns := newKeyDirStore(t, "someuser")

	// Nothing published yet is a nil answer, not an error: an account that has
	// never bootstrapped an identity is what every first sign-on looks like.
	got, err := f.KeyManifest(ctx, sns[0])
	require.NoError(t, err)
	assert.Nil(t, got)

	counter, err := f.PublishManifest(ctx, sns[0], manifest(1, 1, "first"))
	require.NoError(t, err)
	assert.Equal(t, uint64(1), counter)

	got, err = f.KeyManifest(ctx, sns[0])
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, uint64(1), got.Counter)
	assert.Equal(t, identKey(1), got.IdentityKey)
	assert.Equal(t, uint8(0x02), got.IdentityAlg)
	assert.Equal(t, int64(1752883200), got.IssuedAt.Unix())
}

// THE constraint of the whole design: the bytes come back exactly as they went
// in. A signature covers those precise bytes, so a storage layer that normalised
// or re-encoded anything would invalidate every published manifest, and the
// failure would surface as a signature mismatch on a peer's client rather than
// as a server bug.
//
// The blob here is intentionally not a well-formed manifest, and includes a NUL
// and high bytes, because the point is that storage does not look inside it.
func TestKeyDirectory_ManifestBytesSurviveUnchanged(t *testing.T) {
	ctx := context.Background()
	f, sns := newKeyDirStore(t, "someuser")

	blob := []byte{0x00, 0xFF, 0x01, 0x80, 'n', 'o', 't', 0x00, 'a', 0xFE, 'm'}
	m := manifest(1, 1, "")
	m.Manifest = blob
	m.Signature = []byte{0xDE, 0xAD, 0x00, 0xBE, 0xEF}

	_, err := f.PublishManifest(ctx, sns[0], m)
	require.NoError(t, err)

	got, err := f.KeyManifest(ctx, sns[0])
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, blob, got.Manifest, "manifest bytes must survive storage byte for byte")
	assert.Equal(t, []byte{0xDE, 0xAD, 0x00, 0xBE, 0xEF}, got.Signature)
}

// Publishing replaces the manifest wholesale, because the manifest IS the whole
// signed statement and there is no partial update that would mean anything.
func TestKeyDirectory_PublishReplaces(t *testing.T) {
	ctx := context.Background()
	f, sns := newKeyDirStore(t, "someuser")

	_, err := f.PublishManifest(ctx, sns[0], manifest(1, 1, "first"))
	require.NoError(t, err)

	counter, err := f.PublishManifest(ctx, sns[0], manifest(1, 2, "second"))
	require.NoError(t, err)
	assert.Equal(t, uint64(2), counter)

	got, err := f.KeyManifest(ctx, sns[0])
	require.NoError(t, err)
	assert.Equal(t, []byte("second"), got.Manifest)
	assert.Equal(t, uint64(2), got.Counter)
}

// The rollback defence. Removing a device is nothing more than publishing a
// manifest without it at a higher counter, so accepting an older one would let a
// replayed manifest resurrect a machine the user had removed.
func TestKeyDirectory_StaleCounterIsRejected(t *testing.T) {
	ctx := context.Background()
	f, sns := newKeyDirStore(t, "someuser")

	_, err := f.PublishManifest(ctx, sns[0], manifest(1, 5, "current"))
	require.NoError(t, err)

	for _, counter := range []uint64{1, 4, 5} {
		held, err := f.PublishManifest(ctx, sns[0], manifest(1, counter, "replayed"))
		require.ErrorIs(t, err, ErrStaleCounter, "counter %d must not be accepted", counter)

		// The held counter comes back even on refusal, so a client that lost a
		// race learns what it needs to beat without re-querying.
		assert.Equal(t, uint64(5), held)
	}

	got, err := f.KeyManifest(ctx, sns[0])
	require.NoError(t, err)
	assert.Equal(t, []byte("current"), got.Manifest, "a refused publish must not have overwritten anything")
}

// An identity change resets the counter rather than being judged.
//
// A new identity legitimately starts at 1, and refusing that would mean an
// account that bootstrapped a fresh identity could never publish until it had
// counted past its own history. The server has no basis to decide whether the
// change is the account holder recovering or an attacker with the password
// installing their own — those two are cryptographically indistinguishable by
// construction, and adjudicating it is the client's job.
func TestKeyDirectory_IdentityChangeResetsTheCounter(t *testing.T) {
	ctx := context.Background()
	f, sns := newKeyDirStore(t, "someuser")

	_, err := f.PublishManifest(ctx, sns[0], manifest(1, 99, "old identity"))
	require.NoError(t, err)

	// Counter 1 under a DIFFERENT identity: accepted, despite being far below
	// the stored 99.
	counter, err := f.PublishManifest(ctx, sns[0], manifest(2, 1, "new identity"))
	require.NoError(t, err)
	assert.Equal(t, uint64(1), counter)

	got, err := f.KeyManifest(ctx, sns[0])
	require.NoError(t, err)
	assert.Equal(t, identKey(2), got.IdentityKey)
	assert.Equal(t, uint64(1), got.Counter)

	// And the new identity's counter is monotonic from there — the reset applies
	// to the change itself, not to everything that follows it.
	_, err = f.PublishManifest(ctx, sns[0], manifest(2, 1, "replay under new identity"))
	require.ErrorIs(t, err, ErrStaleCounter)
}

// Same key bytes but a different algorithm identifier is a different identity.
// Treating them as equal would mean the counter comparison silently spanned two
// distinct keys that merely happened to share a byte string.
func TestKeyDirectory_IdentityComparisonIncludesTheAlgorithm(t *testing.T) {
	ctx := context.Background()
	f, sns := newKeyDirStore(t, "someuser")

	_, err := f.PublishManifest(ctx, sns[0], manifest(1, 50, "ed25519"))
	require.NoError(t, err)

	other := manifest(1, 1, "some other scheme")
	other.IdentityAlg = 0x04
	counter, err := f.PublishManifest(ctx, sns[0], other)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), counter)
}

// SQLite's INTEGER is signed, so a uint64 above the signed maximum would wrap to
// a negative and then compare BACKWARDS — turning the rollback defence into a
// rollback assist. Refusing is safe: a real counter increments once per
// device-list change.
func TestKeyDirectory_CounterOutOfRangeIsRejected(t *testing.T) {
	ctx := context.Background()
	f, sns := newKeyDirStore(t, "someuser")

	_, err := f.PublishManifest(ctx, sns[0], manifest(1, math.MaxUint64, "wraps"))
	require.ErrorIs(t, err, ErrCounterOutOfRange)

	got, err := f.KeyManifest(ctx, sns[0])
	require.NoError(t, err)
	assert.Nil(t, got, "a refused publish must not have stored anything")

	// The largest value SQLite can hold faithfully is still accepted.
	_, err = f.PublishManifest(ctx, sns[0], manifest(1, math.MaxInt64, "fits"))
	require.NoError(t, err)
}

// One account's publish must not touch another's. The manifest is keyed on the
// screen name and nothing else reaches across.
func TestKeyDirectory_AccountsAreIsolated(t *testing.T) {
	ctx := context.Background()
	f, sns := newKeyDirStore(t, "alice", "bob")

	_, err := f.PublishManifest(ctx, sns[0], manifest(1, 3, "alice"))
	require.NoError(t, err)

	// bob has published nothing, and alice's high counter is no obstacle to him
	// starting at 1.
	got, err := f.KeyManifest(ctx, sns[1])
	require.NoError(t, err)
	assert.Nil(t, got)

	_, err = f.PublishManifest(ctx, sns[1], manifest(2, 1, "bob"))
	require.NoError(t, err)

	alice, err := f.KeyManifest(ctx, sns[0])
	require.NoError(t, err)
	assert.Equal(t, []byte("alice"), alice.Manifest)
}

func TestKeyDirectory_BackupRoundTrips(t *testing.T) {
	ctx := context.Background()
	f, sns := newKeyDirStore(t, "someuser")

	// Absence is the answer a first run depends on: no backup means the account
	// has never bootstrapped an identity.
	got, err := f.IdentityBackup(ctx, sns[0])
	require.NoError(t, err)
	assert.Nil(t, got)

	b := IdentityBackup{
		KDF:    0x01,
		Params: []byte{0x00, 0x03, 0x00, 0x40, 0x01},
		Salt:   []byte("sixteen-byte-slt"),
		Blob:   []byte{0x00, 0xFF, 0x10, 0x00, 0xAB}, // ciphertext, not text
	}
	require.NoError(t, f.SetIdentityBackup(ctx, sns[0], b))

	got, err = f.IdentityBackup(ctx, sns[0])
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, uint8(0x01), got.KDF)
	assert.Equal(t, b.Params, got.Params)
	assert.Equal(t, b.Salt, got.Salt)
	assert.Equal(t, b.Blob, got.Blob, "the blob is ciphertext and must survive byte for byte")
	assert.False(t, got.UpdatedAt.IsZero())
}

// Re-keying: the same identity private key wrapped under a new recovery phrase.
// Deliberately NOT the same operation as taking a new identity — the key inside
// is unchanged, so every device stays signed and no safety number moves.
func TestKeyDirectory_BackupIsReplaced(t *testing.T) {
	ctx := context.Background()
	f, sns := newKeyDirStore(t, "someuser")

	require.NoError(t, f.SetIdentityBackup(ctx, sns[0], IdentityBackup{
		KDF: 0x01, Params: []byte{1}, Salt: []byte("old-salt"), Blob: []byte("old"),
	}))
	require.NoError(t, f.SetIdentityBackup(ctx, sns[0], IdentityBackup{
		KDF: 0x01, Params: []byte{2}, Salt: []byte("new-salt"), Blob: []byte("new"),
	}))

	got, err := f.IdentityBackup(ctx, sns[0])
	require.NoError(t, err)
	assert.Equal(t, []byte("new"), got.Blob)
	assert.Equal(t, []byte("new-salt"), got.Salt)

	// Re-keying must not have disturbed the manifest. That is the whole point of
	// distinguishing it from an identity replacement.
	m, err := f.KeyManifest(ctx, sns[0])
	require.NoError(t, err)
	assert.Nil(t, m)
}

// A backup belongs to exactly one account. Serving one account's blob to another
// would reduce a takeover to an offline attack, so the store must not blur them.
func TestKeyDirectory_BackupsAreIsolated(t *testing.T) {
	ctx := context.Background()
	f, sns := newKeyDirStore(t, "alice", "bob")

	require.NoError(t, f.SetIdentityBackup(ctx, sns[0], IdentityBackup{
		KDF: 0x01, Params: []byte{1}, Salt: []byte("salt"), Blob: []byte("alice-secret"),
	}))

	got, err := f.IdentityBackup(ctx, sns[1])
	require.NoError(t, err)
	assert.Nil(t, got, "bob must not see alice's backup")
}

// Deleting an account takes its key material with it, through the same cascade
// the rest of the schema uses. A manifest outliving its account would be a
// dangling public key nobody could ever replace.
func TestKeyDirectory_CascadesOnUserDelete(t *testing.T) {
	ctx := context.Background()
	f, sns := newKeyDirStore(t, "someuser")

	_, err := f.PublishManifest(ctx, sns[0], manifest(1, 1, "manifest"))
	require.NoError(t, err)
	require.NoError(t, f.SetIdentityBackup(ctx, sns[0], IdentityBackup{
		KDF: 0x01, Params: []byte{1}, Salt: []byte("salt"), Blob: []byte("blob"),
	}))

	require.NoError(t, f.DeleteUser(ctx, sns[0]))

	m, err := f.KeyManifest(ctx, sns[0])
	require.NoError(t, err)
	assert.Nil(t, m)

	b, err := f.IdentityBackup(ctx, sns[0])
	require.NoError(t, err)
	assert.Nil(t, b)
}

// Sanity: the sentinel errors are distinct, since the service maps them to the
// same client-visible outcome and a future reader might assume they are aliases.
func TestKeyDirectory_SentinelErrorsAreDistinct(t *testing.T) {
	assert.False(t, errors.Is(ErrStaleCounter, ErrCounterOutOfRange))
	assert.False(t, errors.Is(ErrCounterOutOfRange, ErrStaleCounter))
}
