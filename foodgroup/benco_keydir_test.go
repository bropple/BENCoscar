package foodgroup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// BENCO addition — key directory v2 service. See benco_keydir.go.

// fakeKeyDirManager is a hand-written stub rather than a mockery mock.
//
// mockery is not installed in this environment and the generated mocks are
// committed, so generating one here would produce a file the next `mockery` run
// might not reproduce identically. The behaviour needed is a map, and recording
// the screen name each call was made with is precisely what the important test
// in this file asserts.
type fakeKeyDirManager struct {
	manifests  map[string]state.KeyManifest
	backups    map[string]state.IdentityBackup
	publishErr error
	err        error

	// Recorded arguments, so tests can prove the service passes the SESSION's
	// screen name rather than anything a client supplied.
	publishedFor state.IdentScreenName
	published    state.KeyManifest
	queriedFor   state.IdentScreenName
	backupPutFor state.IdentScreenName
	backupGotFor state.IdentScreenName
}

func (f *fakeKeyDirManager) KeyManifest(_ context.Context, sn state.IdentScreenName) (*state.KeyManifest, error) {
	f.queriedFor = sn
	if f.err != nil {
		return nil, f.err
	}
	m, ok := f.manifests[sn.String()]
	if !ok {
		return nil, nil
	}
	return &m, nil
}

func (f *fakeKeyDirManager) PublishManifest(_ context.Context, sn state.IdentScreenName, m state.KeyManifest) (uint64, error) {
	f.publishedFor = sn
	f.published = m
	if f.publishErr != nil {
		return 42, f.publishErr // 42 = the counter the "server" already holds
	}
	if f.err != nil {
		return 0, f.err
	}
	if f.manifests == nil {
		f.manifests = map[string]state.KeyManifest{}
	}
	f.manifests[sn.String()] = m
	return m.Counter, nil
}

func (f *fakeKeyDirManager) IdentityBackup(_ context.Context, sn state.IdentScreenName) (*state.IdentityBackup, error) {
	f.backupGotFor = sn
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.backups[sn.String()]
	if !ok {
		return nil, nil
	}
	return &b, nil
}

func (f *fakeKeyDirManager) SetIdentityBackup(_ context.Context, sn state.IdentScreenName, b state.IdentityBackup) error {
	f.backupPutFor = sn
	if f.err != nil {
		return f.err
	}
	if f.backups == nil {
		f.backups = map[string]state.IdentityBackup{}
	}
	f.backups[sn.String()] = b
	return nil
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

// testIdentity returns a deterministic Ed25519 keypair. Deterministic so a
// failing test reproduces rather than depending on which key was drawn.
func testIdentity(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

// signedManifest builds a publish request carrying a correctly signed manifest.
func signedManifest(t *testing.T, priv ed25519.PrivateKey, m wire.BENCOManifest) wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest {
	t.Helper()
	buf := &bytes.Buffer{}
	require.NoError(t, wire.MarshalBE(m, buf))
	return wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
		Version:   wire.BENCOKeyDirVersion,
		Manifest:  buf.Bytes(),
		SigAlg:    wire.BENCOAlgEd25519,
		Signature: ed25519.Sign(priv, buf.Bytes()),
	}
}

// manifestFor builds a well-formed manifest for an account.
func manifestFor(pub ed25519.PublicKey, screenName string, counter uint64) wire.BENCOManifest {
	return wire.BENCOManifest{
		Version:    wire.BENCOKeyDirVersion,
		ScreenName: screenName,
		Counter:    counter,
		IssuedAt:   1752883200,
		Identity:   wire.BENCOKey{Alg: wire.BENCOAlgEd25519, Key: pub},
		Devices: []wire.BENCODevice{
			{
				Box:   wire.BENCOKey{Alg: wire.BENCOAlgX25519, Key: devKey(1)},
				Sign:  wire.BENCOKey{Alg: wire.BENCOAlgEd25519, Key: devKey(2)},
				Label: "thinkpad",
			},
		},
	}
}

func TestBENCOKeyDir_PublishStoresASignedManifest(t *testing.T) {
	pub, priv := testIdentity(t, 1)
	mgr := &fakeKeyDirManager{}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	in := signedManifest(t, priv, manifestFor(pub, "alice", 3))
	out, err := svc.PublishManifest(context.Background(), testSession("alice"), wire.SNACFrame{RequestID: 7}, in)
	require.NoError(t, err)

	assert.Equal(t, state.NewIdentScreenName("alice"), mgr.publishedFor)
	assert.Equal(t, wire.BENCOKeyDirPublishReply, out.Frame.SubGroup)
	assert.Equal(t, uint32(7), out.Frame.RequestID)

	body := out.Body.(wire.SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply)
	assert.Equal(t, uint8(1), body.Accepted)
	assert.Equal(t, uint64(3), body.Counter)
}

// THE constraint of the whole design. The service decodes a manifest to CHECK
// it, then throws the decoded struct away and stores the original bytes. A
// service that re-encoded from the struct would invalidate the detached
// signature for every client that fetched it afterwards, and the failure would
// look like a signature bug on the peer rather than a server one.
func TestBENCOKeyDir_ManifestIsStoredAndServedVerbatim(t *testing.T) {
	pub, priv := testIdentity(t, 1)
	mgr := &fakeKeyDirManager{}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)
	ctx := context.Background()

	in := signedManifest(t, priv, manifestFor(pub, "alice", 1))
	_, err := svc.PublishManifest(ctx, testSession("alice"), wire.SNACFrame{}, in)
	require.NoError(t, err)

	assert.Equal(t, in.Manifest, mgr.published.Manifest, "stored bytes must be the bytes received")
	assert.Equal(t, in.Signature, mgr.published.Signature)

	out, err := svc.QueryManifest(ctx, wire.SNACFrame{},
		wire.SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest{
			Version:    wire.BENCOKeyDirVersion,
			ScreenName: "alice",
		})
	require.NoError(t, err)

	body := out.Body.(wire.SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply)
	assert.Equal(t, uint8(1), body.Present)
	assert.Equal(t, in.Manifest, body.Manifest, "served bytes must be the bytes received")

	// The end-to-end property that actually matters: what a peer fetches still
	// verifies under the identity key inside it.
	assert.True(t, ed25519.Verify(pub, body.Manifest, body.Signature),
		"a round trip through the server must not break the signature")
}

// The server verifies before storing. This is a cheap filter that keeps garbage
// out of the table, NOT a security boundary — a server that wanted to serve a
// forged manifest would simply not run the check — but a manifest no peer could
// ever verify has no business being stored.
func TestBENCOKeyDir_PublishRejectsABadSignature(t *testing.T) {
	pub, priv := testIdentity(t, 1)
	_, otherPriv := testIdentity(t, 2)
	m := manifestFor(pub, "alice", 1)

	buf := &bytes.Buffer{}
	require.NoError(t, wire.MarshalBE(m, buf))

	cases := []struct {
		name string
		req  wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest
	}{
		{
			// Signed by a key that is not the identity in the manifest.
			name: "signed by the wrong key",
			req: wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
				Version:   wire.BENCOKeyDirVersion,
				Manifest:  buf.Bytes(),
				SigAlg:    wire.BENCOAlgEd25519,
				Signature: ed25519.Sign(otherPriv, buf.Bytes()),
			},
		},
		{
			name: "signature over different bytes",
			req: wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
				Version:   wire.BENCOKeyDirVersion,
				Manifest:  buf.Bytes(),
				SigAlg:    wire.BENCOAlgEd25519,
				Signature: ed25519.Sign(priv, []byte("something else")),
			},
		},
		{
			name: "wrong signature length",
			req: wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
				Version:   wire.BENCOKeyDirVersion,
				Manifest:  buf.Bytes(),
				SigAlg:    wire.BENCOAlgEd25519,
				Signature: []byte{1, 2, 3},
			},
		},
		{
			// A reserved post-quantum identifier. Storing a signature the server
			// cannot verify, under the pretence of having verified it, is worse
			// than refusing it.
			name: "unimplemented signature algorithm",
			req: wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
				Version:   wire.BENCOKeyDirVersion,
				Manifest:  buf.Bytes(),
				SigAlg:    wire.BENCOAlgMLDSA65,
				Signature: ed25519.Sign(priv, buf.Bytes()),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mgr := &fakeKeyDirManager{}
			svc := NewBENCOKeyDirService(slog.Default(), mgr)

			out, err := svc.PublishManifest(context.Background(), testSession("alice"), wire.SNACFrame{}, tc.req)
			require.NoError(t, err)

			assert.Equal(t, wire.BENCOKeyDirErr, out.Frame.SubGroup)
			assert.Empty(t, mgr.publishedFor.String(), "an unverifiable manifest must not reach storage")
		})
	}
}

// The screen name inside the signature must be the session's.
//
// Without this check a manifest is a portable signed object: lift Alice's,
// present it on a session for an account you control, and the signature still
// verifies perfectly. The check is what binds the statement to the account it
// was made for, and it is why ScreenName is inside the signed bytes at all.
func TestBENCOKeyDir_PublishRejectsAScreenNameMismatch(t *testing.T) {
	pub, priv := testIdentity(t, 1)
	mgr := &fakeKeyDirManager{}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	// A perfectly valid manifest — for somebody else.
	in := signedManifest(t, priv, manifestFor(pub, "alice", 1))

	out, err := svc.PublishManifest(context.Background(), testSession("mallory"), wire.SNACFrame{}, in)
	require.NoError(t, err)

	assert.Equal(t, wire.BENCOKeyDirErr, out.Frame.SubGroup)
	assert.Empty(t, mgr.publishedFor.String(), "a replayed manifest must not reach storage")
}

// Screen names compare in their identifier form, so the same account written
// with different spacing or case is still the same account. Rejecting "Alice
// Smith" on a session for "alicesmith" would break a legitimate client for no
// reason.
func TestBENCOKeyDir_PublishScreenNameComparisonIsNormalised(t *testing.T) {
	pub, priv := testIdentity(t, 1)
	mgr := &fakeKeyDirManager{}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	in := signedManifest(t, priv, manifestFor(pub, "Alice Smith", 1))

	out, err := svc.PublishManifest(context.Background(), testSession("alicesmith"), wire.SNACFrame{}, in)
	require.NoError(t, err)
	assert.Equal(t, wire.BENCOKeyDirPublishReply, out.Frame.SubGroup)
}

// A stale counter is refused, and the reply still carries the counter the server
// holds so a client that lost a race learns what it needs to beat rather than
// having to re-query to find out.
func TestBENCOKeyDir_PublishReportsAStaleCounter(t *testing.T) {
	pub, priv := testIdentity(t, 1)
	mgr := &fakeKeyDirManager{publishErr: state.ErrStaleCounter}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	in := signedManifest(t, priv, manifestFor(pub, "alice", 2))
	out, err := svc.PublishManifest(context.Background(), testSession("alice"), wire.SNACFrame{}, in)
	require.NoError(t, err, "a stale counter is a refusal, not a server error")

	body := out.Body.(wire.SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply)
	assert.Equal(t, uint8(0), body.Accepted)
	assert.Equal(t, uint64(42), body.Counter, "the reply must report the counter the server holds")
}

// A storage failure is a server error and must propagate, not be dressed up as a
// refusal. A client told "refused" would retry forever against a broken database.
func TestBENCOKeyDir_PublishPropagatesStorageErrors(t *testing.T) {
	pub, priv := testIdentity(t, 1)
	mgr := &fakeKeyDirManager{err: errors.New("database is on fire")}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	in := signedManifest(t, priv, manifestFor(pub, "alice", 1))
	_, err := svc.PublishManifest(context.Background(), testSession("alice"), wire.SNACFrame{}, in)
	assert.Error(t, err)
}

func TestBENCOKeyDir_PublishRejectsMalformedManifests(t *testing.T) {
	pub, priv := testIdentity(t, 1)

	cases := []struct {
		name   string
		mutate func(*wire.BENCOManifest)
	}{
		{
			// Counter 0 is refused so "no manifest" and "the first manifest"
			// cannot be confused by anything treating zero as unset.
			name:   "counter zero",
			mutate: func(m *wire.BENCOManifest) { m.Counter = 0 },
		},
		{
			name:   "wrong manifest version",
			mutate: func(m *wire.BENCOManifest) { m.Version = 99 },
		},
		{
			name: "too many devices",
			mutate: func(m *wire.BENCOManifest) {
				m.Devices = nil
				for range state.MaxDevicesPerAccount + 1 {
					m.Devices = append(m.Devices, wire.BENCODevice{
						Box:  wire.BENCOKey{Alg: wire.BENCOAlgX25519, Key: devKey(1)},
						Sign: wire.BENCOKey{Alg: wire.BENCOAlgEd25519, Key: devKey(2)},
					})
				}
			},
		},
		{
			// Wrong-length key material stored here would be handed to peers as
			// an encryption key and produce undecryptable messages far from the
			// cause, so it must never reach storage.
			name: "short box key",
			mutate: func(m *wire.BENCOManifest) {
				m.Devices[0].Box.Key = []byte{1, 2, 3}
			},
		},
		{
			name: "box key with the wrong algorithm",
			mutate: func(m *wire.BENCOManifest) {
				m.Devices[0].Box.Alg = wire.BENCOAlgEd25519
			},
		},
		{
			name: "identity key with an unimplemented algorithm",
			mutate: func(m *wire.BENCOManifest) {
				m.Identity.Alg = wire.BENCOAlgMLDSA65
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := manifestFor(pub, "alice", 1)
			tc.mutate(&m)

			mgr := &fakeKeyDirManager{}
			svc := NewBENCOKeyDirService(slog.Default(), mgr)

			// Signed correctly, so only the malformation can be the reason.
			out, err := svc.PublishManifest(context.Background(), testSession("alice"),
				wire.SNACFrame{}, signedManifest(t, priv, m))
			require.NoError(t, err)

			assert.Equal(t, wire.BENCOKeyDirErr, out.Frame.SubGroup)
			assert.Empty(t, mgr.publishedFor.String(), "a malformed manifest must not reach storage")
		})
	}
}

// A device that has not generated a signing key is legitimate, not malformed.
func TestBENCOKeyDir_PublishAcceptsAnAbsentSigningKey(t *testing.T) {
	pub, priv := testIdentity(t, 1)
	m := manifestFor(pub, "alice", 1)
	m.Devices[0].Sign = wire.BENCOKey{}

	svc := NewBENCOKeyDirService(slog.Default(), &fakeKeyDirManager{})
	out, err := svc.PublishManifest(context.Background(), testSession("alice"),
		wire.SNACFrame{}, signedManifest(t, priv, m))
	require.NoError(t, err)
	assert.Equal(t, wire.BENCOKeyDirPublishReply, out.Frame.SubGroup)
}

// A garbage blob must be refused rather than stored. Nothing could ever verify
// it, and every peer that fetched it would pay to find that out.
func TestBENCOKeyDir_PublishRejectsAnUndecodableManifest(t *testing.T) {
	mgr := &fakeKeyDirManager{}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	for _, blob := range [][]byte{nil, {}, []byte("not a manifest")} {
		out, err := svc.PublishManifest(context.Background(), testSession("alice"), wire.SNACFrame{},
			wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
				Version:   wire.BENCOKeyDirVersion,
				Manifest:  blob,
				SigAlg:    wire.BENCOAlgEd25519,
				Signature: make([]byte, wire.BENCOEd25519SigLen),
			})
		require.NoError(t, err)
		assert.Equal(t, wire.BENCOKeyDirErr, out.Frame.SubGroup)
	}
	assert.Empty(t, mgr.publishedFor.String())
}

// Querying reads storage, not a session — which is the whole reason the
// directory exists. An offline user and the caller's own account both work.
func TestBENCOKeyDir_QueryReturnsAManifest(t *testing.T) {
	mgr := &fakeKeyDirManager{manifests: map[string]state.KeyManifest{
		"bob": {Manifest: []byte("bytes"), SigAlg: wire.BENCOAlgEd25519, Signature: []byte("sig")},
	}}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	out, err := svc.QueryManifest(context.Background(), wire.SNACFrame{RequestID: 3},
		wire.SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest{ScreenName: "bob"})
	require.NoError(t, err)

	assert.Equal(t, state.NewIdentScreenName("bob"), mgr.queriedFor)
	body := out.Body.(wire.SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply)
	assert.Equal(t, "bob", body.ScreenName)
	assert.Equal(t, uint8(1), body.Present)
	assert.Equal(t, []byte("bytes"), body.Manifest)
}

// An account that published nothing is a normal answer, not a failure: it means
// they have not bootstrapped an identity yet.
func TestBENCOKeyDir_QueryUnknownUserIsAbsentNotError(t *testing.T) {
	svc := NewBENCOKeyDirService(slog.Default(), &fakeKeyDirManager{})

	out, err := svc.QueryManifest(context.Background(), wire.SNACFrame{},
		wire.SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest{ScreenName: "nobody"})
	require.NoError(t, err)

	body := out.Body.(wire.SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply)
	assert.Equal(t, uint8(0), body.Present)
	assert.Empty(t, body.Manifest)
}

func TestBENCOKeyDir_BackupRoundTrips(t *testing.T) {
	mgr := &fakeKeyDirManager{}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)
	ctx := context.Background()
	sess := testSession("alice")

	// Nothing stored: the first-run answer.
	out, err := svc.GetBackup(ctx, sess, wire.SNACFrame{},
		wire.SNAC_0xBE00_0x0008_BENCOKeyDirGetBackupRequest{Version: wire.BENCOKeyDirVersion})
	require.NoError(t, err)
	assert.Equal(t, uint8(0), out.Body.(wire.SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply).Present)

	put := wire.SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest{
		Version: wire.BENCOKeyDirVersion,
		KDF:     wire.BENCOKDFArgon2id,
		Params:  []byte{0x00, 0x03, 0x00, 0x40},
		Salt:    []byte("sixteen-byte-slt"),
		Blob:    []byte{0x00, 0xFF, 0xAB},
	}
	out, err = svc.PutBackup(ctx, sess, wire.SNACFrame{RequestID: 5}, put)
	require.NoError(t, err)
	assert.Equal(t, wire.BENCOKeyDirPutBackupReply, out.Frame.SubGroup)
	assert.Equal(t, uint8(1), out.Body.(wire.SNAC_0xBE00_0x0007_BENCOKeyDirPutBackupReply).Stored)
	assert.Equal(t, state.NewIdentScreenName("alice"), mgr.backupPutFor)

	out, err = svc.GetBackup(ctx, sess, wire.SNACFrame{RequestID: 6},
		wire.SNAC_0xBE00_0x0008_BENCOKeyDirGetBackupRequest{Version: wire.BENCOKeyDirVersion})
	require.NoError(t, err)

	body := out.Body.(wire.SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply)
	assert.Equal(t, uint8(1), body.Present)
	assert.Equal(t, put.KDF, body.KDF)
	assert.Equal(t, put.Params, body.Params)
	assert.Equal(t, put.Salt, body.Salt)
	assert.Equal(t, put.Blob, body.Blob, "the blob is ciphertext and must survive byte for byte")
	assert.Equal(t, uint32(6), out.Frame.RequestID)
}

// A backup is always the SESSION's own. The request has no screen name field,
// and this pins that: serving one account's blob to another would reduce a
// takeover to an offline attack against a phrase written on paper years ago.
func TestBENCOKeyDir_BackupIsScopedToTheSession(t *testing.T) {
	mgr := &fakeKeyDirManager{backups: map[string]state.IdentityBackup{
		"alice": {KDF: 0x01, Blob: []byte("alice-secret")},
	}}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	out, err := svc.GetBackup(context.Background(), testSession("mallory"), wire.SNACFrame{},
		wire.SNAC_0xBE00_0x0008_BENCOKeyDirGetBackupRequest{Version: wire.BENCOKeyDirVersion})
	require.NoError(t, err)

	assert.Equal(t, state.NewIdentScreenName("mallory"), mgr.backupGotFor)
	body := out.Body.(wire.SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply)
	assert.Equal(t, uint8(0), body.Present, "mallory must not receive alice's backup")
}

func TestBENCOKeyDir_PutBackupRejectsMalformedRequests(t *testing.T) {
	valid := wire.SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest{
		Version: wire.BENCOKeyDirVersion,
		KDF:     wire.BENCOKDFArgon2id,
		Params:  []byte{1},
		Salt:    []byte("salt"),
		Blob:    []byte("blob"),
	}

	cases := []struct {
		name   string
		mutate func(*wire.SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest)
	}{
		{"wrong version", func(r *wire.SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest) { r.Version = 1 }},
		{"unknown KDF", func(r *wire.SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest) { r.KDF = 0x7F }},
		{"no salt", func(r *wire.SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest) { r.Salt = nil }},
		{"no blob", func(r *wire.SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest) { r.Blob = nil }},
		{
			// The one place the protocol lets a client store arbitrary bytes the
			// server hands back, so it must not become a file host.
			name: "oversized blob",
			mutate: func(r *wire.SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest) {
				r.Blob = make([]byte, wire.BENCOKeyDirMaxBackupLen+1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := valid
			tc.mutate(&req)

			mgr := &fakeKeyDirManager{}
			svc := NewBENCOKeyDirService(slog.Default(), mgr)

			out, err := svc.PutBackup(context.Background(), testSession("alice"), wire.SNACFrame{}, req)
			require.NoError(t, err)
			assert.Equal(t, wire.BENCOKeyDirErr, out.Frame.SubGroup)
			assert.Empty(t, mgr.backupPutFor.String(), "a malformed backup must not reach storage")
		})
	}
}

// The payload version is not a dispatch point any more — v1 is gone — so an
// unrecognised version is refused rather than routed somewhere else.
func TestBENCOKeyDir_PublishRejectsAnUnknownPayloadVersion(t *testing.T) {
	pub, priv := testIdentity(t, 1)
	mgr := &fakeKeyDirManager{}
	svc := NewBENCOKeyDirService(slog.Default(), mgr)

	in := signedManifest(t, priv, manifestFor(pub, "alice", 1))
	in.Version = 1 // what a v1 client would have sent

	out, err := svc.PublishManifest(context.Background(), testSession("alice"), wire.SNACFrame{}, in)
	require.NoError(t, err)
	assert.Equal(t, wire.BENCOKeyDirErr, out.Frame.SubGroup)
	assert.Empty(t, mgr.publishedFor.String())
}
