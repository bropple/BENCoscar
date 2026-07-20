package wire

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BENCO addition — device key directory wire format.
//
// OSCAR is unforgiving about framing: a subtly wrong length manifests as a
// confusing disconnect a long way from its cause, not a helpful error. So these
// check the encoding at the byte level as well as round-tripping it.

func devKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func testManifest() BENCOManifest {
	return BENCOManifest{
		Version:    BENCOKeyDirVersion,
		ScreenName: "someuser",
		Counter:    7,
		IssuedAt:   1752883200,
		Identity:   BENCOKey{Alg: BENCOAlgEd25519, Key: devKey(0xCC)},
		Devices: []BENCODevice{
			{
				Box:   BENCOKey{Alg: BENCOAlgX25519, Key: devKey(0xAA)},
				Sign:  BENCOKey{Alg: BENCOAlgEd25519, Key: devKey(0xBB)},
				Label: "thinkpad",
			},
		},
	}
}

// The byte layout is pinned deliberately. A round-trip test alone would happily
// pass if both encoder and decoder changed together, which is exactly the change
// that breaks every already-deployed client — and here it would break every
// stored SIGNATURE too, since a signature covers these exact bytes.
func TestBENCOKey_ByteLayout(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, MarshalBE(BENCOKey{Alg: BENCOAlgEd25519, Key: devKey(0xAA)}, buf))

	got := buf.Bytes()
	// algorithm byte + uint16 length prefix + 32 bytes.
	require.Len(t, got, 1+2+32)
	assert.Equal(t, byte(0x02), got[0], "algorithm identifier")
	assert.Equal(t, []byte{0x00, 0x20}, got[1:3], "key length prefix")
	assert.Equal(t, devKey(0xAA), got[3:35])
}

// A device that has not generated a signing key publishes an empty one. That has
// to encode as algorithm 0 with a zero-length key rather than being omitted, or
// the decoder loses framing on every subsequent device in the list.
func TestBENCODevice_AbsentSigningKey(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, MarshalBE(BENCODevice{
		Box: BENCOKey{Alg: BENCOAlgX25519, Key: devKey(1)},
	}, buf))

	got := buf.Bytes()
	// box (1+2+32), absent sign key (1+2), empty label (1).
	require.Len(t, got, 35+3+1)
	assert.Equal(t, byte(0x00), got[35], "absent signing key must still carry an algorithm byte")
	assert.Equal(t, []byte{0x00, 0x00}, got[36:38], "absent signing key must still carry a length")
	assert.Equal(t, byte(0x00), got[38], "absent label must still carry a length")

	var back BENCODevice
	require.NoError(t, UnmarshalBE(&back, bytes.NewReader(got)))
	assert.Equal(t, devKey(1), back.Box.Key)
	assert.Empty(t, back.Sign.Key)
	assert.Empty(t, back.Label)
}

// The label is length-prefixed with a single byte, which caps it at 255. Worth
// pinning: widening it later would silently reframe every manifest after it.
func TestBENCODevice_LabelIsUint8Prefixed(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, MarshalBE(BENCODevice{
		Box:   BENCOKey{Alg: BENCOAlgX25519, Key: devKey(1)},
		Sign:  BENCOKey{Alg: BENCOAlgEd25519, Key: devKey(2)},
		Label: "desktop",
	}, buf))

	got := buf.Bytes()
	labelAt := 35 + 35
	assert.Equal(t, byte(7), got[labelAt], "label length prefix is one byte")
	assert.Equal(t, "desktop", string(got[labelAt+1:]))
}

// The manifest is signed as bytes, so its encoding is a compatibility surface in
// a way an ordinary SNAC is not: changing it invalidates every signature already
// published, not merely every client already deployed.
func TestBENCOManifest_ByteLayout(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, MarshalBE(BENCOManifest{
		Version:    BENCOKeyDirVersion,
		ScreenName: "abc",
		Counter:    1,
		IssuedAt:   2,
		Identity:   BENCOKey{Alg: BENCOAlgEd25519, Key: devKey(9)},
	}, buf))

	got := buf.Bytes()
	assert.Equal(t, []byte{0x00, 0x02}, got[0:2], "version")
	assert.Equal(t, byte(3), got[2], "screen name is uint8-prefixed")
	assert.Equal(t, "abc", string(got[3:6]))
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 1}, got[6:14], "counter is a big-endian uint64")
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 2}, got[14:22], "issuedAt is a big-endian uint64")
	assert.Equal(t, byte(0x02), got[22], "identity algorithm")
	// Then the identity key (2+32), then a uint16 device count of zero.
	assert.Equal(t, []byte{0x00, 0x00}, got[57:59], "empty device list still carries a count")
}

// Encoding a manifest must be deterministic. If it were not, a client that
// encoded, signed, and encoded again would produce a signature over bytes it
// never sent — and the failure would look like a verification bug on the peer.
func TestBENCOManifest_EncodingIsDeterministic(t *testing.T) {
	m := testManifest()

	first := &bytes.Buffer{}
	require.NoError(t, MarshalBE(m, first))

	for range 8 {
		again := &bytes.Buffer{}
		require.NoError(t, MarshalBE(m, again))
		require.Equal(t, first.Bytes(), again.Bytes())
	}
}

// Decoding a manifest and re-encoding it must reproduce the original bytes.
//
// The SERVER must never do this — it stores what it was given — but a client
// that fetches a manifest, decodes it to read the device list, and then wants to
// re-verify has to get the same bytes back or nothing verifies.
func TestBENCOManifest_DecodeReencodeIsIdentical(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, MarshalBE(testManifest(), buf))

	var back BENCOManifest
	require.NoError(t, UnmarshalBE(&back, bytes.NewReader(buf.Bytes())))

	reBuf := &bytes.Buffer{}
	require.NoError(t, MarshalBE(back, reBuf))
	assert.Equal(t, buf.Bytes(), reBuf.Bytes())
}

func TestBENCOKeyDir_RoundTrip(t *testing.T) {
	manifestBytes := func() []byte {
		buf := &bytes.Buffer{}
		require.NoError(t, MarshalBE(testManifest(), buf))
		return buf.Bytes()
	}()
	sig := make([]byte, BENCOEd25519SigLen)
	for i := range sig {
		sig[i] = byte(i)
	}

	cases := []struct {
		name string
		// in and out must be the same concrete type; out is the decode target.
		in  any
		out any
	}{
		{
			name: "publish request",
			in: SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
				Version:   BENCOKeyDirVersion,
				Manifest:  manifestBytes,
				SigAlg:    BENCOAlgEd25519,
				Signature: sig,
			},
			out: &SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{},
		},
		{
			name: "publish reply",
			in: SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply{
				Accepted: 1,
				Counter:  7,
			},
			out: &SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply{},
		},
		{
			// A rejected publish still reports the counter the server holds, so
			// a client that lost a race learns what it needs to beat.
			name: "publish reply refusing a stale counter",
			in: SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply{
				Accepted: 0,
				Counter:  9,
			},
			out: &SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply{},
		},
		{
			name: "query request",
			in: SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest{
				Version:    BENCOKeyDirVersion,
				ScreenName: "someuser",
			},
			out: &SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest{},
		},
		{
			name: "query reply",
			in: SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply{
				ScreenName: "someuser",
				Present:    1,
				Manifest:   manifestBytes,
				SigAlg:     BENCOAlgEd25519,
				Signature:  sig,
			},
			out: &SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply{},
		},
		{
			// An account that has never bootstrapped an identity. Must survive
			// the round trip as Present=0 rather than becoming an error.
			name: "query reply with no manifest",
			in: SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply{
				ScreenName: "someuser",
			},
			out: &SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply{},
		},
		{
			name: "put backup request",
			in: SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest{
				Version: BENCOKeyDirVersion,
				KDF:     BENCOKDFArgon2id,
				Params:  []byte{0, 3, 0, 64},
				Salt:    []byte("sixteen-byte-slt"),
				Blob:    []byte("ciphertext"),
			},
			out: &SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest{},
		},
		{
			name: "put backup reply",
			in:   SNAC_0xBE00_0x0007_BENCOKeyDirPutBackupReply{Stored: 1},
			out:  &SNAC_0xBE00_0x0007_BENCOKeyDirPutBackupReply{},
		},
		{
			name: "get backup request",
			in:   SNAC_0xBE00_0x0008_BENCOKeyDirGetBackupRequest{Version: BENCOKeyDirVersion},
			out:  &SNAC_0xBE00_0x0008_BENCOKeyDirGetBackupRequest{},
		},
		{
			name: "get backup reply",
			in: SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply{
				Present: 1,
				KDF:     BENCOKDFArgon2id,
				Params:  []byte{0, 3, 0, 64},
				Salt:    []byte("sixteen-byte-slt"),
				Blob:    []byte("ciphertext"),
			},
			out: &SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply{},
		},
		{
			// The first-run answer: no identity has been bootstrapped. This is
			// what tells a client which flow it is in, so it has to decode
			// cleanly rather than being an absent-field special case.
			name: "get backup reply with nothing stored",
			in:   SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply{},
			out:  &SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			require.NoError(t, MarshalBE(tc.in, buf))
			require.NoError(t, UnmarshalBE(tc.out, bytes.NewReader(buf.Bytes())))

			// Compare through a second encode: the decoded value re-encodes to
			// the same bytes, which is the property that actually matters.
			// Dereferenced because the codec only marshals struct values, not
			// the pointer UnmarshalBE needs as its target.
			reBuf := &bytes.Buffer{}
			require.NoError(t, MarshalBE(reflect.ValueOf(tc.out).Elem().Interface(), reBuf))
			assert.Equal(t, buf.Bytes(), reBuf.Bytes())
		})
	}
}

// The foodgroup must sit outside the range upstream can allocate into, and its
// name must resolve for logging.
func TestBENCOKeyDir_Registration(t *testing.T) {
	assert.Greater(t, BENCOKeyDir, MDir,
		"the key directory must sit above upstream's allocated range")
	assert.Equal(t, "BENCOKeyDir", FoodGroupName(BENCOKeyDir))
	assert.Equal(t, "BENCOKeyDirPublishRequest", SubGroupName(BENCOKeyDir, BENCOKeyDirPublishRequest))
	assert.Equal(t, "BENCOKeyDirGetBackupReply", SubGroupName(BENCOKeyDir, BENCOKeyDirGetBackupReply))
}

// Clients silently fail when they expect a rate rule the server never sends, so
// every subgroup needs a class.
func TestBENCOKeyDir_RateLimitsRegistered(t *testing.T) {
	limits := WithBENCOKeyDirRateLimits(DefaultSNACRateLimits())

	for _, sub := range []uint16{
		BENCOKeyDirErr,
		BENCOKeyDirPublishRequest,
		BENCOKeyDirPublishReply,
		BENCOKeyDirQueryRequest,
		BENCOKeyDirQueryReply,
		BENCOKeyDirPutBackupRequest,
		BENCOKeyDirPutBackupReply,
		BENCOKeyDirGetBackupRequest,
		BENCOKeyDirGetBackupReply,
	} {
		_, ok := limits.RateClassLookup(BENCOKeyDir, sub)
		assert.True(t, ok, "subgroup %s has no rate class", SubGroupName(BENCOKeyDir, sub))
	}

	// Upstream's own classes must survive the wrapper.
	_, ok := limits.RateClassLookup(ICBM, ICBMChannelMsgToHost)
	assert.True(t, ok, "wrapping must not drop upstream's rate limits")
}
