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

// The byte layout is pinned deliberately. A round-trip test alone would happily
// pass if both encoder and decoder changed together, which is exactly the change
// that breaks every already-deployed client.
func TestBENCODevice_ByteLayout(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, MarshalBE(BENCODevice{BoxKey: devKey(0xAA), SignKey: devKey(0xBB)}, buf))

	got := buf.Bytes()
	// uint16 length prefix + 32 bytes, twice.
	require.Len(t, got, 2+32+2+32)
	assert.Equal(t, []byte{0x00, 0x20}, got[0:2], "box key length prefix")
	assert.Equal(t, devKey(0xAA), got[2:34])
	assert.Equal(t, []byte{0x00, 0x20}, got[34:36], "signing key length prefix")
	assert.Equal(t, devKey(0xBB), got[36:68])
}

// A client that has not generated a signing key publishes an empty one. That has
// to encode as a zero-length field rather than being omitted, or the decoder
// loses framing on every subsequent device in the list.
func TestBENCODevice_EmptySigningKey(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, MarshalBE(BENCODevice{BoxKey: devKey(1)}, buf))

	got := buf.Bytes()
	require.Len(t, got, 2+32+2)
	assert.Equal(t, []byte{0x00, 0x00}, got[34:36], "absent signing key must still carry a length")

	var back BENCODevice
	require.NoError(t, UnmarshalBE(&back, bytes.NewReader(got)))
	assert.Equal(t, devKey(1), back.BoxKey)
	assert.Empty(t, back.SignKey)
}

func TestBENCOKeyDir_RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		// in and out must be the same concrete type; out is the decode target.
		in  any
		out any
	}{
		{
			name: "publish request",
			in: SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
				Version: BENCOKeyDirVersion,
				Devices: []BENCODevice{
					{BoxKey: devKey(1), SignKey: devKey(2)},
					{BoxKey: devKey(3)},
				},
			},
			out: &SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{},
		},
		{
			name: "publish request with no devices",
			in: SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
				Version: BENCOKeyDirVersion,
			},
			out: &SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{},
		},
		{
			name: "publish reply carrying refusals",
			in: SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply{
				Accepted: 2,
				Refused:  []BENCODevice{{BoxKey: devKey(9), SignKey: devKey(8)}},
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
				Devices:    []BENCODevice{{BoxKey: devKey(1), SignKey: devKey(2)}},
			},
			out: &SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply{},
		},
		{
			// An account that published nothing. Must survive the round trip as
			// an empty list rather than becoming an error.
			name: "query reply with no devices",
			in: SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply{
				ScreenName: "someuser",
			},
			out: &SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply{},
		},
		{
			name: "revoke request",
			in: SNAC_0xBE00_0x0006_BENCOKeyDirRevokeRequest{
				Version: BENCOKeyDirVersion,
				BoxKey:  devKey(7),
			},
			out: &SNAC_0xBE00_0x0006_BENCOKeyDirRevokeRequest{},
		},
		{
			name: "revoke reply",
			in:   SNAC_0xBE00_0x0007_BENCOKeyDirRevokeReply{Revoked: 1},
			out:  &SNAC_0xBE00_0x0007_BENCOKeyDirRevokeReply{},
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
		BENCOKeyDirRevokeRequest,
		BENCOKeyDirRevokeReply,
	} {
		_, ok := limits.RateClassLookup(BENCOKeyDir, sub)
		assert.True(t, ok, "subgroup %s has no rate class", SubGroupName(BENCOKeyDir, sub))
	}

	// Upstream's own classes must survive the wrapper.
	_, ok := limits.RateClassLookup(ICBM, ICBMChannelMsgToHost)
	assert.True(t, ok, "wrapping must not drop upstream's rate limits")
}
