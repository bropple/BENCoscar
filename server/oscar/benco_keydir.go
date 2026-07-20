package oscar

import (
	"context"
	"io"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// BENCO addition: routing for the device key directory foodgroup (0xBE00).
//
// The service interface and the Handler methods both live here rather than in
// types.go and handler.go, so the only edits to those upstream files are the
// struct embed and the dispatch case.

// BENCOKeyDirService is the device key directory.
type BENCOKeyDirService interface {
	PublishKeys(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest) (wire.SNACMessage, error)
	QueryKeys(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest) (wire.SNACMessage, error)
	RevokeKey(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0xBE00_0x0006_BENCOKeyDirRevokeRequest) (wire.SNACMessage, error)
	RestoreKey(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0xBE00_0x0008_BENCOKeyDirRestoreRequest) (wire.SNACMessage, error)
}

func (rt Handler) BENCOKeyDirPublishRequest(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	// The session supplies the screen name; the request has no field for one.
	// See BENCOKeyDirService.PublishKeys.
	outSNAC, err := rt.PublishKeys(ctx, instance.Session(), inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) BENCOKeyDirQueryRequest(ctx context.Context, _ *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.QueryKeys(ctx, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) BENCOKeyDirRevokeRequest(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0xBE00_0x0006_BENCOKeyDirRevokeRequest{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.RevokeKey(ctx, instance.Session(), inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) BENCOKeyDirRestoreRequest(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0xBE00_0x0008_BENCOKeyDirRestoreRequest{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.RestoreKey(ctx, instance.Session(), inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}
