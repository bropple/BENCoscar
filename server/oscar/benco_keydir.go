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
//
// Nothing here branches on the payload Version field. v2 is the only format the
// server speaks — v1 was deleted rather than deprecated — so a request carrying
// another version is rejected by the service rather than routed somewhere else.
// The field is still on the wire because it is how a future format change would
// be signalled; see wire/benco_keydir.go.

// BENCOKeyDirService is the device key directory.
type BENCOKeyDirService interface {
	PublishManifest(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest) (wire.SNACMessage, error)
	QueryManifest(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest) (wire.SNACMessage, error)
	PutBackup(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest) (wire.SNACMessage, error)
	GetBackup(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0xBE00_0x0008_BENCOKeyDirGetBackupRequest) (wire.SNACMessage, error)
}

func (rt Handler) BENCOKeyDirPublishRequest(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	// The session supplies the screen name, and the one inside the signed
	// manifest is checked against it. See BENCOKeyDirService.PublishManifest.
	outSNAC, err := rt.PublishManifest(ctx, instance.Session(), inFrame, inBody)
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
	outSNAC, err := rt.QueryManifest(ctx, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) BENCOKeyDirPutBackupRequest(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.PutBackup(ctx, instance.Session(), inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}

func (rt Handler) BENCOKeyDirGetBackupRequest(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0xBE00_0x0008_BENCOKeyDirGetBackupRequest{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	// The account's own backup, always. The request has no screen name field
	// because handing one account's backup to another would be an offline
	// attack handed over on request.
	outSNAC, err := rt.GetBackup(ctx, instance.Session(), inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)
	return rw.SendSNAC(outSNAC.Frame, outSNAC.Body)
}
