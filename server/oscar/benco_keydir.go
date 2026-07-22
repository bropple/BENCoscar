package oscar

import (
	"context"
	"errors"
	"github.com/mk6i/open-oscar-server/foodgroup"
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
	// Device attestation. A password proves the ACCOUNT; these prove which
	// DEVICE of it is talking, which is what makes removing a device mean
	// anything. See foodgroup/benco_deviceauth.go.
	Challenge(ctx context.Context, mode foodgroup.DeviceAuthMode, screenName state.IdentScreenName) (wire.SNACMessage, []byte, bool)
	AttestResponse(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0xBE00_0x000B_BENCOKeyDirAttestResponse) (wire.SNACMessage, error)
}

// BENCOKeyDirAttestResponse handles a session's answer to a device challenge.
func (rt Handler) BENCOKeyDirAttestResponse(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) error {
	inBody := wire.SNAC_0xBE00_0x000B_BENCOKeyDirAttestResponse{}
	if err := wire.UnmarshalBE(&inBody, r); err != nil {
		return err
	}
	outSNAC, err := rt.BENCOKeyDirService.AttestResponse(ctx, instance, inFrame, inBody)
	if err != nil {
		return err
	}
	rt.LogRequestAndResponse(ctx, inFrame, inBody, outSNAC.Frame, outSNAC.Body)

	if err := rw.SendSNAC(outSNAC.Frame, outSNAC.Body); err != nil {
		return err
	}

	// Enforcement happens here rather than inside the service, because closing a
	// connection is the server loop's business and refusing to answer is not the
	// same as refusing to serve.
	if !instance.Attested() {
		switch rt.DeviceAuthMode {
		case foodgroup.DeviceAuthEnforce:
			rt.Logger.WarnContext(ctx, "closing a session that could not prove its device",
				"screen_name", instance.IdentScreenName().String())
			return errors.New("device attestation failed")
		case foodgroup.DeviceAuthLog:
			rt.Logger.WarnContext(ctx, "session could not prove its device (log mode, admitted anyway)",
				"screen_name", instance.IdentScreenName().String())
		}
	}
	return nil
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
