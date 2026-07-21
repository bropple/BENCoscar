package foodgroup

// BENCO delta: consensual buddy connections for AIM-style accounts.
//
// Upstream open-oscar-server implements a full authorization flow for ICQ, but
// AIM↔AIM buddy adds are silent and unilateral — adding someone gives you their
// presence (and, via the ICBM path, the ability to message them) with no
// consent from the target. This file, together with small commented hooks in
// feedbag.go (UpsertItem / RespondAuthorizeToHost) and icbm.go
// (ChannelMsgToHost), extends the existing ICQ authorization machinery to AIM so
// that an AIM connection is consensual: presence AND messaging are both gated by
// the SAME authorization grant. See docs/BENCO_AIM_AUTH.md.
//
// Everything the flow needs already exists in the store — RequiresAuthorization
// consults users.icq_permissions_authRequired (defaulted to true for every
// account by migration 0028) and the contactPreauth table. AIM accounts
// therefore already "require authorization" at the store level; upstream simply
// never checked it on the aim→aim path. Grandfathering of relationships that
// predate this change is handled one-time by migration 0037.

import (
	"context"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// sendAIMAuthReq notifies target (a modern feedbag client) that `from` wants to
// add them and needs their authorization. It relays SNAC(0x13,0x19)
// FeedbagRequestAuthorizeToClient — the same notification the ICQ→feedbag path
// uses (see RequestAuthorizeToHost's feedbag branch and ForwardICQAuthEvents),
// which is the delivery that reaches a modern BENCchat client. If the target is
// offline the relay is a no-op; the requester's row stays pending and the
// target can act on it once the add is retried while they are online.
func (s *FeedbagService) sendAIMAuthReq(ctx context.Context, from *state.SessionInstance, target state.IdentScreenName) {
	s.messageRelayer.RelayToScreenName(ctx, target, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagRequestAuthorizeToClient,
			Flags:     wire.SNACFlagsExtendedInfo,
		},
		Body: wire.SNAC_0x13_0x19_FeedbagRequestAuthorizeToClient{
			TLVLBlock: wire.TLVLBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.FeedbagTLVVersion, uint16(2)),
				},
			},
			ScreenName: from.IdentScreenName().String(),
		},
	})
}

// sendAIMConnectionRemoved tells a removed buddy that `from` has disconnected
// from them, so their client can drop `from` silently. OSCAR has no native
// "you were removed" push, so it rides the authorization-response channel as a
// revocation: SNAC(0x13,0x1B) FeedbagRespondAuthorizeToClient with Accepted=0.
// A BENCchat client already removes the named buddy on a 0x1B decline, so a
// removal and a declined request converge on the same handling. Offline is a
// no-op; the relationship is already severed server-side, and the stale row on
// the buddy's list surfaces the next time they try to reach `from` (the gate
// rejects it).
func (s *FeedbagService) sendAIMConnectionRemoved(ctx context.Context, from, target state.IdentScreenName) {
	s.messageRelayer.RelayToScreenName(ctx, target, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagRespondAuthorizeToClient,
			Flags:     wire.SNACFlagsExtendedInfo,
		},
		Body: wire.SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient{
			TLVLBlock: wire.TLVLBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.FeedbagTLVVersion, uint16(2)),
				},
			},
			ScreenName: from.String(),
			Accepted:   0,
		},
	})
}
