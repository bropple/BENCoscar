package wire

// BENCO addition: the device key directory foodgroup.
//
// This is the first genuinely new protocol in the fork. It exists because
// BENCchat previously published its end-to-end encryption keys by hiding them in
// an HTML comment inside the Locate profile text, which caused four separate
// problems that all reduce to "the profile is the wrong place for this":
//
//  1. Keys could only be fetched for a user who was ONLINE, because Locate
//     answers a user-info query out of the live session.
//  2. A client could not discover its OWN other devices, because the self-lookup
//     path takes a branch where a session always exists.
//  3. "Remove device" was not durable: the removed machine keeps its keypair and
//     silently republished itself on next sign-on, with no server-side authority
//     to say otherwise.
//  4. The profile is a user-editable field with a FLAP frame-size ceiling, so
//     key material shared space with text the user could clobber.
//
// Everything here lives in its own file, and the foodgroup and subgroup name
// maps are extended from init() rather than by editing snacs_string.go, so the
// upstream diff stays additive (see CLAUDE.md).

// BENCOKeyDir is the device key directory foodgroup.
//
// The value is deliberately far above anything AOL ever assigned, so upstream
// adding a foodgroup can never collide with it. That has one consequence worth
// knowing: session foodgroup-version state is a FIXED ARRAY bounded by wire.MDir
// (0x0025), and OServiceService.ClientVersions rejects anything outside it. So
// this foodgroup deliberately does NOT participate in that negotiation — a
// client must not list it in OServiceClientVersions. Support is advertised the
// other way, through the OServiceHostOnline foodgroup list, which is an
// unbounded slice, and the payloads carry their own Version field.
//
// The alternative was widening a per-session array to 48KB or converting it to a
// map across nine call sites in upstream files. Neither is worth it to avoid a
// version field we want anyway.
const BENCOKeyDir uint16 = 0xBE00

// BENCOKeyDir subgroups.
const (
	BENCOKeyDirErr            uint16 = 0x0001
	BENCOKeyDirPublishRequest uint16 = 0x0002
	BENCOKeyDirPublishReply   uint16 = 0x0003
	BENCOKeyDirQueryRequest   uint16 = 0x0004
	BENCOKeyDirQueryReply     uint16 = 0x0005
	BENCOKeyDirRevokeRequest  uint16 = 0x0006
	BENCOKeyDirRevokeReply    uint16 = 0x0007
	BENCOKeyDirRestoreRequest uint16 = 0x0008
	BENCOKeyDirRestoreReply   uint16 = 0x0009
)

// BENCOKeyDirVersion is the current payload version, carried in every request so
// the format can change without relying on foodgroup version negotiation.
const BENCOKeyDirVersion uint16 = 1

// Key lengths. Both are fixed-size public keys, but they are length-prefixed on
// the wire rather than raw so a future algorithm change does not require a new
// SNAC layout. The server validates the lengths.
const (
	BENCOKeyDirBoxKeyLen  = 32 // X25519 public key
	BENCOKeyDirSignKeyLen = 32 // Ed25519 public key
)

// BENCODevice is one machine belonging to an account.
//
// BoxKey is the device's identity: it is the X25519 public key messages are
// sealed to, and it is what the directory is keyed on. SignKey is the Ed25519
// key used to attribute chat-room messages to a sender, and may be empty for a
// client that has not generated one.
type BENCODevice struct {
	BoxKey  []byte `oscar:"len_prefix=uint16"`
	SignKey []byte `oscar:"len_prefix=uint16"`
}

// SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest publishes the sending account's
// devices. It replaces the published set for that account rather than merging,
// so a client sends its complete list every time.
//
// A client may only publish for itself; the server takes the screen name from
// the session and there is no field for it here.
type SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest struct {
	Version uint16
	Devices []BENCODevice `oscar:"count_prefix=uint16"`
}

// SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply reports what was stored.
//
// Refused carries any device the server declined, which happens when a key has
// been revoked. The client is expected to surface those to the user through the
// existing device-approval flow rather than retrying: a revoked key reappearing
// means a machine you removed has come back, which is a question for a human.
type SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply struct {
	Accepted uint16
	Refused  []BENCODevice `oscar:"count_prefix=uint16"`
}

// SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest asks for an account's devices.
//
// Unlike the Locate profile it replaces, this is answered from storage, so it
// works for a user who is offline and for the caller's own screen name.
type SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest struct {
	Version    uint16
	ScreenName string `oscar:"len_prefix=uint8"`
}

// SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply carries the account's active devices.
// Revoked devices are never included.
//
// An account that exists but has published nothing returns an empty list rather
// than an error, because "this user runs a client that does not do encryption"
// is a normal answer, not a failure.
type SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply struct {
	ScreenName string        `oscar:"len_prefix=uint8"`
	Devices    []BENCODevice `oscar:"count_prefix=uint16"`
}

// SNAC_0xBE00_0x0006_BENCOKeyDirRevokeRequest removes one of the sending
// account's own devices.
//
// Revocation leaves a tombstone rather than deleting the row. That is the whole
// point: the removed machine keeps its keypair and will republish on its next
// sign-on, so without a record that the key was revoked it simply comes back and
// "remove device" means nothing.
type SNAC_0xBE00_0x0006_BENCOKeyDirRevokeRequest struct {
	Version uint16
	BoxKey  []byte `oscar:"len_prefix=uint16"`
}

// SNAC_0xBE00_0x0007_BENCOKeyDirRevokeReply reports whether a device was
// revoked. Revoked is 0 when the key was not published by this account, which is
// not an error — revoking something already gone is a no-op, not a failure.
type SNAC_0xBE00_0x0007_BENCOKeyDirRevokeReply struct {
	Revoked uint8
}

// SNAC_0xBE00_0x0008_BENCOKeyDirRestoreRequest lifts a revocation, letting a
// previously removed device publish again.
//
// This is the other half of Revoke, and the design is incomplete without it. A
// tombstone that can never be lifted turns "remove this device" into "destroy
// this device", because the machine keeps its keypair, republishes on every
// sign-on, and is refused forever with no way out. Reinstalling a laptop is a
// normal thing to do; it must not require deleting the account.
//
// Restricted to the account's own devices, like publish and revoke: the screen
// name comes from the session and there is no field for one.
type SNAC_0xBE00_0x0008_BENCOKeyDirRestoreRequest struct {
	Version uint16
	BoxKey  []byte `oscar:"len_prefix=uint16"`
}

// SNAC_0xBE00_0x0009_BENCOKeyDirRestoreReply reports whether a revocation was
// lifted. Zero means there was no tombstone for that key, which is not an error.
type SNAC_0xBE00_0x0009_BENCOKeyDirRestoreReply struct {
	Restored uint8
}

// WithBENCOKeyDirRateLimits returns limits with this foodgroup's classes added.
//
// A wrapper rather than an edit to DefaultSNACRateLimits so the upstream file
// stays untouched. Registering these matters beyond throttling: RateParamsQuery
// builds its reply by iterating every registered pair, and the comment on that
// function warns that clients silently fail when they expect a rate rule that
// the server does not send.
//
// Class 1 is the most permissive. Key directory traffic is a handful of SNACs
// per sign-on, not a message stream.
func WithBENCOKeyDirRateLimits(limits SNACRateLimits) SNACRateLimits {
	limits.lookup[BENCOKeyDir] = map[uint16]RateLimitClassID{
		BENCOKeyDirErr:            1,
		BENCOKeyDirPublishRequest: 1,
		BENCOKeyDirPublishReply:   1,
		BENCOKeyDirQueryRequest:   1,
		BENCOKeyDirQueryReply:     1,
		BENCOKeyDirRevokeRequest:  1,
		BENCOKeyDirRevokeReply:    1,
		BENCOKeyDirRestoreRequest: 1,
		BENCOKeyDirRestoreReply:   1,
	}
	return limits
}

// Extend the logging name maps from here rather than editing snacs_string.go.
func init() {
	foodGroupName[BENCOKeyDir] = "BENCOKeyDir"
	subGroupName[BENCOKeyDir] = map[uint16]string{
		BENCOKeyDirErr:            "BENCOKeyDirErr",
		BENCOKeyDirPublishRequest: "BENCOKeyDirPublishRequest",
		BENCOKeyDirPublishReply:   "BENCOKeyDirPublishReply",
		BENCOKeyDirQueryRequest:   "BENCOKeyDirQueryRequest",
		BENCOKeyDirQueryReply:     "BENCOKeyDirQueryReply",
		BENCOKeyDirRevokeRequest:  "BENCOKeyDirRevokeRequest",
		BENCOKeyDirRevokeReply:    "BENCOKeyDirRevokeReply",
		BENCOKeyDirRestoreRequest: "BENCOKeyDirRestoreRequest",
		BENCOKeyDirRestoreReply:   "BENCOKeyDirRestoreReply",
	}
}
