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
//
// # Version 2: the client is the authority, not the server
//
// v1 stored a bare list of device keys and let the server arbitrate it, with
// revocation implemented as a server-side tombstone. That worked, and it fixed
// all four problems above, but it left the server as the authority over who your
// devices are — it could insert one, drop one, or serve a stale list, and no
// client could tell.
//
// v2 replaces the list with a MANIFEST: the whole device set, signed as one
// statement by an account identity key the server never holds. Per-device
// signatures would not have been enough. They stop a forged device, but not an
// OMITTED one and not an older list replayed, because each individual signature
// still verifies. Signing the list as a whole, with a monotonic counter, closes
// all three at once.
//
// Revocation therefore stops being a protocol operation. Removing a device means
// publishing a manifest without it at counter+1, and a client that remembers the
// highest counter it has seen will refuse the older manifest that still contains
// it. There is no Revoke or Restore subgroup in v2 and no tombstone table behind
// one — the counter does that job, and does it without trusting the server.
//
// v1 was deleted outright rather than served alongside. No account outside
// testing had published keys, so there was no migration to survive; see
// state/migrations/0036_key_directory.up.sql, which drops the v1 table.

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
//
// These are v2's numbers, and they start again at 0x0002 rather than continuing
// past v1's range. v1 and its subgroups were deleted rather than deprecated, so
// nothing on the wire can still be using the old assignments and leaving a hole
// would only invite someone to wonder what used to be in it.
const (
	BENCOKeyDirErr              uint16 = 0x0001
	BENCOKeyDirPublishRequest   uint16 = 0x0002
	BENCOKeyDirPublishReply     uint16 = 0x0003
	BENCOKeyDirQueryRequest     uint16 = 0x0004
	BENCOKeyDirQueryReply       uint16 = 0x0005
	BENCOKeyDirPutBackupRequest uint16 = 0x0006
	BENCOKeyDirPutBackupReply   uint16 = 0x0007
	BENCOKeyDirGetBackupRequest uint16 = 0x0008
	BENCOKeyDirGetBackupReply   uint16 = 0x0009
)

// BENCOKeyDirVersion is the current payload version, carried in every request so
// the format can change without relying on foodgroup version negotiation.
//
// Nothing branches on it today — v1 is gone and v2 is the only format the server
// speaks, so a request carrying anything else is rejected rather than routed.
// The field is kept because it is how the NEXT format change gets signalled, and
// adding a version field to a protocol that shipped without one is the awkward
// part; keeping it costs two bytes.
const BENCOKeyDirVersion uint16 = 2

// Key algorithm identifiers.
//
// Every key and signature on the wire carries one. That is what makes a
// post-quantum migration a version bump rather than a flag day: a client can
// publish an ML-DSA identity alongside an Ed25519 one without renegotiating the
// SNAC layout, because the layout never encoded the algorithm in the first place.
//
// The ML-* values are RESERVED and not implemented. They are assigned now purely
// so that implementing them later does not require agreeing on a number.
const (
	BENCOAlgX25519   uint8 = 0x01 // message key agreement
	BENCOAlgEd25519  uint8 = 0x02 // signatures
	BENCOAlgMLKEM768 uint8 = 0x03 // reserved — post-quantum key agreement
	BENCOAlgMLDSA65  uint8 = 0x04 // reserved — post-quantum signatures
)

// Key lengths for the algorithms that are actually implemented.
//
// The reserved algorithms deliberately have no length constant. The server has
// no way to check a key it cannot use, and inventing a constant for a scheme
// nothing here implements would be a claim about a format that has not been
// committed to yet.
const (
	BENCOX25519KeyLen  = 32
	BENCOEd25519KeyLen = 32
	BENCOEd25519SigLen = 64
)

// BENCOKeyDirMaxManifestLen bounds a stored manifest.
//
// A manifest is at most MaxDevicesPerAccount devices, each two keys and a label
// of up to 255 bytes, so the realistic worst case is around 10KB. The cap is set
// above that rather than at it, because the manifest is opaque to the server and
// a limit that a legitimate client can hit is a limit that turns into a support
// question. What it is actually defending against is a client storing megabytes
// of unrelated data in a field the server will hand back on request.
const BENCOKeyDirMaxManifestLen = 16384

// BENCOKey is a public key plus the algorithm it belongs to.
//
// The key is length-prefixed rather than fixed-size for the same reason the
// algorithm is explicit: an ML-KEM encapsulation key is 1184 bytes and an
// Ed25519 key is 32, and a layout that assumed either would have to change to
// carry the other.
type BENCOKey struct {
	Alg uint8
	Key []byte `oscar:"len_prefix=uint16"`
}

// BENCODevice is one machine belonging to an account.
//
// Box is the X25519 public key messages are sealed to, and is the device's
// identity. Sign is the Ed25519 key that attributes chat-room messages to a
// sender.
//
// Label is a human name for the machine ("desktop", "thinkpad") so a device list
// stops being a wall of fingerprints. It is optional and may be empty. The
// tradeoff is deliberate and worth stating: it is metadata the server can read,
// and it tells anyone holding the account password what hardware exists. It sits
// inside the signed manifest so the server cannot FORGE it, but nothing hides it
// from the server, so clients should ship it empty and let the user opt in.
type BENCODevice struct {
	Box   BENCOKey
	Sign  BENCOKey
	Label string `oscar:"len_prefix=uint8"`
}

// BENCOManifest is the signed statement of who an account's devices are.
//
// This type exists so the server can INSPECT a manifest — check the screen name
// binds, read the counter, find the identity key to verify against. It is not
// how a manifest is stored or served. The bytes a client signed are stored and
// returned verbatim, because re-encoding them through this struct would break
// every signature the moment the encoder's output differed by a byte. See
// SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest.Manifest.
//
// ScreenName is inside the signature deliberately. Without it, a manifest lifted
// from one account could be replayed onto another and would still verify.
//
// Counter and IssuedAt do different jobs and only one of them is authoritative.
// Counter orders manifests and is the rollback defence — it is the only field
// that may be used to reject a manifest as stale, and it is monotonic WITHIN an
// identity (see the storage layer for what happens when the identity changes).
// IssuedAt is advisory: it bounds how old a served manifest can plausibly be and
// gives a UI something to show, but a client must never reject a manifest on
// timestamp alone. A wrong clock on either side is far more likely than an
// attack, and hard-rejecting on time would brick a conversation over a dead CMOS
// battery. Always UTC seconds, never local time, never a formatted string.
type BENCOManifest struct {
	Version    uint16
	ScreenName string `oscar:"len_prefix=uint8"`
	Counter    uint64
	IssuedAt   uint64
	Identity   BENCOKey
	Devices    []BENCODevice `oscar:"count_prefix=uint16"`
}

// SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest publishes the sending account's
// signed device manifest, replacing whatever was stored.
//
// Manifest is an encoded BENCOManifest and is treated as OPAQUE BYTES by
// everything that is not verifying it. The server stores and returns exactly
// these bytes. This is the single most important constraint in the protocol: a
// server that decoded and re-encoded a manifest would invalidate the detached
// signature for every client that fetched it afterwards, and the failure would
// look like a signature bug on the client rather than a server one.
//
// Signature is detached and covers Manifest exactly as sent, made by the private
// half of the Identity key inside it. That the identity vouches for itself is
// not circular — it proves the manifest was issued by whoever holds that
// identity, and whether the client should TRUST that identity is a separate
// question answered by the client's own trust store, not by the server.
//
// A client may only publish for itself. The server takes the screen name from
// the session and compares it against the one inside the manifest; there is
// deliberately no field for it out here, where it would not be signed.
type SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest struct {
	Version   uint16
	Manifest  []byte `oscar:"len_prefix=uint16"`
	SigAlg    uint8
	Signature []byte `oscar:"len_prefix=uint16"`
}

// SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply reports what the server now holds.
//
// Counter is the stored counter after the call, which is what makes a lost race
// detectable: a client whose publish was rejected as stale learns the value it
// needs to beat rather than having to re-query to find out.
type SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply struct {
	Accepted uint8 // 1 = stored
	Counter  uint64
}

// SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest asks for an account's manifest.
//
// Unlike the Locate profile this replaced, it is answered from storage, so it
// works for a user who is offline and for the caller's own screen name.
type SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest struct {
	Version    uint16
	ScreenName string `oscar:"len_prefix=uint8"`
}

// SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply carries an account's signed manifest.
//
// Present is 0 for an account that has published nothing, which is a normal
// answer rather than an error: "this user has not bootstrapped an identity" is a
// state a client has to handle anyway, and making it an error would mean
// clients treating a routine condition as a failure.
//
// Manifest is byte-for-byte what was published. See the publish request.
type SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply struct {
	ScreenName string `oscar:"len_prefix=uint8"`
	Present    uint8
	Manifest   []byte `oscar:"len_prefix=uint16"`
	SigAlg     uint8
	Signature  []byte `oscar:"len_prefix=uint16"`
}

// SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest stores the account's encrypted
// identity key.
//
// The identity private key is needed to sign a manifest and is held only
// transiently by a client — fetched, used, discarded — so it has to live
// somewhere between uses. It lives here, encrypted under a key derived from a
// generated recovery phrase that the server never sees and cannot derive.
//
// Blob is that ciphertext. KDF, Params and Salt travel with it so the work
// factor can be raised later without stranding backups made under the old one;
// a server that hardcoded the parameters would have to migrate every existing
// blob to change them, which in practice means never changing them.
//
// Scoped to the sending account: the screen name comes from the session.
type SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest struct {
	Version uint16
	KDF     uint8  // 0x01 = argon2id
	Params  []byte `oscar:"len_prefix=uint16"` // time, memory, parallelism
	Salt    []byte `oscar:"len_prefix=uint16"`
	Blob    []byte `oscar:"len_prefix=uint16"` // secretbox(identity private key)
}

// BENCOKDFArgon2id is the only key derivation function defined for a backup.
//
// The server does not run it and could not check that a client did. It is
// carried so a client knows how to derive the unwrapping key, and validated only
// to the extent of refusing values that mean nothing.
const BENCOKDFArgon2id uint8 = 0x01

// BENCOKeyDirMaxBackupLen bounds each variable-length field of a backup.
//
// The real blob is a secretbox around a 32-byte private key, so tens of bytes.
// The cap exists because this is the one place the protocol lets a client store
// arbitrary bytes the server will hand back, and an unbounded one would make the
// key directory a free file host.
const BENCOKeyDirMaxBackupLen = 4096

// SNAC_0xBE00_0x0007_BENCOKeyDirPutBackupReply acknowledges a stored backup.
type SNAC_0xBE00_0x0007_BENCOKeyDirPutBackupReply struct {
	Stored uint8 // 1 = stored
}

// SNAC_0xBE00_0x0008_BENCOKeyDirGetBackupRequest fetches the SENDING account's
// encrypted identity key.
//
// There is no screen name field, and that is a security boundary rather than a
// convenience. The blob is encrypted, but it is attackable offline with no rate
// limiting once someone has it, so handing one account's backup to another would
// reduce an account takeover to a dictionary attack run at leisure. The session
// supplies the screen name and there is no way to ask for anybody else's.
type SNAC_0xBE00_0x0008_BENCOKeyDirGetBackupRequest struct {
	Version uint16
}

// SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply carries the encrypted identity
// key, if one has been stored.
//
// Present = 0 means the account has never bootstrapped an identity, and it is
// what tells a client which first-run flow it is in: no backup means generate an
// identity and show a recovery phrase, a backup means prompt for the phrase to
// link this device. No server-side "has this account signed in" flag is needed,
// because an unused account is exactly an account with no backup.
type SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply struct {
	Present uint8
	KDF     uint8
	Params  []byte `oscar:"len_prefix=uint16"`
	Salt    []byte `oscar:"len_prefix=uint16"`
	Blob    []byte `oscar:"len_prefix=uint16"`
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
		BENCOKeyDirErr:              1,
		BENCOKeyDirPublishRequest:   1,
		BENCOKeyDirPublishReply:     1,
		BENCOKeyDirQueryRequest:     1,
		BENCOKeyDirQueryReply:       1,
		BENCOKeyDirPutBackupRequest: 1,
		BENCOKeyDirPutBackupReply:   1,
		BENCOKeyDirGetBackupRequest: 1,
		BENCOKeyDirGetBackupReply:   1,
	}
	return limits
}

// Extend the logging name maps from here rather than editing snacs_string.go.
func init() {
	foodGroupName[BENCOKeyDir] = "BENCOKeyDir"
	subGroupName[BENCOKeyDir] = map[uint16]string{
		BENCOKeyDirErr:              "BENCOKeyDirErr",
		BENCOKeyDirPublishRequest:   "BENCOKeyDirPublishRequest",
		BENCOKeyDirPublishReply:     "BENCOKeyDirPublishReply",
		BENCOKeyDirQueryRequest:     "BENCOKeyDirQueryRequest",
		BENCOKeyDirQueryReply:       "BENCOKeyDirQueryReply",
		BENCOKeyDirPutBackupRequest: "BENCOKeyDirPutBackupRequest",
		BENCOKeyDirPutBackupReply:   "BENCOKeyDirPutBackupReply",
		BENCOKeyDirGetBackupRequest: "BENCOKeyDirGetBackupRequest",
		BENCOKeyDirGetBackupReply:   "BENCOKeyDirGetBackupReply",
	}
}

// Device attestation subgroups.
//
// A password proves an ACCOUNT. These prove a DEVICE: after sign-on the server
// sends a nonce, and the session must return it signed by a device signing key
// that appears in the account's current manifest. Until now every membership
// check in the key directory was advisory precisely because the server had no
// way to tell one device from another — a removed device that ignored the signal
// kept full access, because it authenticated with the same password as before.
const (
	BENCOKeyDirAttestChallenge uint16 = 0x000A
	BENCOKeyDirAttestResponse  uint16 = 0x000B
	BENCOKeyDirAttestReply     uint16 = 0x000C
)

// BENCOAttestNonceLen is the challenge size. Generous: the nonce only has to be
// unguessable for the life of one connection, and there is no reason to be tight
// about 32 bytes.
const BENCOAttestNonceLen = 32

// SNAC_0xBE00_0x000A_BENCOKeyDirAttestChallenge asks a session to prove which
// device it is.
type SNAC_0xBE00_0x000A_BENCOKeyDirAttestChallenge struct {
	Version uint8
	Nonce   []byte `oscar:"len_prefix=uint16"`
}

// SNAC_0xBE00_0x000B_BENCOKeyDirAttestResponse answers one.
//
// The signing key travels alongside the signature so the server can pick the
// right one out of the manifest instead of trying all of them; it is checked for
// membership regardless, so sending somebody else's buys nothing.
type SNAC_0xBE00_0x000B_BENCOKeyDirAttestResponse struct {
	Version   uint8
	SignKey   BENCOKey
	Signature []byte `oscar:"len_prefix=uint16"`
}

// SNAC_0xBE00_0x000C_BENCOKeyDirAttestReply reports the outcome.
type SNAC_0xBE00_0x000C_BENCOKeyDirAttestReply struct {
	Version uint8
	// Accepted is 1 when the session is now attested.
	Accepted uint8
}
