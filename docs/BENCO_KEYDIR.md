# Device key directory (BENCO)

A BENCO fork addition: foodgroup **`0xBE00`**, a directory of published
end-to-end encryption keys. It is the first genuinely new protocol in the fork.

Payload version **2**. Version 1 was deleted rather than deprecated — see
[Version 2](#version-2-the-client-is-the-authority) for what changed and
[Migration](#migration-from-v1) for why deleting it was acceptable.

## What it replaces, and why

BENCchat used to publish its device keys by hiding them in an HTML comment inside
the **Locate profile text**:

```
<!--BENCO-E2EE:v3:boxkey|signkey,boxkey|signkey-->
```

That worked with no server change at all, which is why it was done — but putting
key material in a profile caused four separate problems that all reduce to *the
profile is the wrong place for this*:

| Problem | Cause |
|---|---|
| Keys readable only for **online** users | Locate answers a user-info query out of the live session |
| A client could not see its **own other devices** | self-lookup takes a branch where a session always exists |
| **"Remove device" did not stick** | the removed machine keeps its keypair and republishes on next sign-on |
| Key material shared space with **user-editable text** | the profile is a free-form field, with a FLAP frame-size ceiling |

The directory fixes all four. The first two fall out of reading storage instead
of a session. The fourth is just having a table. The third is the interesting
one, and it is what version 2 changes the answer to.

## Version 2: the client is the authority

v1 stored a bare list of device keys and made the **server** the authority over
which devices an account has, with removal implemented as a server-side
tombstone. It fixed all four problems above and it worked — but it left a gap no
client could close. The server could insert a device, omit one, or serve an older
list, and every one of those looked identical to the truth from outside.

v2 replaces the list with a **manifest**: the whole device set as one statement,
signed by an account identity key the server never holds.

Signing each device individually would not have been enough:

| Attack | Per-device signatures | Signed manifest |
|---|---|---|
| Insert a device | blocked | blocked |
| **Omit** a device | undetectable | blocked — the list is signed as a whole |
| Serve an **older** list | undetectable | blocked — the counter must not go backwards |
| Undo a removal | needs tombstones | blocked — removal *is* a higher counter |

### Removal stops being a server operation

There is no Revoke or Restore in v2, and no tombstone table behind them.
**Removing a device means publishing a manifest without it at `counter + 1`.**
Clients remember the highest counter seen per peer and refuse anything lower, so
a rolled-back or hostile server cannot resurrect a removed machine.

That is strictly stronger than a tombstone, because it does not require trusting
the server to honour it.

### The manifest travels as opaque bytes

**The single most important implementation constraint.** The server stores and
returns byte-for-byte what the client sent. It never decodes and re-encodes a
manifest. The detached signature covers those exact bytes, so any encoding
difference — a field order, a length-prefix width, a re-serialised string —
invalidates the signature for every client that fetches it afterwards, and the
failure surfaces as a signature mismatch on a *peer's* client, a long way from
the server that caused it.

The server does decode a manifest to *check* it, then throws the decoded struct
away.

### The server verifies signatures, and that is not a security boundary

Before storing, the server checks the signature against the identity key inside
the manifest. This is a cheap filter that keeps unverifiable garbage out of the
table — it is **not** something a client may rely on. A server that wanted to
serve a forged manifest would simply not run the check, so its having run tells a
client nothing.

**Clients must verify independently**, against an identity key from their own
trust store. That verification is the one that decides anything.

### Counter and identity

The counter is scoped to the identity, not global:

- **Same identity key as stored** — the counter must be **strictly greater**.
  This is the rollback defence.
- **Different identity key** — a legitimate identity replacement. Accepted, and
  the counter **resets** to whatever the new manifest carries. A new identity
  starts at 1, and refusing that would mean an account that bootstrapped a fresh
  identity could never publish until it counted past its own history.

**The server does not adjudicate an identity change, and could not.** It is
either the account holder who lost everything and bootstrapped again, or someone
with the password who cleared the identity and installed their own — and those
two are cryptographically indistinguishable by construction. That is not a gap;
it is the property the design is for. An operator can *destroy* or *replace* an
identity but cannot silently *become* someone, because every contact sees the
safety number move.

Deciding what to do about it is the client's job, and the client's answer is to
tell a human and let them ask out of band.

### The identity backup

The identity private key signs manifests and is held only **transiently** by a
client — fetched, used, discarded — so linking a device costs the user their
recovery phrase every time. That is deliberate: a stolen laptop should yield that
device's key and nothing more.

Between uses it lives on the server, encrypted under a key derived from a
generated ~110-bit recovery phrase the server never sees and cannot derive. The
KDF identifier, parameters and salt travel with the blob so the work factor can
be raised later without stranding existing backups.

`GetBackup` reporting `Present = 0` is what tells a client it is in first-run: an
account nobody has used is exactly an account with no backup, so no server-side
"has this account signed in" flag is needed.

## The protocol

| Subgroup | Name | Who |
|---|---|---|
| `0x0002` / `0x0003` | Publish request / reply | own account only |
| `0x0004` / `0x0005` | Query request / reply | any signed-in user |
| `0x0006` / `0x0007` | PutBackup request / reply | own account only |
| `0x0008` / `0x0009` | GetBackup request / reply | own account only |
| `0x0001` | Error | — |

**Publish** carries the manifest as opaque bytes plus a detached signature. The
reply reports whether it was stored and **the counter the server now holds**, so
a client that lost a race learns what it needs to beat without re-querying.

**Query** is answered from storage, so it works for an offline user and for the
caller's own screen name. An account that has published nothing returns
`Present = 0`, not an error: it has simply not bootstrapped an identity yet.

**The screen name always comes from the session**, never from a request. Publish
has no field for one, and the screen name **inside** the signed manifest is
checked against the session rather than trusted — without that check a manifest
is a portable signed object, and one lifted from another account would verify
perfectly on a session you control.

**GetBackup has no screen name field either, and that is a real boundary.** The
blob is encrypted, but once someone holds it they can attack it offline with no
rate limiting, so serving one account's backup to another would reduce a takeover
to a dictionary attack run at leisure.

### Algorithm identifiers

Every key and signature carries one, so a post-quantum migration is a version
bump rather than a flag day.

| Alg | Meaning | Status |
|---|---|---|
| `0x01` | X25519 | key agreement |
| `0x02` | Ed25519 | signatures |
| `0x03` | ML-KEM-768 | **reserved**, not implemented |
| `0x04` | ML-DSA-65 | **reserved**, not implemented |

Reserved values are refused on arrival. Storing a signature the server cannot
verify, under the pretence of having verified it, is worse than refusing it.

## What the server still cannot do

Worth restating, because a protocol carrying signatures is easy to misread as
making the server trustworthy:

- **It cannot tell which device is talking to it.** A session authenticates with
  an account password, so every server-side check is advisory. The signatures are
  what actually bind anything.
- **It can still refuse service, drop a publish, or serve an old manifest.**
  Signatures prove authenticity, not availability or freshness. A hostile server
  can serve a correctly-signed, correctly-countered, very old manifest
  indefinitely; the only signal is `IssuedAt` looking stale, which is advisory
  and must never by itself cause a client to reject.
- **It sees all the metadata** — who queries whom, how many devices exist, and
  their labels when set.
- **It cannot read a message or open a backup.** Only public keys and ciphertext
  are stored.

## Counter vs. timestamp

`Counter` and `IssuedAt` do different jobs and **only one is authoritative**.

`Counter` orders manifests and is the rollback defence. It is the only field a
client may use to reject a manifest as stale.

`IssuedAt` is **advisory**: it bounds how old a served manifest can plausibly be
and gives a UI something to show, but a client must **never** reject on timestamp
alone. A wrong clock on either side is far more likely than an attack, and
hard-rejecting on time would brick a conversation over a dead CMOS battery.
Always UTC seconds; never local time, never a formatted string.

## Migration from v1

**v1 was deleted, not deprecated.** Migration `0036` drops the `deviceKeys`
table outright.

This was acceptable for one reason that will not be true again: no account
outside the owner's own test accounts had ever published a key, and there is a
script to wipe the database (`scripts/benco-deploy/reset-db.sh`). There was no
user data to migrate, so carrying both formats through a flag day would have been
more risk than the cutover it avoided. **Do not read it as a pattern to copy.**

Nothing was lost that cannot be regenerated — every device still holds its own
keypair. What went is the revocation tombstones, which v2 has no use for.

v2's subgroups restart at `0x0002` rather than continuing past v1's range, since
nothing on the wire can still be using the old assignments.

One consequence for clients: publishing a v2 manifest requires an identity key,
which requires a recovery phrase to exist. So recovery-phrase generation has to
happen at first v2 sign-on, before anything can be published.

## The foodgroup ID, and why it is not negotiated

`0xBE00` sits far above anything AOL ever assigned, so upstream adding a
foodgroup can never collide with it.

That has one consequence. Session foodgroup-version state is a **fixed array**
bounded by `wire.MDir` (0x0025) — `foodGroupVersions [wire.MDir + 1]uint16` in
`state/session.go` — and `OServiceService.ClientVersions` rejects anything
outside it. So this foodgroup **deliberately does not take part in version
negotiation**, and a client must not list it in `OServiceClientVersions`.

Support is advertised the other way, through the **`OServiceHostOnline`
foodgroup list**, which is an unbounded slice, and the payloads carry their own
`Version` field.

The alternative was widening a per-session array to 48KB, or converting it to a
map across nine call sites in upstream files — neither worth it to avoid a
version field we want anyway.

Nothing branches on `Version` today, since v2 is the only format the server
speaks; a request carrying anything else is refused. The field remains because it
is how the *next* format change gets signalled, and retrofitting one is the
awkward part.

## Where the code lives

Almost everything is in new files, so it rebases cheaply:

| Concern | File |
|---|---|
| Wire format, constants, rate limits, name registration | `wire/benco_keydir.go` |
| Service | `foodgroup/benco_keydir.go` |
| Routing and service interface | `server/oscar/benco_keydir.go` |
| Storage | `state/key_directory.go` |
| Schema | `state/migrations/0036_key_directory.{up,down}.sql` |

Upstream files carry only hooks: the `Handler` struct embed and dispatch case
(`server/oscar/handler.go`), the `HostOnline` list entry
(`foodgroup/oservice.go`), and construction in `cmd/server/factory.go`. The
foodgroup and subgroup logging-name maps are extended from an `init()` rather
than by editing `snacs_string.go`, and the rate-limit classes via a wrapper
rather than by editing `DefaultSNACRateLimits`.

## Verified

Unit tests cover the byte layout (pinned, not merely round-tripped, since it is
now a *signature* compatibility surface and not only a client one), that manifest
bytes survive publish and query unchanged and still verify afterwards, that a bad
signature is refused, that a stale counter is refused while an identity change
resets it, that a manifest naming another account is refused, and that backups
round-trip and stay scoped to their own account.

The end-to-end live verification described for v1 predates this change and needs
re-running against v2.
