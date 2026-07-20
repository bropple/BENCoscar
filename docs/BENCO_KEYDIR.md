# Device key directory (BENCO)

A BENCO fork addition: foodgroup **`0xBE00`**, a directory of published
end-to-end encryption keys. It is the first genuinely new protocol in the fork.

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
one, and the only one that genuinely *needs* a server.

## Durable removal

Revoking a device does not delete its row — it sets `revokedAt`, leaving a
**tombstone**. Publishing then refuses any tombstoned key.

This matters because the removed machine still holds its keypair. Delete the row
and it silently republishes itself on next sign-on, with the *same* key, so peers
who already verified it see nothing new: no safety-number change, no prompt. That
is precisely the behaviour observed before this existed. Forgetting a device does
not make it come back as a *new* device; it makes it come back invisibly.

Making it return as genuinely new would require the device to regenerate its key,
which is the one thing device keys must not do — every regeneration spends a
contact's attention on a "key changed" warning, and doing that casually trains
people to click through the alert meant to catch an attacker.

So the server holds the tombstone. A refused key is **reported back** to the
client rather than silently dropped, so it can be surfaced through the existing
device-approval dialog: *a device you removed has come back — approve?* Removal
stays meaningful, and deliberately re-adding a reinstalled laptop is one click.

**Restore is not optional.** A tombstone that cannot be lifted does not mean
"removed", it means "destroyed": the machine keeps its keypair, republishes on
every sign-on, and is refused forever. Telling the user to "approve it from
another device" then leads nowhere, and the only escape is wiping every machine.
Reinstalling a laptop has to be recoverable, so approving a returned device lifts
the revocation before republishing.

**Limit worth stating plainly:** none of this defends against someone who has the
account password. They can sign in, revoke your devices and approve their own.
Device removal means "stop encrypting to a machine I no longer control"; it is
not an account-recovery mechanism.

## The protocol

| Subgroup | Name | Who |
|---|---|---|
| `0x0002` / `0x0003` | Publish request / reply | own account only |
| `0x0004` / `0x0005` | Query request / reply | any signed-in user |
| `0x0006` / `0x0007` | Revoke request / reply | own account only |
| `0x0008` / `0x0009` | Restore request / reply | own account only |
| `0x0001` | Error | — |

**Publish** replaces the account's device set; a client sends its complete list
every time. The reply reports how many were accepted and carries any that were
**refused** because they are revoked.

A device absent from a publish is removed but leaves **no tombstone** — that is
"this is no longer in my set", which is different from "I revoked this". Only the
latter needs to survive.

**Query** is answered from storage, so it works for an offline user and for the
caller's own screen name. An account that has published nothing returns an empty
list, not an error: "this user runs a client that does not do encryption" is a
normal answer.

**Publish and revoke take the screen name from the session**, never from the
request — there is deliberately no field for one. A client that could publish for
an arbitrary screen name could insert its own device into anyone's account and
read their messages, which would defeat the encryption this directory serves.

Only **public** keys are stored. The server cannot read any message this helps
encrypt, and nothing here would help it if it tried. What the server uniquely
provides is the authority that a revoked device stays revoked.

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
`Version` field. A client that does not see `0xBE00` in that list must fall back
to the profile-marker scheme.

The alternative was widening a per-session array to 48KB, or converting it to a
map across nine call sites in upstream files — neither worth it to avoid a
version field we want anyway.

## Where the code lives

Almost everything is in new files, so it rebases cheaply:

| Concern | File |
|---|---|
| Wire format, constants, rate limits, name registration | `wire/benco_keydir.go` |
| Service | `foodgroup/benco_keydir.go` |
| Routing and service interface | `server/oscar/benco_keydir.go` |
| Storage | `state/device_keys.go` |
| Schema | `state/migrations/0035_device_keys.{up,down}.sql` |

Upstream files carry only hooks: the `Handler` struct embed and dispatch case
(`server/oscar/handler.go`), the `HostOnline` list entry
(`foodgroup/oservice.go`), and construction in `cmd/server/factory.go`. The
foodgroup and subgroup logging-name maps are extended from an `init()` rather
than by editing `snacs_string.go`, and the rate-limit classes via a wrapper
rather than by editing `DefaultSNACRateLimits`.

## Verified

Unit tests cover the byte layout (pinned, not merely round-tripped), the store's
tombstone behaviour, and that publish and revoke use the session's screen name.

Driven end to end against a real server: the foodgroup is advertised in
`HostOnline`; an account published two devices and read **its own** back; a
second account published a device, disconnected, and its keys were still fetched
while **offline**; and after a revoke, republishing the revoked key was refused
while the other device remained active.
