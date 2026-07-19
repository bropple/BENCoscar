# Password storage (BENCO)

This fork stores passwords as **argon2id** hashes and does not support **BUCP
challenge-response** authentication. Upstream does the opposite. This document
explains the change, what it breaks, and what an operator has to do.

> **For the BENCO deployment specifically, this section is moot:** the plan is to
> redeploy with a fresh database, so there are no pre-existing rows to migrate.
> It matters only if you point this server at a database created by upstream.

## ⚠️ Existing accounts must have their passwords reset

Migration `0034_argon2id_passwords` drops the old MD5 columns and adds an empty
`passwordHash`. **An argon2id hash cannot be derived from an MD5 one** — that is
what "one-way" means — so every pre-existing account has no usable credential
after migrating and **cannot sign in** until its password is set again:

```sh
curl -X PUT http://127.0.0.1:8080/user/password \
  -H 'Content-Type: application/json' \
  -d '{"screen_name": "someone", "password": "their-new-password"}'
```

(The management API is loopback-only; reach it over an SSH tunnel.)

This is deliberate, not an oversight. The alternative — keeping the MD5 columns
as a fallback — would preserve exactly the exposure the change exists to remove.

## Why BUCP had to go

Upstream stores three credential fields per user: `authKey` (a per-user salt),
`weakMD5Pass`, and `strongMD5Pass`. They exist because BUCP works like this:

1. Client asks for a challenge. Server sends back the user's `authKey`.
2. Client computes `MD5(authKey ‖ password ‖ constant)` and sends the result.
3. Server compares it against the value it has stored.

For step 3 to work, the server must hold something it can use to *reproduce* what
the client computed. That makes the stored value a **password equivalent**:
anyone with a copy of the database can complete step 2 themselves and sign in as
any user, without cracking anything. Single-round MD5 with no iteration count
makes it worse, but the structural problem would remain with any hash.

So no key-stretching algorithm can be bolted onto BUCP. The choice is BUCP *or*
a one-way KDF, and this fork chooses the KDF.

**The insight that made this cheap:** BUCP is the *only* path with that
requirement. Every other one — roasted FLAP, roasted Java, roasted TOC, Kerberos
plaintext, Kerberos roasted, legacy ICQ, and the management API's create and
reset endpoints — already has the cleartext password in hand at verification
time. "Roasting" is a reversible XOR against a fixed table, not encryption, so
undoing it yields the password itself. Those paths were merely *choosing* to
compare an MD5. They now verify against argon2id instead, with no protocol change
at all.

### Isn't sending the password in cleartext worse?

Only without TLS. Challenge-response protects a password from a passive
eavesdropper on a plaintext link — a real concern in 1998, when there was no
transport encryption underneath. Once TLS carries the connection, the transport
already solves that, and challenge-response buys nothing while still forbidding a
real KDF.

`TLS + cleartext + argon2id` beats `no TLS + challenge-response + MD5` on every
axis. The only genuinely bad combination is cleartext *without* TLS, which is why
native TLS (see [`BENCO_TLS.md`](BENCO_TLS.md)) landed first and why the plaintext
OSCAR port is closed on the live deployment.

## What breaks

**AIM v3.5–v5.9** clients, which authenticate over BUCP. Nothing else.

Notably **not** broken: AIM v1.0–v3.0 (roasted FLAP), TOC clients, Kerberos, and
legacy ICQ — those paths all recover cleartext and verify fine. Buddy lists,
groups, presence, and messaging are untouched; BUCP is foodgroup `0x0017` and
concerns login only, despite what the acronym may suggest.

BENCchat uses the FLAP sign-on path with TLV `0x1339`
(`LoginTLVTagsPlaintextPassword`) over TLS.

A BUCP client gets `LoginErrInvalidUsernameOrPassword`. That subcode is not
literally accurate — OSCAR has no "unsupported auth method" code — but it is one
every client renders. The real reason is logged server-side at WARN.

## The hash format

Hashes are stored in PHC string format:

```
$argon2id$v=19$m=65536,t=3,p=2$<base64 salt>$<base64 hash>
```

argon2id rather than argon2i or argon2d: it is the hybrid RFC 9106 recommends
absent a specific reason to choose otherwise, resisting GPU cracking through
memory hardness and side-channel attacks through its data-independent first pass.

Parameters are `m=19 MiB, t=2, p=1` — the configuration OWASP names first.

It is tempting to go much higher on the reasoning that sign-ins are rare, and
that reasoning is wrong: **the login rate is not ours to choose.** Every
unauthenticated login attempt makes the server allocate the full memory cost
before any password is checked, so argon2's memory parameter is also an
amplification factor handed to whoever is sending the attempts. At 64 MiB a
trivial trickle of concurrent sign-on frames exhausts a small VPS. At 19 MiB the
same trickle is survivable, and offline cracking is still expensive.

**Raising the cost later does not invalidate existing hashes.** The parameters
travel inside each hash and are used when verifying it, so old hashes remain
verifiable under the parameters they were created with while new ones use the
new cost. Change the constants in `state/password.go`; no migration needed.

Each hash carries its own random 16-byte salt, so two users with the same
password get different stored values. Upstream's single stored `authKey` per user
did not give this.

## Where the code lives

| Concern | File |
|---|---|
| Hashing, verification, PHC encode/decode | `state/password.go` (new) |
| `User.PasswordHash` and the `Validate*` methods | `state/user.go` |
| Schema change | `state/migrations/0034_argon2id_passwords.{up,down}.sql` |
| BUCP refusal | `foodgroup/auth.go` — `BUCPChallenge`, `BUCPLogin` |

`ValidateHash` is kept and hardcoded to return `false` rather than deleted, so
upstream's BUCP call sites still compile and the sync diff stays small.

`wire.WeakMD5PasswordHash` and `wire.StrongMD5PasswordHash` are also left in
place, along with their tests. They are no longer reachable from any auth path,
but deleting them would touch upstream files for no benefit.
