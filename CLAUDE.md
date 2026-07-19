# BENCoscar

## What this is

BENCoscar is a **fork of [open-oscar-server](https://github.com/mk6i/open-oscar-server)**
(mk6i, Go, MIT), forked at tag `v0.24.0`. It is the server half of BENCchat: a
lightweight, self-hosted, end-to-end-encrypted messaging system that happens to
speak OSCAR on the wire.

This is a BENCO Holdings project. Brand voice, lore, and character details
(R. Triy, etc.) live in the separate BENCO lore document. This file is scoped to
fork policy and architecture.

**For upstream architecture, packages, testing conventions and Go style, read
[`AGENTS.md`](AGENTS.md)** — that is mk6i's own guide to this codebase and it is
accurate and thorough. Don't duplicate it here. This file covers only what is
different *because* it's a fork.

## Why a fork, and not a companion service

The constraints that shaped BENCchat's design turned out to be open-oscar-server
*implementation* choices, not OSCAR protocol limits. Fixing them here keeps
everything on one wire protocol instead of inventing a second one alongside it.

The goal is **not** nostalgia and **not** an AIM museum piece. It is a small
encrypted messaging system fully under BENCO's control, with OSCAR as the
transport because a hand-rolled binary protocol is the interesting part.

Compatibility with classic AIM/ICQ clients is **not a goal**. It is also not a
goal to *break* them — OSCAR negotiates foodgroup versions, so additive changes
leave old clients working for free. The rule is simply that legacy-client
compatibility never gets a veto over a design decision. If preserving it is free,
preserve it; if it costs anything real, drop it.

## Fork discipline

These rules exist to keep syncing with upstream cheap. mk6i is very active
(15–27 commits/month), so every avoidable conflict is a recurring tax.

- **Do NOT rename the Go module path.** It stays
  `github.com/mk6i/open-oscar-server`. It appears in hundreds of import lines
  across the tree; renaming creates a conflict in nearly every file on every
  future sync, for zero functional gain. A module path is an identifier, not a
  URL — BENCchat already proves a path need not match its repo.
- **Keep the diff small and ADDITIVE.** New foodgroups and features belong in
  **new files**; those rebase almost free. Edits scattered through existing files
  fight every sync. When a change must touch an upstream file, make it the
  smallest possible hook — ideally one call out to a new file.
- **Every BENCO-specific change gets a comment saying so**, so a future sync can
  tell "ours" from "theirs" without archaeology.
- **Upstream's tests must stay green.** They are the regression suite for the
  ~95% of this codebase we did not write. Never delete an upstream test to make a
  change pass; that's the alarm working correctly.

## Syncing with upstream

The `upstream` remote points at mk6i's repo; `origin` is ours. The working branch
is `benco`.

**Sync at upstream RELEASES, not at `main`.** Tags land every 6–10 weeks with
roughly 40–50 commits each (`v0.22.0` Jan 30, `v0.23.0` Mar 24, `v0.24.0` Jun 6,
2026), so this means about six syncs a year against a settled core, each landing
on a revision upstream considered shippable. Chasing `main` means rebasing onto
whatever half-finished state the webapi work is in that week, for no benefit.

```sh
git fetch upstream --tags
git tag --sort=-creatordate | head -5     # newest releases
git log --oneline benco..v0.25.0          # what the release contains
git rebase v0.25.0                        # or merge, if the diff has grown
```

Before pushing, run what CI runs — all of it. CI runs the linter *before* vet,
build and test, so a lint failure skips everything else and tells you nothing
about whether the code works:

```sh
gofmt -s -l .                             # must print nothing
golangci-lint run ./...                   # v2.12.2, matches .golangci.yml
go vet ./... && go test -race ./...
```

`errcheck` is on and it is stricter than habit: a bare `defer conn.Close()` in a
test is a lint failure, not a style nit. Write `defer func() { _ = conn.Close() }()`.

`git log --oneline <tag>..benco` is the inverse and always shows exactly the
BENCO delta. Keep that list short and readable — if it stops being either, the
fork discipline above has slipped.

Pin the deployment to the tag the fork is based on, so "which upstream are we
running" is always answerable.

Watch `server/webapi/` in particular: mk6i is building an HTTP/JSON access layer
there, which overlaps with things BENCO might otherwise build itself. Check
whether upstream already has it before writing it.

## Deployment — don't publish the address

The live hostname, ports, and VPS details live in `DEPLOYMENT.local.md`, which is
deliberately **not** in source control. This repo is public; the server address
is a deployment detail and publishing it just invites traffic.

- **Never hardcode a hostname** in committed code, config, tests, docs, or CI.
  Upstream's defaults (`localhost`, `127.0.0.1`) are correct and should stay.
- Configuration is env-var driven (see `AGENTS.md`), so a real deployment
  supplies its own address at runtime. There is no reason for one to be in the
  tree.
- Same rule as BENCchat: a public artifact can be `strings`-grepped, so a
  "secret" baked into a build flag is not secret.

## Security posture

BENCchat does end-to-end encryption **client-side** — the server never sees
plaintext message bodies and must never need to. Anything added here that would
require the server to read message content is the wrong design, not a shortcut.

**Native TLS is implemented** — see [`docs/BENCO_TLS.md`](docs/BENCO_TLS.md).
Setting `OSCAR_TLS_CERT_FILE` and `OSCAR_TLS_KEY_FILE` makes every OSCAR listener
a TLS listener, with no plaintext port in existence. Leaving them unset
reproduces upstream's stunnel model exactly. Half-configured TLS is a startup
error rather than a silent fallback to cleartext.

Known open items, carried over from the client-side analysis:

- **Auth is salted MD5.** BUCP challenge-response structurally *requires* the
  server to hold a password-equivalent, so a stronger KDF cannot simply be bolted
  onto it. The escape route is plaintext-over-TLS plus argon2id at rest — the
  codebase already has an `isPlaintextAuth` path. This is now unblocked (the
  plaintext OSCAR port is closed on the live deployment) but not yet done.
- **The WebAPI is removed from this fork.** `SQLiteUserStore.AuthenticateUser`
  (`state/webapi_auth.go`) does not verify passwords — it returns the user for
  any non-empty string, with a `// TODO: In production, verify password hash
  here` — and the listener binds `0.0.0.0:9000` hardcoded
  (`cmd/server/factory.go`), ignoring the listener config. That combination is
  an authentication bypass reachable on every interface. Upstream
  work-in-progress rather than something broken, but it ships in v0.24.0.
  `cmd/server/main.go` refuses to start if `ENABLE_WEBAPI` is set at all, before
  any socket is bound, rather than ignoring it — an operator who sets it
  believes a web API is listening, and silence would leave that belief intact.
  Note `server/webapi/` is still compiled and still runs upstream's tests; only
  the wiring in `main.go` is gone, which keeps the sync diff minimal.
- **Device removal is not durable.** A device removed from a BENCchat account
  re-publishes itself on next sign-on, because there is no server-side authority
  over the published key set. A fork-side fix is plausible and is one of the
  better reasons this fork exists.
- Credentials, keys and tokens are **never** committed, and never written to a
  file in the repo — not even in a test fixture.

## Relationship to BENCchat

BENCchat (the client) lives in a sibling directory and its own repo. The two are
developed together but are separate projects:

- Protocol changes start here, in a new foodgroup or SNAC subtype, and BENCchat
  learns to speak them. Not the reverse.
- BENCchat's `CLAUDE.md` is the reference for client-side architecture and for
  the E2EE model. Read it before changing anything that touches key
  distribution, the Locate foodgroup, or the profile blob — the client stores
  its device keys in places that look incidental from the server side.

## Attribution

Upstream is MIT-licensed. `LICENSE` retains mk6i's copyright notice verbatim and
must stay that way — that is the entirety of the obligation, and it is not
optional. Bug reports for upstream behavior belong upstream, not here; issues
here should be about the BENCO delta.
