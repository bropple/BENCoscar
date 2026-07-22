# Deploying BENCoscar

Install once from a workstation. After that, deploys run **on the server**:
`deploy.sh` pulls, builds and rolls the service over in one command.

**No hostname is baked into any of them** — this repo is public, and the server
address is a deployment detail. The install scripts require `HOSTNAME_FQDN` and
refuse to run without it.

## First install

```bash
# workstation
./scripts/benco-deploy/build.sh                      # defaults to linux/arm64
scp dist/bencoscar-linux-arm64 <vps>:~/bencoscar
scp scripts/benco-deploy/{install.sh,letsencrypt.sh,deploy.sh} <vps>:~/

# server
sudo HOSTNAME_FQDN=chat.example.com ./install.sh
sudo HOSTNAME_FQDN=chat.example.com ./letsencrypt.sh
```

Then create an account and point a client at it.

## Every deploy after that

```bash
# on the server
sudo ./deploy.sh
```

That is the whole thing. It clones the public repo (HTTPS, no credentials) to
`/opt/bencoscar/src` on first run and fetches after that, builds both binaries,
and swaps them in with a health check and automatic rollback. See
[`deploy.sh`](#deploysh) below.

## What changed from the stunnel setup

BENCoscar terminates TLS itself, so **stunnel is gone** and there is **no
plaintext OSCAR port at all**. If you are migrating:

```bash
sudo systemctl disable --now stunnel4     # or stunnel
```

and remove the old cleartext port from your firewall and from the network-layer
rules. On Oracle Cloud that is the subnet's security list, which gates ports
separately from the host firewall — a port can be open on the VM and still
unreachable, or vice versa.

The TLS port defaults to **5191**, matching what the stunnel front-end used, so
existing client configs keep working.

## The scripts

### `deploy.sh`

**The normal way to ship a change.** Runs on the server, as root, against an
installation that already exists.

```bash
sudo ./deploy.sh                  # deploy the benco branch
sudo ./deploy.sh --branch main    # something else
sudo ./deploy.sh --dry-run        # show every step, change nothing
sudo ./deploy.sh --force          # rebuild and reinstall the same commit
```

What it does, in order:

1. Checks `git` and a Go toolchain new enough for `go.mod`. It never installs Go
   silently — it prints the upstream tarball commands for this architecture and
   stops.
2. Finds the installed unit (`bencoscar`, or `ras` for an upstream-style
   install) and reads the binary path, service account and management API
   address **out of the unit itself**, so it cannot drift from what is running.
   If no unit exists it tells you to run `install.sh` and stops — it will not
   half-install.
3. Clones or fetches `/opt/<service>/src`. **A dirty checkout aborts the
   deploy**: someone editing code on the server is a situation to surface, not
   to clobber. Untracked files are only a warning.
4. Prints `git log <current>..<target> --oneline` and asks for confirmation,
   calling out any migrations in the range. Nothing to deploy is a clean exit,
   not an error.
5. Builds `./cmd/server` and `./cmd/benco_admin` **into a temp directory**, and
   checks each artifact is an ELF executable for this machine that actually
   runs. A working binary is never replaced by an unverified one.
6. Stops the service, copies the running binaries to `<binary>.prev`, installs,
   starts.
7. Health check — see below.
8. On failure, restores `.prev`, restarts, dumps the journal, and exits non-zero.

It deploys **code only**. It never touches the unit, the environment file, the
database, the certificate, the service account or the admin group, and the
server gains no privileges from any of it.

#### What the health check actually probes

`systemctl is-active` is not sufficient: the OSCAR listener binds before the
database is opened, a migration can fail after start, and `Restart=on-failure`
makes a crash loop look like `activating`. So all three must hold, retried for
up to 30 seconds because migrations run during startup:

1. `systemctl is-active` reports the unit running.
2. `GET /version` on the **management API** answers. The unit puts that API on a
   unix socket, so the probe is
   `curl --unix-socket /run/bencoscar/mgmt.sock http://localhost/version`. Root
   traverses the `0750` runtime directory without needing the admin group. If
   `curl` is absent it falls back to the freshly built
   `benco_admin user list --api …`, and says that the check was weaker.
3. **The commit that endpoint reports matches the commit just installed.** This
   is the part that distinguishes a real deploy from an old process that never
   died and is still holding the socket — the commit is baked in at link time by
   the same `-X main.commit` ldflag `build.sh` uses.

#### Rolling back by hand

The replaced binaries are kept beside their replacements:

```bash
sudo systemctl stop bencoscar
sudo cp -a /usr/local/bin/bencoscar.prev /usr/local/bin/bencoscar
sudo cp -a /usr/local/bin/benco_admin.prev /usr/local/bin/benco_admin
sudo systemctl start bencoscar
```

One generation is kept — each deploy overwrites `.prev`. For anything older,
check out the commit in `/opt/bencoscar/src` and deploy that.

### `build.sh`

Cross-compiles a static binary. Defaults to `linux/arm64`; override with
`GOOS`/`GOARCH`. Cross-compiling needs no toolchain because the SQLite driver is
pure Go and CGO stays off.

Still the route for the first install, and the alternative for **a server you do
not want a Go toolchain on** — build elsewhere, `scp`, re-run `install.sh`.

### `install.sh`

Idempotent. Creates a system user, directories, a systemd unit and an
environment file, then starts the service. Re-running upgrades the binary and
restarts, leaving the database and any hand-edited config alone.

It refuses to start the service until a certificate exists. That is deliberate:
half-configured TLS is a startup error in BENCoscar rather than a silent
fallback to cleartext, because a server listening in the clear while the
operator believes otherwise is the failure this whole design exists to prevent.

The systemd unit is hardened — `ProtectSystem=strict`, no new privileges, no
capabilities, and the database directory is the only writable path.

Useful overrides: `OSCAR_PORT`, `API_PORT`, `SVC_USER`, `BIN_SRC`.

### `letsencrypt.sh`

Gets a certificate over DNS-01 through Cloudflare, so port 80 never needs to be
open. Needs a Cloudflare API token with `Zone:DNS:Edit` at
`/etc/letsencrypt/cloudflare.ini`; the script tells you how if it is missing.

It installs a renewal deploy hook that copies the certificate into
`/etc/bencoscar/tls/` **and restarts the service**. That restart matters:
BENCoscar loads the keypair once at startup, so without it a renewed certificate
would sit on disk unused until the old one expired and clients started failing.

### `uninstall.sh`

Removes everything `install.sh` created — unit, `/etc/bencoscar`,
`/var/lib/bencoscar`, both binaries, the service user and the admin group — so a
reinstall starts from nothing. `reset-db.sh` wipes the *database*; this wipes the
*install*.

**It keeps `/etc/letsencrypt` by default, and that is the point.** Let's Encrypt
allows five duplicate certificates per registered domain per 168 hours, and
BENCoscar treats a missing keypair as a startup error rather than falling back to
cleartext — so a rebuild that cannot get a certificate is a rebuild that cannot
start. `letsencrypt.sh` short-circuits when a live certificate already exists,
which makes the reinstall free. `--purge-certs` overrides this, and says why not
to.

It refuses to run when `/var/lib/bencoscar` is a mount point, which is what the
optional LUKS bundle makes it: `rm -rf` on a live mount empties the volume and
leaves the mapping behind, so that bundle's own `uninstall.sh` has to go first.

The database and the env file are copied to `/var/backups/bencoscar-<stamp>` at
`0700` before anything is removed (`--purge-data` skips this). The env file is
the only record of what was tuned by hand — `LOG_LEVEL`, `BENCO_DEVICE_AUTH`, the
rate class — since `install.sh` writes a fresh one.

The renewal deploy hook is removed even when the certificates are kept: it
installs files owned by the service group, so with the group gone a renewal
landing between uninstall and reinstall would fail. `letsencrypt.sh` writes it
again.

```bash
sudo ./uninstall.sh --dry-run     # show the plan, change nothing
sudo ./uninstall.sh               # asks you to type the service name
```

## Accounts

`DISABLE_AUTH=false`, so accounts must be provisioned before anyone can sign in.

```bash
# on the VPS
benco_admin user add someone
benco_admin user list
```

Passwords are stored as argon2id. There is no way to recover one — reset it:

```bash
benco_admin user passwd someone
```

`benco_admin` never takes a password as an argument (argv is visible in `ps` and
lands in shell history); it prompts, or reads stdin when stdin is a pipe.

### Who is allowed to do this

The management API has no authentication of its own — no token, no password.
Instead it listens on a unix socket, and the filesystem decides who may connect:

```
/run/bencoscar             0750  bencoscar:bencoscar-admin   traverse
/run/bencoscar/mgmt.sock   0660  bencoscar:bencoscar-admin   connect
```

The kernel refuses anyone outside `bencoscar-admin` before the server reads a
byte. There is nothing to leak, nothing to rotate, and no bind address to get
wrong — the API cannot be exposed to the network by editing an environment
variable, because it has no address.

The **directory** mode is the load-bearing part. Go creates unix sockets with
`0777 &~ umask` and can only `chmod` them after binding, so for an instant the
socket itself is world-writable; a directory nobody outside the group can
traverse means that instant does not matter.

Each link in the chain is established by a different component:

| What | By whom |
| --- | --- |
| `bencoscar-admin` exists; the admin is a member | `install.sh` (`groupadd`, `usermod -aG`) |
| `/run/bencoscar` exists at `0750`, removed on stop | systemd `RuntimeDirectory=` / `RuntimeDirectoryMode=` |
| The server is *in* the group, so it can hand the socket over | systemd `SupplementaryGroups=` |
| Directory and socket given to the group; socket set `0660` | the server at startup, from `API_SOCKET_GROUP` |
| `AF_UNIX` permitted at all | systemd `RestrictAddressFamilies=` |

Grant someone access:

```bash
sudo usermod -aG bencoscar-admin <user>
```

They must then log out and back in. Group membership is fixed when a process
starts and inherited from its parent, so a shell that was already running never
picks it up — and no command run *inside* that shell can change that, which is
why the installer cannot do it for you. `benco_admin` detects this case (in the
group per `/etc/group`, but absent from `os.Getgroups()`) and transparently
re-runs itself under `sg`, printing one line when it does. Everything else will
report permission denied until the next login.

### Still want a TCP port?

`API_LISTENER=127.0.0.1:8080` still works, reached through a tunnel
(`ssh -L 8080:localhost:8080 <vps>`), and `benco_admin --api 127.0.0.1:8080`
will talk to it. Two things change over TCP: there are no peer credentials, so
the audit log records actions as `peer_uid=unknown`; and a **non-loopback** bind
now refuses to start unless `API_ALLOW_NONLOOPBACK=true` is set alongside it.
That is deliberate — a typo in a bind address should not be able to publish an
unauthenticated "reset any password" endpoint.

## Starting the database over

```bash
sudo ./reset-db.sh
```

Stops the service, moves the database aside, and restarts. Migrations rebuild
the schema at boot, so there is nothing to restore or re-import — but **every
account is destroyed**, and argon2id hashes cannot be recovered from what is
removed, so accounts have to be created again.

The database is moved rather than deleted and the rollback command is printed.
`--keep-accounts` clears published device keys while preserving the users table,
for when clients are in a confused state but the accounts are fine.

Clients keep their own keys and republish them, but each one is a brand new
device to a fresh server: expect the approval prompts of a new account, and
contacts will see safety numbers change.

## Checking it works

```bash
systemctl status bencoscar
journalctl -u bencoscar -f
```

The startup log line should say `native_tls=true`. Then confirm the socket is
genuinely encrypted:

```bash
openssl s_client -connect chat.example.com:5191 -servername chat.example.com </dev/null
```

A plaintext connection to the same port should hang and time out rather than
returning a FLAP frame — one that begins with the byte `0x2A` would mean
cleartext OSCAR is answering, which should now be impossible.

## Upgrading

```bash
# on the server
sudo ./deploy.sh
```

### Without Go on the server

The old route still works and stays supported, because a server that should not
carry a compiler is a legitimate position:

```bash
./scripts/benco-deploy/build.sh
scp dist/bencoscar-linux-arm64 <vps>:~/bencoscar
sudo HOSTNAME_FQDN=chat.example.com ./install.sh
```

`install.sh` is idempotent, so this upgrades the binary and restarts. Note it
does **not** health-check the management API or keep a rollback copy — that part
is `deploy.sh`'s.

### Migrations

There is no migration step in either route. The server runs its own migrations
at startup, so they happen inside the restart.

Take a backup first when the range touches `state/migrations/` — `deploy.sh`
says so when it does. Two are one-way: `0034` drops the old password columns,
and **`0036` drops the v1 `deviceKeys` table outright**. A first deploy onto a
database that predates 0036 should be backed up beforehand.

There is no `backup-db.sh` in this repo. Copy the file by hand, with the service
stopped so SQLite is not mid-write:

```bash
sudo systemctl stop bencoscar
sudo cp -a /var/lib/bencoscar/oscar.sqlite ~/oscar.sqlite.bak
sudo systemctl start bencoscar
```

Clients keep their own keypairs and republish them, so what 0036 destroys is
server-side v1 key state, not anyone's identity.
