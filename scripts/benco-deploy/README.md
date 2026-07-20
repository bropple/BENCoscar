# Deploying BENCoscar

Three scripts. Build on your workstation, install on the server.

**No hostname is baked into any of them** — this repo is public, and the server
address is a deployment detail. Every script requires `HOSTNAME_FQDN` and
refuses to run without it.

## Quick version

```bash
# workstation
./scripts/benco-deploy/build.sh                      # defaults to linux/arm64
scp dist/bencoscar-linux-arm64 <vps>:~/bencoscar
scp scripts/benco-deploy/{install.sh,letsencrypt.sh} <vps>:~/

# server
sudo HOSTNAME_FQDN=chat.example.com ./install.sh
sudo HOSTNAME_FQDN=chat.example.com ./letsencrypt.sh
```

Then create an account and point a client at it.

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

### `build.sh`

Cross-compiles a static binary. Defaults to `linux/arm64`; override with
`GOOS`/`GOARCH`. Cross-compiling needs no toolchain because the SQLite driver is
pure Go and CGO stays off.

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
./scripts/benco-deploy/build.sh
scp dist/bencoscar-linux-arm64 <vps>:~/bencoscar
sudo HOSTNAME_FQDN=chat.example.com ./install.sh
```

Database migrations run automatically at startup. Take a backup first if the
release notes mention a schema change — migration `0034` in particular is
one-way and drops the old password columns.
