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
The management API is loopback-only:

```bash
# on the VPS
curl -X POST http://127.0.0.1:8080/user \
  -H 'Content-Type: application/json' \
  -d '{"screen_name":"someone","password":"their-password"}'

# or from your workstation
ssh -L 8080:localhost:8080 <vps>
```

Passwords are stored as argon2id. There is no way to recover one — reset it:

```bash
curl -X PUT http://127.0.0.1:8080/user/password \
  -H 'Content-Type: application/json' \
  -d '{"screen_name":"someone","password":"a-new-password"}'
```

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
