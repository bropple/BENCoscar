#!/usr/bin/env bash
# BENCoscar server installer.
#
# Installs the binary, a dedicated unprivileged user, a systemd unit, and an
# environment file. Run it on the server, as root, with the binary in the same
# directory:
#
#   sudo HOSTNAME_FQDN=chat.example.com ./install.sh
#
# Safe to re-run: every step is idempotent. Re-running upgrades the binary and
# restarts the service, leaving the database and config alone.
#
# This replaces the old stunnel front-end. BENCoscar terminates TLS itself, so
# there is no proxy and NO PLAINTEXT OSCAR PORT AT ALL. If you are migrating,
# remove the stunnel service and close the old plaintext port afterwards.

set -euo pipefail

HOSTNAME_FQDN="${HOSTNAME_FQDN:-}"
OSCAR_PORT="${OSCAR_PORT:-5191}"
API_PORT="${API_PORT:-8080}"
SVC_USER="${SVC_USER:-bencoscar}"
BIN_SRC="${BIN_SRC:-}"

# Paths are overridable so the script can be exercised without root, and so an
# unusual layout does not require editing it. The defaults are what you want.
PREFIX="${PREFIX:-}"
BIN_DST="${BIN_DST:-$PREFIX/usr/local/bin/bencoscar}"
CONF_DIR="${CONF_DIR:-$PREFIX/etc/bencoscar}"
DATA_DIR="${DATA_DIR:-$PREFIX/var/lib/bencoscar}"
ENV_FILE="$CONF_DIR/bencoscar.env"
UNIT="${UNIT:-$PREFIX/etc/systemd/system/bencoscar.service}"

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# DRY_RUN exists so this script can be exercised without root. It skips the
# privilege and ownership steps only; everything it generates is identical.
DRY_RUN="${DRY_RUN:-}"

if [ -z "$DRY_RUN" ]; then
  [ "$(id -u)" -eq 0 ] || die "Run this with sudo:  sudo HOSTNAME_FQDN=... ./install.sh"
fi

# The hostname is never baked into this repo — it is a deployment detail, and
# this script is public. It also goes in the certificate and in what the server
# tells clients to reconnect to, so it must match what clients actually dial.
[ -n "$HOSTNAME_FQDN" ] || die "Set the hostname clients will connect to:
       sudo HOSTNAME_FQDN=chat.example.com ./install.sh"

if [ -z "$DRY_RUN" ]; then
  command -v systemctl >/dev/null 2>&1 || die "This installer expects systemd."
fi

# --- locate the binary -----------------------------------------------------
if [ -z "$BIN_SRC" ]; then
  for c in ./bencoscar ./bencoscar-linux-arm64 ./bencoscar-linux-amd64; do
    [ -f "$c" ] && BIN_SRC="$c" && break
  done
fi
[ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ] || die "No binary found. Copy it next to this script:
       scp dist/bencoscar-linux-arm64 <vps>:~/bencoscar
     or point at it:  sudo BIN_SRC=/path/to/bencoscar HOSTNAME_FQDN=... ./install.sh"

# Fail early on an architecture mismatch rather than at first start, where it
# surfaces as a confusing exec format error.
if command -v file >/dev/null 2>&1; then
  HOST_ARCH="$(uname -m)"
  BIN_INFO="$(file -b "$BIN_SRC")"
  case "$HOST_ARCH:$BIN_INFO" in
    aarch64:*aarch64*|arm64:*aarch64*|x86_64:*x86-64*) ;;
    *) die "Binary does not match this machine.
       machine : $HOST_ARCH
       binary  : $BIN_INFO
     Rebuild with:  GOARCH=<arch> ./build.sh" ;;
  esac
fi

say "BENCoscar install"
echo "    hostname       : $HOSTNAME_FQDN"
echo "    OSCAR port     : $OSCAR_PORT  (TLS, terminated by the server itself)"
echo "    management API : 127.0.0.1:$API_PORT  (loopback only)"
echo "    binary         : $BIN_SRC"
echo "    database       : $DATA_DIR/oscar.sqlite"

# --- service user ----------------------------------------------------------
if [ -n "$DRY_RUN" ]; then
  say "[dry run] would ensure system user $SVC_USER exists"
elif id "$SVC_USER" >/dev/null 2>&1; then
  say "User $SVC_USER already exists"
else
  say "Creating system user $SVC_USER"
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
    || useradd --system --home-dir "$DATA_DIR" --shell /sbin/nologin "$SVC_USER"
fi

# --- directories -----------------------------------------------------------
say "Creating directories"
if [ -n "$DRY_RUN" ]; then
  install -d -m 0755 "$CONF_DIR" "$CONF_DIR/tls" "$DATA_DIR" "$(dirname "$BIN_DST")" "$(dirname "$UNIT")"
else
  install -d -m 0755 -o root -g root "$CONF_DIR"
  install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR"
  # Certificates land here. Readable by the service user and nobody else,
  # because this directory holds a private key.
  install -d -m 0750 -o root -g "$SVC_USER" "$CONF_DIR/tls"
fi

# --- binary ----------------------------------------------------------------
say "Installing binary to $BIN_DST"
if [ -n "$DRY_RUN" ]; then
  install -m 0755 "$BIN_SRC" "$BIN_DST"
else
  install -m 0755 -o root -g root "$BIN_SRC" "$BIN_DST"
  "$BIN_DST" --version 2>/dev/null || true
fi

# --- environment file ------------------------------------------------------
# Written once. Re-running the installer upgrades the binary without stomping
# on settings someone may have tuned by hand.
if [ -f "$ENV_FILE" ]; then
  say "Keeping existing $ENV_FILE"
  warn "If the hostname or port changed, edit it by hand and restart."
else
  say "Writing $ENV_FILE"
  cat > "$ENV_FILE" <<EOF
# BENCoscar configuration. Written by install.sh; safe to edit by hand.
# Restart after changes:  systemctl restart bencoscar

# Bind address. TLS is terminated here, by the server itself — there is no
# stunnel and no plaintext OSCAR port.
OSCAR_LISTENERS=BENCO://0.0.0.0:$OSCAR_PORT

# What the server tells clients to reconnect to, for BOS and chat redirects.
# This is NOT the bind address: it must be reachable by clients.
OSCAR_ADVERTISED_LISTENERS_PLAIN=BENCO://$HOSTNAME_FQDN:$OSCAR_PORT

# Native TLS. Both must be set together; setting only one is a startup error
# rather than a silent fallback to cleartext. letsencrypt.sh fills these in.
OSCAR_TLS_CERT_FILE=$CONF_DIR/tls/fullchain.pem
OSCAR_TLS_KEY_FILE=$CONF_DIR/tls/privkey.pem

# Accounts must be provisioned through the management API before anyone can
# sign in. Never set this to true on a reachable server: it accepts any password
# and auto-creates accounts.
DISABLE_AUTH=false

# Loopback only. Reach it with:  ssh -L $API_PORT:localhost:$API_PORT <vps>
API_LISTENER=127.0.0.1:$API_PORT

DB_PATH=$DATA_DIR/oscar.sqlite
LOG_LEVEL=info

# TOC is a plaintext protocol with no TLS story. Bound to loopback so it cannot
# be reached from outside; the server requires the setting to be present.
TOC_LISTENERS=127.0.0.1:9898

ICQ_LEGACY_ENABLED=false

# ENABLE_WEBAPI is deliberately absent. The WebAPI is removed from this fork
# because it authenticates any non-empty password; setting the variable at all
# makes the server refuse to start.
EOF
  chmod 0640 "$ENV_FILE"
  [ -n "$DRY_RUN" ] || chown root:"$SVC_USER" "$ENV_FILE"
fi

# --- systemd unit ----------------------------------------------------------
say "Writing $UNIT"
cat > "$UNIT" <<EOF
[Unit]
Description=BENCoscar (OSCAR server)
Documentation=https://github.com/bropple/BENCoscar
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
EnvironmentFile=$ENV_FILE
ExecStart=$BIN_DST
WorkingDirectory=$DATA_DIR
Restart=on-failure
RestartSec=5s

# The server binds a privileged-ish port only if you set one below 1024; by
# default it does not, so it needs no capabilities at all.
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
# The database directory is the only thing it may write to.
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF

if [ -n "$DRY_RUN" ]; then
  say "[dry run] wrote $UNIT; stopping before systemctl"
  echo
  echo "Generated files:"
  echo "  $ENV_FILE"
  echo "  $UNIT"
  exit 0
fi

systemctl daemon-reload

# --- start -----------------------------------------------------------------
if [ -s "$CONF_DIR/tls/fullchain.pem" ] && [ -s "$CONF_DIR/tls/privkey.pem" ]; then
  say "Enabling and starting bencoscar"
  systemctl enable --now bencoscar
  sleep 2
  systemctl is-active --quiet bencoscar \
    && say "Running" \
    || { warn "Service did not come up. Recent log:"; journalctl -u bencoscar -n 30 --no-pager; exit 1; }
else
  systemctl enable bencoscar >/dev/null 2>&1 || true
  warn "No certificate yet, so the service is enabled but NOT started."
  echo "     BENCoscar refuses to run without one rather than falling back to"
  echo "     cleartext. Get a real certificate next:"
  echo
  echo "         sudo HOSTNAME_FQDN=$HOSTNAME_FQDN ./letsencrypt.sh"
fi

cat <<EOF

$(printf '\033[1;32m==>\033[0m') Installed.

  Service      : systemctl status bencoscar
  Logs         : journalctl -u bencoscar -f
  Config       : $ENV_FILE
  Database     : $DATA_DIR/oscar.sqlite

  Create an account (the management API is loopback-only, so from the VPS):

    curl -X POST http://127.0.0.1:$API_PORT/user \\
      -H 'Content-Type: application/json' \\
      -d '{"screen_name":"someone","password":"their-password"}'

  From your workstation, tunnel first:

    ssh -L $API_PORT:localhost:$API_PORT <vps>

  Then point BENCchat at $HOSTNAME_FQDN port $OSCAR_PORT, with TLS on.

  Remember the network layer gates ports separately from the host firewall —
  on Oracle Cloud that is the security list for the subnet.
EOF
