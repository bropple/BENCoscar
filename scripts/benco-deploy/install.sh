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
SVC_USER="${SVC_USER:-bencoscar}"
BIN_SRC="${BIN_SRC:-}"

# The management API is a unix socket, not a port. Membership of ADMIN_GROUP is
# what authorises administration: the socket lives in a directory only that
# group can traverse, so the kernel refuses everyone else before the server
# reads a byte. There is no token, nothing to rotate, and no way to widen it
# onto the network by mistyping a bind address.
ADMIN_GROUP="${ADMIN_GROUP:-bencoscar-admin}"
RUNTIME_DIR_NAME="${RUNTIME_DIR_NAME:-bencoscar}"
SOCKET_PATH="${SOCKET_PATH:-/run/$RUNTIME_DIR_NAME/mgmt.sock}"
# ADMIN_USER is resolved below; see resolve_admin_user for why $USER is wrong.
ADMIN_USER="${ADMIN_USER:-}"

# Paths are overridable so the script can be exercised without root, and so an
# unusual layout does not require editing it. The defaults are what you want.
PREFIX="${PREFIX:-}"
BIN_DST="${BIN_DST:-$PREFIX/usr/local/bin/bencoscar}"
ADMIN_BIN_DST="${ADMIN_BIN_DST:-$PREFIX/usr/local/bin/benco_admin}"
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

usage() {
  cat <<'USAGE'
BENCoscar server installer.

  sudo HOSTNAME_FQDN=chat.example.com ./install.sh [options]

Options:
  --admin-user NAME   User to add to the management group. Defaults to the
                      person who ran sudo. Required when that cannot be
                      determined, or when it resolves to root.
  --dry-run           Generate everything, touch nothing privileged.
  -h, --help          This text.

Environment (all optional):
  HOSTNAME_FQDN   Hostname clients connect to. REQUIRED.
  OSCAR_PORT      OSCAR/TLS port (default 5191)
  SVC_USER        Service account (default bencoscar)
  ADMIN_GROUP     Group allowed to administer the server (default bencoscar-admin)
  SOCKET_PATH     Management socket (default /run/bencoscar/mgmt.sock)
  BIN_SRC         Path to the server binary
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --admin-user) [ $# -ge 2 ] || die "--admin-user needs a username"; ADMIN_USER="$2"; shift 2 ;;
    --admin-user=*) ADMIN_USER="${1#*=}"; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

if [ -z "$DRY_RUN" ]; then
  [ "$(id -u)" -eq 0 ] || die "Run this with sudo:  sudo HOSTNAME_FQDN=... ./install.sh"
fi

# --- who is the administrator? ---------------------------------------------
# Getting this wrong fails silently: the group is created, someone is added to
# it, the script says "Installed", and the person who ran it still cannot
# administer anything.
#
# $USER is root here. sudo's default env_reset rewrites it, so using it would
# add root to the admin group -- which grants nobody anything new, because root
# already bypasses the permission check the group exists to make.
#
# $SUDO_USER is what sudo preserves for exactly this purpose. `logname` reads
# the controlling terminal's owner and covers `sudo -i` and similar, where
# SUDO_USER may be absent.
resolve_admin_user() {
  if [ -n "$ADMIN_USER" ]; then
    printf '%s' "$ADMIN_USER"
    return
  fi
  local candidate="${SUDO_USER:-}"
  if [ -z "$candidate" ]; then
    candidate="$(logname 2>/dev/null || true)"
  fi
  printf '%s' "$candidate"
}

ADMIN_USER="$(resolve_admin_user)"

if [ -z "$ADMIN_USER" ]; then
  # A root shell or cloud-init has no "the user who ran this" to find. There is
  # no sensible guess, so ask rather than pick one.
  die "Cannot tell who should administer this server.

     This looks like a root shell with no sudo context, so there is no
     invoking user to add to the $ADMIN_GROUP group. Name them:

         sudo ./install.sh --admin-user alice HOSTNAME_FQDN=..."
fi

if [ "$ADMIN_USER" = "root" ]; then
  die "Refusing to make root the only member of $ADMIN_GROUP.

     A group whose sole member is root grants nothing: root already passes
     every permission check the group exists to enforce, so the management
     socket would end up administrable by root and nobody else -- which is
     where we started, with sudo as the only route in.

     Name a real user:

         sudo ./install.sh --admin-user alice HOSTNAME_FQDN=$HOSTNAME_FQDN"
fi

if [ -z "$DRY_RUN" ] && ! id "$ADMIN_USER" >/dev/null 2>&1; then
  die "No such user: $ADMIN_USER. Create the account first, or pass --admin-user."
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

# --- port conflict ---------------------------------------------------------
# Checked BEFORE anything is installed. A bind failure at first start reports
# only "address already in use" from a service that then crash-loops, which is a
# needlessly obscure way to discover that the old TLS front-end is still running.
#
# Runs even under DRY_RUN: it only reads socket state, and being able to
# exercise it without root is worth more than the symmetry. Without root, ss
# omits the process name, so the holder is reported without attribution rather
# than not reported at all.
if command -v ss >/dev/null 2>&1; then
  HOLDER="$(ss -ltnpH "sport = :$OSCAR_PORT" 2>/dev/null | head -1 || true)"
  if [ -n "$HOLDER" ]; then
    # Ignore ourselves: re-running the installer over a running service is fine.
    if printf '%s' "$HOLDER" | grep -q 'bencoscar'; then
      say "Port $OSCAR_PORT is held by bencoscar itself (upgrade in place)"
    else
      warn "Port $OSCAR_PORT is already in use:"
      echo "    $HOLDER"
      echo
      if printf '%s' "$HOLDER" | grep -q 'stunnel'; then
        # By far the most likely case: migrating off the stunnel front-end,
        # which BENCoscar's native TLS replaces.
        cat <<'MIGRATE'
    That is stunnel — the old TLS front-end, which BENCoscar replaces because
    it now terminates TLS itself. Retire it:

        sudo systemctl disable --now benchat-tls
        sudo rm -f /etc/letsencrypt/renewal-hooks/deploy/benchat-tls.sh

    The second command matters as much as the first: that hook restarts the
    stunnel service on every certificate renewal, so without removing it
    stunnel returns months later and takes this port back.

    Note the systemd unit is called benchat-tls, not stunnel — disabling
    "stunnel4" only touches the distribution's own unit and changes nothing.
MIGRATE
      else
        echo "    Stop whatever owns it, or install on a different port:"
        echo "        sudo OSCAR_PORT=<port> HOSTNAME_FQDN=$HOSTNAME_FQDN ./install.sh"
      fi
      die "port $OSCAR_PORT is not free"
    fi
  fi
fi

say "BENCoscar install"
echo "    hostname       : $HOSTNAME_FQDN"
echo "    OSCAR port     : $OSCAR_PORT  (TLS, terminated by the server itself)"
echo "    management API : $SOCKET_PATH  (unix socket)"
echo "    admin group    : $ADMIN_GROUP"
echo "    administrator  : $ADMIN_USER"
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

# --- admin group -----------------------------------------------------------
# This group IS the management API's authentication. Both steps below are
# idempotent: groupadd is skipped when the group exists, and `usermod -aG` is a
# no-op for someone already in it (it appends, and re-appending an existing
# member does not duplicate the entry).
if [ -n "$DRY_RUN" ]; then
  say "[dry run] would ensure group $ADMIN_GROUP exists and contains $ADMIN_USER"
else
  if getent group "$ADMIN_GROUP" >/dev/null 2>&1; then
    say "Group $ADMIN_GROUP already exists"
  else
    say "Creating group $ADMIN_GROUP"
    groupadd --system "$ADMIN_GROUP"
  fi

  if id -nG "$ADMIN_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$ADMIN_GROUP"; then
    say "$ADMIN_USER is already in $ADMIN_GROUP"
  else
    say "Adding $ADMIN_USER to $ADMIN_GROUP"
    usermod -aG "$ADMIN_GROUP" "$ADMIN_USER"
    NEEDS_RELOGIN=1
  fi

  # The service must be a member too, because it is the process that hands the
  # socket and its runtime directory to the group at startup, and a process may
  # only chgrp to a group it belongs to.
  if id -nG "$SVC_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$ADMIN_GROUP"; then
    :
  else
    usermod -aG "$ADMIN_GROUP" "$SVC_USER"
  fi
fi
NEEDS_RELOGIN="${NEEDS_RELOGIN:-}"

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

# --- admin CLI -------------------------------------------------------------
# Optional: installed when it was shipped alongside the server. The admin group
# is not much use without the tool that dials the socket, so take it if it is
# here. 0755 -- the binary grants nothing by itself; the group does.
ADMIN_BIN_SRC="${ADMIN_BIN_SRC:-}"
if [ -z "$ADMIN_BIN_SRC" ]; then
  for c in ./benco_admin ./benco_admin-linux-arm64 ./benco_admin-linux-amd64; do
    [ -f "$c" ] && ADMIN_BIN_SRC="$c" && break
  done
fi
if [ -n "$ADMIN_BIN_SRC" ]; then
  say "Installing admin CLI to $ADMIN_BIN_DST"
  if [ -n "$DRY_RUN" ]; then
    install -m 0755 "$ADMIN_BIN_SRC" "$ADMIN_BIN_DST"
  else
    install -m 0755 -o root -g root "$ADMIN_BIN_SRC" "$ADMIN_BIN_DST"
  fi
else
  warn "No benco_admin binary found next to this script; skipping it."
  echo "     Build it with:  GOOS=linux GOARCH=\$(uname -m) go build ./cmd/benco_admin"
  echo "     Without it, administration means curl --unix-socket $SOCKET_PATH"
fi

# --- environment file ------------------------------------------------------
# Written once. Re-running the installer upgrades the binary without stomping
# on settings someone may have tuned by hand.
if [ -f "$ENV_FILE" ]; then
  say "Keeping existing $ENV_FILE"
  warn "If the hostname or port changed, edit it by hand and restart."
  # An upgrade from a pre-socket install leaves the API on a TCP port, which
  # still works but is the configuration this release exists to replace.
  if grep -q '^API_LISTENER=unix:' "$ENV_FILE" 2>/dev/null; then
    :
  else
    warn "$ENV_FILE still puts the management API on a TCP port."
    echo "     That port has NO authentication -- anything that can reach it can reset"
    echo "     any password. Switch it to the socket, where group membership is the"
    echo "     credential, by replacing the API_LISTENER line with:"
    echo
    echo "         API_LISTENER=unix:$SOCKET_PATH"
    echo "         API_SOCKET_GROUP=$ADMIN_GROUP"
    echo
    echo "     then:  systemctl restart bencoscar"
  fi
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

# The management API has no authentication of its own, so it does not get a
# port. It gets a unix socket, and the filesystem does the authenticating:
# systemd creates /run/$RUNTIME_DIR_NAME at 0750, the server hands it and the
# socket to $ADMIN_GROUP, and the kernel then refuses anyone outside that group
# before the server reads a byte. Nothing here can be widened onto the network
# by mistyping an address, because there is no address.
API_LISTENER=unix:$SOCKET_PATH
API_SOCKET_GROUP=$ADMIN_GROUP

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
# The server chgrps the management socket and its directory to the admin group
# at startup, and a process may only chgrp to a group it is in. This is the line
# that lets it, without making the admin group the service's primary group --
# which would change the group of everything else it writes, including the
# database.
SupplementaryGroups=$ADMIN_GROUP
EnvironmentFile=$ENV_FILE
ExecStart=$BIN_DST
WorkingDirectory=$DATA_DIR
Restart=on-failure
RestartSec=5s

# Where the management socket lives. systemd creates this before the server
# starts, and removes it when the service stops -- so a crash cannot leave a
# stale socket behind, and the socket cannot outlive the process that served it.
#
# 0750 is the load-bearing part of the whole scheme. Go creates unix sockets
# with 0777 &~ umask and can only chmod them after bind, so for a moment the
# socket itself is world-writable; a directory nobody outside the group can
# traverse means that moment does not matter.
RuntimeDirectory=$RUNTIME_DIR_NAME
RuntimeDirectoryMode=0750

# The server has been observed failing to exit on SIGTERM. Its own shutdown is
# bounded to 5s internally, so anything past that is a goroutine that never
# returned, and waiting is pointless. systemd's default here is 90s, which turns
# a routine restart into a minute and a half of downtime and makes a certificate
# renewal look like an outage. Give it a few seconds, then SIGKILL.
#
# The database is SQLite in WAL mode and every write is committed before the
# request returns, so a hard kill loses nothing that was acknowledged.
TimeoutStopSec=15s
KillMode=mixed

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
# AF_UNIX is here because the management API is a unix socket. Without it the
# server starts, serves OSCAR happily, and fails to bind the management socket
# with a permission error that looks like a filesystem problem and is not.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
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
  Admin socket : $SOCKET_PATH  (group $ADMIN_GROUP)

  Administration goes through benco_admin, on this machine:

    benco_admin user add someone
    benco_admin user list
    benco_admin session list

  Membership of $ADMIN_GROUP is the credential. There is no API token
  and no password: the socket sits in a directory only that group can open, so
  the kernel decides who may administer this server. To grant someone else:

    sudo usermod -aG $ADMIN_GROUP <user>

  Then point BENCchat at $HOSTNAME_FQDN port $OSCAR_PORT, with TLS on.

  Remember the network layer gates ports separately from the host firewall —
  on Oracle Cloud that is the security list for the subnet.
EOF

if [ -n "$NEEDS_RELOGIN" ]; then
  # Say this last, loudly, because it is the one step the installer cannot do
  # for you and the one that makes a correct install look broken.
  #
  # A process's group memberships are fixed when it is created and inherited
  # from its parent. Nothing this script does can add a group to the shell that
  # invoked it -- running `newgrp` here would only make a subshell that dies
  # with the script. So $ADMIN_USER's current shell does not have
  # $ADMIN_GROUP yet, however much /etc/group now says otherwise.
  warn "$ADMIN_USER was just added to $ADMIN_GROUP, but this shell does not have it yet."
  cat <<EOF
     Group membership is set when a process starts, so a shell that was already
     running never picks it up. Log out and back in, or start one that has it:

         newgrp $ADMIN_GROUP

     benco_admin notices this case and retries itself via sg, so it will work
     either way -- but everything else (ls on the socket, your own scripts) will
     report permission denied until you do.
EOF
fi
