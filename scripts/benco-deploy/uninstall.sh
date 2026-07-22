#!/usr/bin/env bash
# Remove everything install.sh created, so the next install starts from nothing.
#
#   sudo ./uninstall.sh
#
# Undoes install.sh and nothing else: the service and its unit, /etc/bencoscar,
# /var/lib/bencoscar, both binaries, the service user and the admin group. The
# runtime directory and the management socket are systemd's and disappear when
# the service stops.
#
#   --purge-certs   also delete /etc/letsencrypt. Read the warning first.
#   --purge-data    delete the database outright instead of copying it aside.
#   --dry-run       show what would happen, change nothing
#   --yes           skip the confirmation
#
# TLS CERTIFICATES ARE KEPT BY DEFAULT, and that is the important part of this
# script. Let's Encrypt allows five duplicate certificates per registered domain
# per 168 hours, and BENCoscar treats a missing keypair as a startup error rather
# than falling back to cleartext -- so a rebuild that cannot get a certificate is
# a rebuild that cannot start. letsencrypt.sh short-circuits when a live
# certificate already exists, so keeping /etc/letsencrypt makes the reinstall
# free. /etc/letsencrypt/cloudflare.ini holds the API token, too.
#
# The renewal DEPLOY HOOK is removed even though the certificates are kept: it
# installs files owned by the service group, and with the group gone a renewal in
# the gap between uninstall and reinstall would fail. letsencrypt.sh writes it
# again.
#
# Not touched, because install.sh never created them: firewall rules, the DNS
# record, and anything the network layer gates separately.

set -euo pipefail

SERVICE="${SERVICE:-bencoscar}"
SVC_USER="${SVC_USER:-bencoscar}"
ADMIN_GROUP="${ADMIN_GROUP:-bencoscar-admin}"
RUNTIME_DIR_NAME="${RUNTIME_DIR_NAME:-bencoscar}"

PREFIX="${PREFIX:-}"
BIN_DST="${BIN_DST:-$PREFIX/usr/local/bin/bencoscar}"
ADMIN_BIN_DST="${ADMIN_BIN_DST:-$PREFIX/usr/local/bin/benco_admin}"
CONF_DIR="${CONF_DIR:-$PREFIX/etc/bencoscar}"
DATA_DIR="${DATA_DIR:-$PREFIX/var/lib/bencoscar}"
DB_PATH="${DB_PATH:-$DATA_DIR/oscar.sqlite}"
ENV_FILE="$CONF_DIR/bencoscar.env"
UNIT="${UNIT:-$PREFIX/etc/systemd/system/$SERVICE.service}"
LE_DIR="${LE_DIR:-$PREFIX/etc/letsencrypt}"
HOOK="$LE_DIR/renewal-hooks/deploy/bencoscar.sh"
KEEP_DIR="${KEEP_DIR:-$PREFIX/var/backups}"

PURGE_CERTS=0
PURGE_DATA=0
DRY_RUN=0
ASSUME_YES=0

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" -eq 1 ]; then echo "    would: $*"; else "$@"; fi; }

while [ $# -gt 0 ]; do
  case "$1" in
    --purge-certs) PURGE_CERTS=1 ;;
    --purge-data)  PURGE_DATA=1 ;;
    --dry-run)     DRY_RUN=1 ;;
    --yes|-y)      ASSUME_YES=1 ;;
    -h|--help)     sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1  (try --help)" ;;
  esac
  shift
done

[ "$DRY_RUN" -eq 1 ] || [ "$(id -u)" -eq 0 ] || die "Run this with sudo:  sudo ./uninstall.sh"

# --- the LUKS check --------------------------------------------------------
# The optional LUKS bundle bind-mounts the data directory onto an encrypted
# volume. rm -rf on a live mount empties the volume while leaving the mapping
# and the fstab entry behind, which looks like it worked and is not recoverable
# by reinstalling. That bundle has its own uninstaller; use it.
if mountpoint -q "$DATA_DIR" 2>/dev/null; then
  die "$DATA_DIR is a mount point -- this looks like the LUKS bundle.
     Use BENCchat's scripts/benchat-luks/uninstall.sh instead, which unmounts
     the volume and removes the crypttab and fstab entries. Re-run this script
     afterwards if you also want the server itself gone."
fi

# --- what is actually here -------------------------------------------------
HAVE_UNIT=0;  [ -f "$UNIT" ] && HAVE_UNIT=1
HAVE_CONF=0;  [ -d "$CONF_DIR" ] && HAVE_CONF=1
HAVE_DATA=0;  [ -d "$DATA_DIR" ] && HAVE_DATA=1
HAVE_DB=0;    [ -f "$DB_PATH" ] && HAVE_DB=1
HAVE_USER=0;  id "$SVC_USER" >/dev/null 2>&1 && HAVE_USER=1
HAVE_GROUP=0; getent group "$ADMIN_GROUP" >/dev/null 2>&1 && HAVE_GROUP=1
HAVE_CERTS=0; [ -d "$LE_DIR" ] && HAVE_CERTS=1

if [ "$HAVE_UNIT$HAVE_CONF$HAVE_DATA$HAVE_USER$HAVE_GROUP" = "00000" ] &&
   [ ! -x "$BIN_DST" ]; then
  say "Nothing to remove -- no unit, config, data, binary, user or group found."
  exit 0
fi

DB_SIZE="-"
ACCOUNTS="?"
if [ "$HAVE_DB" -eq 1 ]; then
  DB_SIZE="$(du -h "$DB_PATH" | cut -f1)"
  if command -v sqlite3 >/dev/null 2>&1; then
    ACCOUNTS="$(sqlite3 "$DB_PATH" 'SELECT COUNT(*) FROM users' 2>/dev/null || echo '?')"
  fi
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
KEEP="$KEEP_DIR/bencoscar-$STAMP"

say "BENCoscar uninstall"
echo "    service    : $SERVICE"
echo "    unit       : $(if [ "$HAVE_UNIT"  -eq 1 ]; then echo "$UNIT"; else echo '(absent)'; fi)"
echo "    config     : $(if [ "$HAVE_CONF"  -eq 1 ]; then echo "$CONF_DIR"; else echo '(absent)'; fi)"
echo "    data       : $(if [ "$HAVE_DATA"  -eq 1 ]; then echo "$DATA_DIR"; else echo '(absent)'; fi)"
echo "    database   : $(if [ "$HAVE_DB"    -eq 1 ]; then echo "$DB_PATH  ($DB_SIZE, $ACCOUNTS accounts)"; else echo '(absent)'; fi)"
echo "    binaries   : $BIN_DST, $ADMIN_BIN_DST"
echo "    user/group : $SVC_USER / $ADMIN_GROUP"

if [ "$PURGE_DATA" -eq 1 ]; then
  echo "    database   : DELETED, not copied aside (--purge-data)"
elif [ "$HAVE_DB" -eq 1 ] || [ -f "$ENV_FILE" ]; then
  echo "    keeping    : $KEEP"
  echo "                 the database and the env file are copied here first"
fi

if [ "$PURGE_CERTS" -eq 1 ]; then
  warn "This also deletes $LE_DIR."
  cat <<'CERTS'
     Let's Encrypt allows five duplicate certificates per registered domain per
     168 hours. If that limit is already spent, the rebuild gets no certificate,
     and BENCoscar refuses to start without one rather than serving cleartext --
     so the server stays down until the window rolls over. The Cloudflare API
     token in cloudflare.ini goes too, and has to be reissued.

     Keep them unless the certificate itself is what you are trying to replace.
CERTS
elif [ "$HAVE_CERTS" -eq 1 ]; then
  echo "    certs      : KEPT ($LE_DIR)"
  echo "                 letsencrypt.sh reuses them, so the reinstall is free"
fi

warn "Everything the server stored is removed."
cat <<'GONE'
     Screen names, argon2id password hashes, buddy lists, chat rooms, offline
     messages, published device keys and identity backups. Accounts have to be
     provisioned through the management API again, and every client is a brand
     new device to the new server: expect first-run setup and safety numbers
     that change for every contact.
GONE

if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -ne 1 ]; then
  echo
  printf 'Type the service name (%s) to confirm: ' "$SERVICE"
  read -r reply
  [ "$reply" = "$SERVICE" ] || die "cancelled"
fi

# --- stop ------------------------------------------------------------------
# Before anything is moved. SQLite tolerates a clean shutdown far better than a
# file vanishing under a live connection, and the server holds the database open
# for its whole lifetime.
say "Stopping $SERVICE"
run systemctl disable --now "$SERVICE" 2>/dev/null || warn "service was not running or not enabled"

# --- keep what is expensive to retype --------------------------------------
if [ "$PURGE_DATA" -eq 0 ] && { [ "$HAVE_DB" -eq 1 ] || [ -f "$ENV_FILE" ]; }; then
  say "Copying the database and config aside to $KEEP"
  run install -d -m 0700 "$KEEP"
  [ "$HAVE_DB" -eq 1 ] && run cp -a "$DB_PATH" "$KEEP/"
  # The env file holds the advertised hostname and every setting that was tuned
  # by hand -- BENCO_DEVICE_AUTH, LOG_LEVEL, the rate class. install.sh writes a
  # fresh one, so without this copy those choices are gone with no record.
  [ -f "$ENV_FILE" ] && run cp -a "$ENV_FILE" "$KEEP/"
  echo "    (0700, root-owned -- it contains password hashes and identity backups)"
fi

# --- remove ----------------------------------------------------------------
say "Removing the unit"
run rm -f "$UNIT"
run systemctl daemon-reload
run systemctl reset-failed "$SERVICE" 2>/dev/null || true

say "Removing config, data and binaries"
run rm -rf "$CONF_DIR" "$DATA_DIR"
run rm -f "$BIN_DST" "$ADMIN_BIN_DST"

# systemd removes /run/$RUNTIME_DIR_NAME when the service stops, so the socket
# cannot outlive the process that served it. Swept anyway: a unit edited by hand
# to drop RuntimeDirectory would leave it behind, and a stale socket directory
# owned by a group that no longer exists is a confusing thing to reinstall onto.
[ -d "/run/$RUNTIME_DIR_NAME" ] && run rm -rf "/run/$RUNTIME_DIR_NAME"

if [ -f "$HOOK" ]; then
  say "Removing the certbot deploy hook"
  run rm -f "$HOOK"
  echo "    (letsencrypt.sh reinstalls it; left in place it would fail at the"
  echo "     next renewal, since it installs files owned by $SVC_USER)"
fi

if [ "$HAVE_USER" -eq 1 ]; then
  say "Removing the service user"
  run userdel "$SVC_USER" 2>/dev/null || warn "could not remove $SVC_USER -- check for running processes"
fi
if [ "$HAVE_GROUP" -eq 1 ]; then
  say "Removing the admin group"
  # Removing the group also drops every membership in it, so whoever was added
  # with --admin-user has to be added again by the next install.
  run groupdel "$ADMIN_GROUP" 2>/dev/null || warn "could not remove $ADMIN_GROUP"
fi

if [ "$PURGE_CERTS" -eq 1 ] && [ "$HAVE_CERTS" -eq 1 ]; then
  say "Deleting $LE_DIR"
  run rm -rf "$LE_DIR"
fi

# The legacy stunnel sidecar. TLS is terminated in-process now, so this should
# not exist -- but an install that predates that still has it, and it would bind
# the same port the new server wants.
if systemctl list-unit-files 2>/dev/null | grep -q '^benchat-tls'; then
  say "Removing the legacy benchat-tls unit"
  run systemctl disable --now benchat-tls 2>/dev/null || true
fi

if [ "$DRY_RUN" -eq 1 ]; then
  say "[dry run] nothing changed"
  exit 0
fi

say "Done."
cat <<REBUILD

  To rebuild, in this order -- the renewal hook installs files owned by
  $SVC_USER, so the user has to exist before certbot runs again:

      ./build.sh
      sudo HOSTNAME_FQDN=<fqdn> ./install.sh
      sudo HOSTNAME_FQDN=<fqdn> ./letsencrypt.sh
      # then provision accounts through the management API

  install.sh writes a FRESH $ENV_FILE, so anything tuned by hand is back at its
  default -- LOG_LEVEL is info again, and it logs nothing on a successful
  sign-on. Set it to debug before the first sign-on if you want to watch one.
REBUILD

if [ "$PURGE_DATA" -eq 0 ] && [ -d "$KEEP" ]; then
  cat <<KEPT

  The old database and env file are at:

      $KEEP

  Nothing reads them automatically. Delete them once the rebuild is proven --
  the database holds password hashes and identity backups.
KEPT
fi
