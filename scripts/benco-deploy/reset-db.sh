#!/usr/bin/env bash
# Wipe the BENCoscar database and start over.
#
#   sudo ./reset-db.sh
#
# Stops the service, sets the database aside, and starts it again. Migrations
# recreate the schema at boot, so there is nothing to restore or re-import.
#
# THIS DESTROYS EVERY ACCOUNT. Screen names, argon2id password hashes, buddy
# lists, chat rooms, offline messages and every published device key are gone,
# and passwords cannot be recovered from what is removed. Accounts must be
# created again through the management API.
#
#   --keep-accounts       preserve the users table, wipe everything else
#   --clear-connections   drop only AIM buddy connections + their authorizations,
#                         keeping accounts, device keys, identity backups and
#                         rooms. Use this to clear grandfathered (pre-consent)
#                         connections so every add re-runs the authorization flow.
#   --dry-run             show what would happen, change nothing
#   --yes                 skip the confirmation
#
# The database is MOVED (or, for the surgical modes, COPIED) aside first, so a
# mistaken run is recoverable.

set -euo pipefail

DATA_DIR="${DATA_DIR:-/var/lib/bencoscar}"
DB_PATH="${DB_PATH:-$DATA_DIR/oscar.sqlite}"
SERVICE="${SERVICE:-bencoscar}"
API_PORT="${API_PORT:-8080}"

KEEP_ACCOUNTS=0
CLEAR_CONNECTIONS=0
DRY_RUN=0
ASSUME_YES=0

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --keep-accounts) KEEP_ACCOUNTS=1 ;;
    --clear-connections) CLEAR_CONNECTIONS=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    -h|--help) sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1  (try --help)" ;;
  esac
  shift
done

[ "$KEEP_ACCOUNTS" -eq 1 ] && [ "$CLEAR_CONNECTIONS" -eq 1 ] &&
  die "--keep-accounts and --clear-connections are mutually exclusive"

[ "$(id -u)" -eq 0 ] || die "Run this with sudo:  sudo ./reset-db.sh"
[ -f "$DB_PATH" ] || die "No database at $DB_PATH
     Set DB_PATH if it lives elsewhere. If there is no database, the server
     already starts clean."

SIZE="$(du -h "$DB_PATH" | cut -f1)"
ACCOUNTS="?"
if command -v sqlite3 >/dev/null 2>&1; then
  ACCOUNTS="$(sqlite3 "$DB_PATH" 'SELECT COUNT(*) FROM users' 2>/dev/null || echo '?')"
fi

say "BENCoscar database reset"
echo "    service   : $SERVICE"
echo "    database  : $DB_PATH  ($SIZE)"
echo "    accounts  : $ACCOUNTS"
if [ "$CLEAR_CONNECTIONS" -eq 1 ]; then
  echo "    mode      : clear AIM connections only (accounts + keys kept)"
elif [ "$KEEP_ACCOUNTS" -eq 1 ]; then
  echo "    mode      : keep accounts, wipe everything else"
else
  echo "    mode      : full wipe"
fi

if [ "$CLEAR_CONNECTIONS" -eq 1 ]; then
  cat <<'CLEARS'
     Drops every AIM buddy edge and every AIM<->AIM authorization grant, so
     rosters start empty and each future add re-runs the consent flow. Accounts,
     argon2id passwords, published device keys, identity backups, chat rooms and
     ICQ authorizations are all kept. Clients pull their roster from the server
     on sign-on, so buddies simply disappear until re-added; no re-provisioning,
     no first-run setup, no safety-number churn.
CLEARS
fi

if [ "$KEEP_ACCOUNTS" -eq 0 ] && [ "$CLEAR_CONNECTIONS" -eq 0 ]; then
  warn "This destroys every account."
  cat <<'GONE'
     Screen names, password hashes, buddy lists, chat rooms, offline messages
     and every published device key. Passwords are argon2id and cannot be
     recovered, so accounts have to be created again from scratch.

     Clients keep their own keys and will republish them, but each one is a
     brand new device to the server: expect the approval prompts you get on a
     fresh account, and contacts will see safety numbers change.
GONE
fi

if { [ "$KEEP_ACCOUNTS" -eq 1 ] || [ "$CLEAR_CONNECTIONS" -eq 1 ]; } &&
   ! command -v sqlite3 >/dev/null 2>&1; then
  die "this mode needs sqlite3:  apt-get install -y sqlite3"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  say "[dry run] nothing changed"
  exit 0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
  echo
  printf 'Type the service name (%s) to confirm: ' "$SERVICE"
  read -r reply
  [ "$reply" = "$SERVICE" ] || die "cancelled"
fi

# Stop first. SQLite tolerates a file vanishing under a live connection far
# less gracefully than it tolerates a clean shutdown, and the server holds the
# database open for its whole lifetime.
say "Stopping $SERVICE"
systemctl stop "$SERVICE" || warn "service was not running"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$DB_PATH.backup-$STAMP"

if [ "$CLEAR_CONNECTIONS" -eq 1 ]; then
  say "Clearing AIM connections and their authorization grants"
  cp -a "$DB_PATH" "$BACKUP"
  # Two things define an AIM connection: the buddy edge in the feedbag, and the
  # reciprocal rows in contactPreauth that RequiresAuthorization consults. Drop
  # both, scoped to AIM<->AIM (both ends isICQ = 0) so ICQ's real authorization
  # grants are left intact. Group rows (classID = 1) are harmless empty folders
  # and are left alone. Mirrors the grandfather migration's scope, in reverse.
  DELETED="$(sqlite3 "$DB_PATH" <<'SQL'
PRAGMA foreign_keys = ON;
DELETE FROM contactPreauth
 WHERE ownerScreenName      IN (SELECT identScreenName FROM users WHERE isICQ = 0)
   AND authorizedScreenName IN (SELECT identScreenName FROM users WHERE isICQ = 0);
DELETE FROM feedbag
 WHERE classID = 0
   AND screenName IN (SELECT identScreenName FROM users WHERE isICQ = 0);
SELECT changes();
SQL
)"
  echo "    AIM buddy edges + authorizations cleared (feedbag rows removed: $DELETED)"
  echo "    accounts, device keys, identity backups, rooms and ICQ grants kept"
elif [ "$KEEP_ACCOUNTS" -eq 1 ]; then
  say "Preserving accounts, clearing everything else"
  cp -a "$DB_PATH" "$BACKUP"
  # Every other table is derived state that clients rebuild: buddy lists come
  # back from the feedbag, device keys are republished on sign-on, rooms are
  # recreated on demand. The users table is the only thing that cannot be.
  sqlite3 "$DB_PATH" <<'SQL'
PRAGMA foreign_keys = ON;
DELETE FROM deviceKeys;
SQL
  echo "    device keys cleared; accounts kept"
  warn "Buddy lists, rooms and offline messages were NOT cleared by this mode."
else
  say "Setting the database aside"
  mv "$DB_PATH" "$BACKUP"
  # WAL and shared-memory sidecars belong to the old database; leaving them
  # beside a new one invites SQLite to read a journal that does not match.
  rm -f "$DB_PATH-wal" "$DB_PATH-shm" "$DB_PATH-journal"
  echo "    moved to $BACKUP"
fi

say "Starting $SERVICE"
systemctl start "$SERVICE"
sleep 3

if systemctl is-active --quiet "$SERVICE"; then
  say "Running"
else
  warn "Service did not come up. Recent log:"
  journalctl -u "$SERVICE" -n 30 --no-pager
  echo
  echo "To roll back:  sudo systemctl stop $SERVICE && sudo mv '$BACKUP' '$DB_PATH' && sudo systemctl start $SERVICE"
  exit 1
fi

cat <<EOF

$(printf '\033[1;32m==>\033[0m') Done. The old database is kept at:

    $BACKUP

  Roll back with:

      sudo systemctl stop $SERVICE
      sudo mv "$BACKUP" "$DB_PATH"
      sudo systemctl start $SERVICE

EOF

if [ "$KEEP_ACCOUNTS" -eq 0 ] && [ "$CLEAR_CONNECTIONS" -eq 0 ]; then
  cat <<EOF
  Create accounts again (the management API is loopback-only):

      curl -X POST http://127.0.0.1:$API_PORT/user \\
        -H 'Content-Type: application/json' \\
        -d '{"screen_name":"someone","password":"their-password"}'

  Passwords are 8-128 characters.

EOF
fi
