#!/usr/bin/env bash
# push.sh — build BENCoscar HERE and deploy it to a server over SSH.
#
#   ./scripts/benco-deploy/push.sh HOST
#   ./scripts/benco-deploy/push.sh HOST --dry-run
#
#   HOST            ssh destination. Use a ~/.ssh/config alias that carries the
#                   user and key (e.g. `Host benco`), so neither lives in this
#                   repo. Required; there is no default, on purpose.
#   --dry-run       build and upload, then have the server show every step
#                   without changing anything
#   --yes, -y       skip the server's confirmation prompt
#   --force         reinstall even if the server already runs this commit
#   --allow-dirty   build from a tree with uncommitted changes (the binary
#                   then reports a commit it does not actually match)
#   -h, --help      this text
#
# What it does:
#   1. Builds bencoscar + benco_admin for the server's architecture with
#      build.sh, on EXACTLY the Go version in go.mod (GOTOOLCHAIN=go<that>).
#      That is the version CI tests and govulncheck scans; a workstation's newer
#      default toolchain is not, and has shipped its own stdlib vulns before.
#   2. Uploads both binaries and deploy.sh to a fresh private temp dir in the
#      remote user's home.
#   3. Runs `sudo deploy.sh --binaries <dir> --commit <sha>` there. That does
#      the arch check, keeps <binary>.prev, swaps, health-checks that the
#      management API reports this commit, and rolls back on failure.
#   4. Removes the temp dir, whatever happened.
#
# The server needs no Go toolchain and no checkout. It needs sudo for the remote
# user, systemd, and an existing install from install.sh.

set -euo pipefail

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

HOST=""
DEPLOY_ARGS=()
ALLOW_DIRTY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)     DEPLOY_ARGS+=(--dry-run) ;;
    --yes|-y)      DEPLOY_ARGS+=(--yes) ;;
    --force)       DEPLOY_ARGS+=(--force) ;;
    --allow-dirty) ALLOW_DIRTY=1 ;;
    -h|--help)     sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)            die "unknown option: $1  (try --help)" ;;
    *)             [ -z "$HOST" ] || die "only one host, please (got '$HOST' and '$1')"
                   HOST="$1" ;;
  esac
  shift
done

[ -n "$HOST" ] || die "Which server?  ./scripts/benco-deploy/push.sh HOST

     HOST is an ssh destination, ideally a ~/.ssh/config alias, e.g.:

         Host benco
             HostName <server address>
             User ubuntu
             IdentityFile ~/path/to/key
             IdentitiesOnly yes"

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/../.."
[ -f go.mod ] && [ -f "$HERE/deploy.sh" ] && [ -f "$HERE/build.sh" ] \
  || die "run this from inside the BENCoscar checkout"
command -v go >/dev/null 2>&1 || die "go is not installed on this machine"

# --- 1. What is being shipped? ----------------------------------------------
# The commit is stamped into the binary and the health check matches on it, so
# a dirty tree would deploy code that claims to be a commit it is not.
if [ -n "$(git status --porcelain --untracked-files=no)" ] && [ "$ALLOW_DIRTY" -eq 0 ]; then
  git status --short --untracked-files=no | sed 's/^/    /'
  die "Uncommitted changes. Commit them, or pass --allow-dirty to ship them anyway."
fi

COMMIT="$(git rev-parse --short HEAD)"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ -z "$(git branch -r --contains HEAD 2>/dev/null)" ]; then
  warn "$COMMIT is not on any remote branch. The server will run code that is not on GitHub."
fi

GO_WANT="$(sed -n 's/^go \([0-9][0-9.]*\).*/\1/p' go.mod | head -n1)"
[ -n "$GO_WANT" ] || die "could not read the go directive from go.mod"
export GOTOOLCHAIN="go$GO_WANT"

# --- 2. Reach the server and learn its architecture -------------------------
say "Connecting to $HOST"
REMOTE_ARCH="$(ssh -o BatchMode=yes -o ConnectTimeout=15 "$HOST" uname -m)" \
  || die "ssh $HOST failed. Check that \`ssh $HOST\` works on its own first."
case "$REMOTE_ARCH" in
  aarch64|arm64) GOARCH=arm64 ;;
  x86_64|amd64)  GOARCH=amd64 ;;
  *)             die "unsupported server architecture: $REMOTE_ARCH" ;;
esac
echo "    server arch : $REMOTE_ARCH -> linux/$GOARCH"
echo "    commit      : $COMMIT ($BRANCH)"
echo "    toolchain   : $GOTOOLCHAIN (from go.mod)"

# --- 3. Build ---------------------------------------------------------------
OUT_DIR="dist"
GOOS=linux GOARCH="$GOARCH" OUT_DIR="$OUT_DIR" "$HERE/build.sh" | sed -n '/^.*==>/p'
SERVER_BIN="$OUT_DIR/bencoscar-linux-$GOARCH"
ADMIN_BIN="$OUT_DIR/benco_admin-linux-$GOARCH"

BUILT_GO="$(go version "$SERVER_BIN" | awk '{print $2}')"
[ "$BUILT_GO" = "go$GO_WANT" ] || die "built with $BUILT_GO, expected go$GO_WANT"

# --- 4. Upload --------------------------------------------------------------
# A fresh 0700 dir in the remote home, not /tmp: /tmp is sometimes noexec, and
# deploy.sh executes these binaries before installing them.
REMOTE_DIR="$(ssh -o BatchMode=yes "$HOST" 'mktemp -d "$HOME/.bencoscar-push.XXXXXX"')" \
  || die "could not create a temp directory on $HOST"
cleanup() { ssh -o BatchMode=yes "$HOST" "rm -rf '$REMOTE_DIR'" 2>/dev/null || true; }
trap cleanup EXIT

say "Uploading to $HOST:$REMOTE_DIR"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"; cleanup' EXIT
cp "$SERVER_BIN" "$STAGE/bencoscar"
cp "$ADMIN_BIN"  "$STAGE/benco_admin"
cp "$HERE/deploy.sh" "$STAGE/deploy.sh"
scp -q "$STAGE/bencoscar" "$STAGE/benco_admin" "$STAGE/deploy.sh" "$HOST:$REMOTE_DIR/"

# --- 5. Deploy --------------------------------------------------------------
# -t so sudo can prompt for a password and deploy.sh can ask for confirmation.
say "Running deploy.sh on $HOST"
set +e
ssh -t "$HOST" sudo bash "$REMOTE_DIR/deploy.sh" \
  --binaries "$REMOTE_DIR" --commit "$COMMIT" "${DEPLOY_ARGS[@]}"
RC=$?
set -e

[ "$RC" -eq 0 ] || die "deploy.sh on $HOST exited $RC (see above). Temp files are being removed."
