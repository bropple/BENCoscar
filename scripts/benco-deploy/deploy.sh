#!/usr/bin/env bash
# deploy.sh — pull, build and roll over BENCoscar, ON THE SERVER.
#
# This replaces the cross-compile-then-scp dance: the server fetches the public
# repository over HTTPS, builds both binaries itself, and swaps them in. No
# credentials are needed anywhere — the repo is public and read-only here.
#
#   sudo ./deploy.sh
#   sudo ./deploy.sh --branch main
#   sudo ./deploy.sh --dry-run
#
#   --branch NAME   branch to deploy (default benco)
#   --src PATH      source checkout (default /opt/<service>/src)
#   --service NAME  systemd unit (default bencoscar, else ras if that is what
#                   is installed)
#   --force         redeploy even when the branch has nothing new
#   --dry-run       show every step, change nothing
#   --yes, -y       skip the confirmation
#   -h, --help      this text
#
# Root is required: the script writes under /opt and /usr/local/bin and drives
# systemctl. The SERVER itself gains no privileges from this — it keeps running
# as its own unprivileged service account, and this script never touches the
# unit, the environment file, the database, or the certificate. It deploys code.
# Installation is install.sh's job, and if the unit does not exist yet this
# script says so and stops rather than half-installing.
#
# MIGRATIONS: there is no migration step here, deliberately. The server runs its
# migrations itself at startup, so they happen inside the restart below.
#
#   Migration 0036 is DESTRUCTIVE: it drops the v1 deviceKeys table outright
#   (see state/migrations/0036_key_directory.up.sql for why that was acceptable
#   at the time). If the database on this server predates 0036, back it up
#   before the first deploy that carries it. There is no backup-db.sh in this
#   repo — copy the file by hand with the service stopped:
#
#       sudo systemctl stop bencoscar
#       sudo cp -a /var/lib/bencoscar/oscar.sqlite ~/oscar.sqlite.bak
#       sudo systemctl start bencoscar
#
#   Clients keep their own keypairs and republish, so what is lost is server-side
#   v1 key state, not anyone's identity.
#
# ROLLBACK: the binary being replaced is kept next to its replacement as
# <binary>.prev, and this script restores it automatically if the new one fails
# its health check. By hand:
#
#       sudo systemctl stop bencoscar
#       sudo cp -a /usr/local/bin/bencoscar.prev /usr/local/bin/bencoscar
#       sudo systemctl start bencoscar

set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/bropple/BENCoscar.git}"
BRANCH="${BRANCH:-benco}"
SERVICE="${SERVICE:-}"
SRC_DIR="${SRC_DIR:-}"
ADMIN_BIN_DST="${ADMIN_BIN_DST:-/usr/local/bin/benco_admin}"

DRY_RUN=0
ASSUME_YES=0
FORCE=0

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" -eq 1 ]; then printf '    [dry run] %s\n' "$*"; else "$@"; fi; }

while [ $# -gt 0 ]; do
  case "$1" in
    --branch)  shift; BRANCH="${1:-}";  [ -n "$BRANCH" ]  || die "--branch needs a name" ;;
    --src)     shift; SRC_DIR="${1:-}"; [ -n "$SRC_DIR" ] || die "--src needs a path" ;;
    --service) shift; SERVICE="${1:-}"; [ -n "$SERVICE" ] || die "--service needs a name" ;;
    --force)   FORCE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    -h|--help) sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)         die "unknown option: $1  (try --help)" ;;
  esac
  shift
done

# Root is checked even under --dry-run for the systemctl probes below, which
# read unit state — except those are readable unprivileged, so a dry run is
# allowed to proceed without it. That is the whole point of the flag: someone
# should be able to see what this would do before handing it root.
if [ "$DRY_RUN" -eq 0 ]; then
  [ "$(id -u)" -eq 0 ] || die "Run this with sudo:  sudo ./deploy.sh"
fi

# --- 1. Prerequisites ------------------------------------------------------
command -v systemctl >/dev/null 2>&1 || die "This expects systemd. Nothing here knows how to roll over any other init."
command -v git >/dev/null 2>&1 || die "git is not installed:  sudo apt-get install -y git"

# The Go toolchain is NOT installed silently. It is a multi-hundred-megabyte
# dependency and distributions ship versions old enough to fail on this module
# in confusing ways; picking one on the operator's behalf is not this script's
# call to make.
if ! command -v go >/dev/null 2>&1; then
  ARCH="$(uname -m)"
  case "$ARCH" in
    aarch64|arm64) GOARCH_HINT=arm64 ;;
    x86_64|amd64)  GOARCH_HINT=amd64 ;;
    *)             GOARCH_HINT="$ARCH" ;;
  esac
  die "No Go toolchain found, and this script builds on the server.

     Distribution packages are usually too old for this module. Take it from
     upstream instead (linux/$GOARCH_HINT):

         curl -fsSLO https://go.dev/dl/go1.26.5.linux-$GOARCH_HINT.tar.gz
         sudo rm -rf /usr/local/go
         sudo tar -C /usr/local -xzf go1.26.5.linux-$GOARCH_HINT.tar.gz
         echo 'export PATH=\$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh
         export PATH=\$PATH:/usr/local/go/bin

     Check https://go.dev/dl/ for the current release. Then re-run this script.

     If you would rather not put a toolchain on the server at all, the old route
     still works: build.sh on a workstation, scp, install.sh."
fi

GO_VER="$(go env GOVERSION 2>/dev/null | sed 's/^go//' || true)"

# Checked against go.mod rather than against a number written down here, so this
# script does not need editing every time the module moves forward. Called twice:
# once on the checkout as it stands, and again after checking out the target,
# because the target commit is allowed to raise the requirement.
check_go_version() {
  local gomod="$1" want have first
  [ -r "$gomod" ] || return 0
  want="$(sed -n 's/^go \([0-9][0-9.]*\).*/\1/p' "$gomod" | head -n1)"
  have="$(go env GOVERSION 2>/dev/null | sed 's/^go//; s/[^0-9.].*//')"
  [ -n "$want" ] && [ -n "$have" ] || return 0
  first="$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n1)"
  [ "$first" = "$want" ] && return 0
  die "The Go toolchain here is too old for this module.
     installed : go$have
     go.mod    : go$want

     Go can fetch a newer toolchain itself (GOTOOLCHAIN=auto, the default), but
     that needs outbound access to proxy.golang.org, which a locked-down VPS
     often does not have — and a build that silently downloads a compiler is not
     something to discover during a deploy. Install it explicitly:

         https://go.dev/dl/"
}

# --- 2. Which service is installed? ----------------------------------------
# install.sh writes a unit called bencoscar. config/ras.service is the upstream
# unit and names things "ras" instead; a server installed from that is a real
# possibility, so detect rather than assume. Either way the deployment layout is
# read out of the unit itself below, not hardcoded here.
if [ -z "$SERVICE" ]; then
  for candidate in bencoscar ras; do
    if systemctl cat "$candidate" >/dev/null 2>&1; then
      SERVICE="$candidate"
      break
    fi
  done
fi

if [ -z "$SERVICE" ] || ! systemctl cat "$SERVICE" >/dev/null 2>&1; then
  die "No BENCoscar systemd unit found${SERVICE:+ (looked for $SERVICE)}.

     This script deploys code onto an existing installation; it does not
     install one, because doing that halfway is worse than not starting. The
     service account, environment file, admin group, TLS certificate and
     database all come from the installer:

         sudo HOSTNAME_FQDN=chat.example.com ./install.sh
         sudo HOSTNAME_FQDN=chat.example.com ./letsencrypt.sh

     Then come back here. If the unit exists under another name, pass
     --service NAME."
fi

# Everything about the layout comes from the unit, so this script cannot drift
# away from what is actually running.
unit_prop() { systemctl show "$SERVICE" -p "$1" --value 2>/dev/null || true; }

# ExecStart shows as "{ path=/usr/local/bin/bencoscar ; argv[]=... }".
BIN_DST="${BIN_DST:-$(unit_prop ExecStart | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -n1)}"
[ -n "$BIN_DST" ] || die "Could not read ExecStart= from the $SERVICE unit. Set BIN_DST=/path/to/binary."

SVC_USER="$(unit_prop User)"
SVC_USER="${SVC_USER:-root}"

[ -n "$SRC_DIR" ] || SRC_DIR="/opt/$SERVICE/src"

# The management API address, which the health check needs. It may be set in the
# unit (config/ras.service does that) or in an EnvironmentFile (install.sh does
# that), so look in both, unit first.
env_lookup() {
  local name="$1" value="" envfile
  value="$(unit_prop Environment | tr ' ' '\n' | sed -n "s/^$name=//p" | tail -n1)"
  if [ -z "$value" ]; then
    envfile="$(unit_prop EnvironmentFiles | sed -n 's/^\([^ ]*\).*/\1/p' | head -n1)"
    if [ -n "$envfile" ] && [ -r "$envfile" ]; then
      value="$(sed -n "s/^[[:space:]]*$name=//p" "$envfile" | tail -n1 | tr -d '"')"
    fi
  fi
  printf '%s' "$value"
}

API_LISTENER="${API_LISTENER:-$(env_lookup API_LISTENER)}"

say "BENCoscar deploy"
echo "    service     : $SERVICE  (runs as $SVC_USER)"
echo "    repository  : $REPO_URL"
echo "    branch      : $BRANCH"
echo "    source      : $SRC_DIR"
echo "    server bin  : $BIN_DST"
echo "    admin CLI   : $ADMIN_BIN_DST"
echo "    go          : ${GO_VER:-unknown}"
echo "    mgmt API    : ${API_LISTENER:-<not found — health check will be reduced>}"

# --- 3. Fetch --------------------------------------------------------------
if [ -d "$SRC_DIR/.git" ]; then
  say "Updating $SRC_DIR"
  run git -C "$SRC_DIR" fetch --prune origin
elif [ -e "$SRC_DIR" ] && [ -n "$(ls -A "$SRC_DIR" 2>/dev/null || true)" ]; then
  die "$SRC_DIR exists, is not empty, and is not a git checkout.
     Refusing to clone over it. Move it aside or pass --src."
else
  say "Cloning $REPO_URL into $SRC_DIR"
  # Depth is deliberately NOT limited: the version string comes from
  # `git describe --tags`, which needs the tags and enough history to reach one.
  run install -d -m 0755 -o root -g root "$(dirname "$SRC_DIR")"
  run git clone --branch "$BRANCH" "$REPO_URL" "$SRC_DIR"
fi

if [ "$DRY_RUN" -eq 1 ] && [ ! -d "$SRC_DIR/.git" ]; then
  say "[dry run] $SRC_DIR does not exist yet, so there is nothing to compare."
  echo "    A real run would clone it, build, and roll the service over."
  say "[dry run] nothing changed"
  exit 0
fi

check_go_version "$SRC_DIR/go.mod"

# --- 4. Refuse a dirty checkout --------------------------------------------
# Someone editing code on the server is a situation to surface, not to clobber:
# a fetch+reset would silently destroy whatever they were mid-way through, and
# whatever they were doing is probably why the server is behaving oddly.
DIRTY="$(git -C "$SRC_DIR" status --porcelain --untracked-files=no 2>/dev/null || true)"
if [ -n "$DIRTY" ]; then
  warn "The checkout at $SRC_DIR has local modifications:"
  printf '%s\n' "$DIRTY" | sed 's/^/    /'
  die "Refusing to deploy over uncommitted changes.

     Someone has edited tracked files on this server. Find out who and why
     before throwing it away. To discard deliberately:

         sudo git -C $SRC_DIR checkout -- .

     A stash keeps it instead:  sudo git -C $SRC_DIR stash"
fi

# Untracked files are only a warning. Stray files accumulate in a build
# directory and blocking every future deploy on them would be its own outage.
UNTRACKED="$(git -C "$SRC_DIR" ls-files --others --exclude-standard 2>/dev/null | head -n 10 || true)"
if [ -n "$UNTRACKED" ]; then
  warn "Untracked files in $SRC_DIR (ignored, but worth a look):"
  printf '%s\n' "$UNTRACKED" | sed 's/^/    /'
fi

# --- 5. What is about to ship? ---------------------------------------------
CURRENT="$(git -C "$SRC_DIR" rev-parse HEAD 2>/dev/null || echo '')"
TARGET="$(git -C "$SRC_DIR" rev-parse "origin/$BRANCH" 2>/dev/null || true)"
[ -n "$TARGET" ] || die "No branch origin/$BRANCH in $SRC_DIR.
     Available:  git -C $SRC_DIR branch -r"

if [ "$CURRENT" = "$TARGET" ] && [ "$FORCE" -eq 0 ]; then
  # Not an error. Running this on a schedule, or twice by hand, should be a
  # no-op rather than something that has to be explained away.
  say "Already at $(git -C "$SRC_DIR" rev-parse --short HEAD) — nothing to deploy."
  echo "    Use --force to rebuild and reinstall the same commit anyway."
  exit 0
fi

say "Commits to deploy"
if [ -z "$CURRENT" ]; then
  # A checkout with no HEAD at all — a freshly cloned empty repo, or one
  # someone left mid-surgery. There is no range to show, so show the tip.
  warn "The checkout has no HEAD; treating this as a first deploy."
  git -C "$SRC_DIR" log --oneline -n 10 "$TARGET" | sed 's/^/    /'
  COUNT="?"
elif [ "$CURRENT" = "$TARGET" ]; then
  echo "    (none — --force, redeploying $(git -C "$SRC_DIR" rev-parse --short HEAD))"
  COUNT=0
else
  git -C "$SRC_DIR" log --oneline "$CURRENT..$TARGET" | sed 's/^/    /'
  COUNT="$(git -C "$SRC_DIR" rev-list --count "$CURRENT..$TARGET")"
  echo
  echo "    $COUNT commit(s), $(git -C "$SRC_DIR" rev-parse --short "$CURRENT") -> $(git -C "$SRC_DIR" rev-parse --short "$TARGET")"

  # Worth knowing before the restart, because the restart is when they run.
  if git -C "$SRC_DIR" diff --name-only "$CURRENT..$TARGET" | grep -q '^state/migrations/'; then
    warn "This range touches database migrations:"
    git -C "$SRC_DIR" diff --name-only "$CURRENT..$TARGET" | grep '^state/migrations/' | sed 's/^/    /'
    echo "     They run automatically when the service starts. If any of them is"
    echo "     destructive (0036 drops deviceKeys), back the database up first —"
    echo "     see the header of this script."
  fi
fi

if [ "$DRY_RUN" -eq 1 ]; then
  cat <<EOF

    [dry run] Would then:
      1. git -C $SRC_DIR checkout --detach $TARGET
      2. build ./cmd/server and ./cmd/benco_admin into a temp directory
      3. verify both are executables for $(uname -m) and report their versions
      4. systemctl stop $SERVICE
      5. cp -a $BIN_DST $BIN_DST.prev   (rollback copy)
      6. install both new binaries
      7. systemctl start $SERVICE
      8. health check: systemctl is-active, then GET /version on the
         management API${API_LISTENER:+ ($API_LISTENER)}, confirming the commit it reports
      9. on failure, restore $BIN_DST.prev and restart
EOF
  say "[dry run] nothing changed"
  exit 0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
  echo
  printf 'Deploy to %s? [y/N] ' "$SERVICE"
  read -r reply
  case "$reply" in y|Y|yes|YES) ;; *) die "cancelled — nothing was touched" ;; esac
fi

# --- 6. Check out and build to a temp path ---------------------------------
# Detached, not a branch: this checkout is a build input, not somewhere to work.
say "Checking out $TARGET"
git -C "$SRC_DIR" checkout --quiet --detach "$TARGET"

check_go_version "$SRC_DIR/go.mod"

VERSION="$(git -C "$SRC_DIR" describe --tags --always --dirty 2>/dev/null || echo dev)"
COMMIT="$(git -C "$SRC_DIR" rev-parse --short HEAD)"
FULL_COMMIT="$(git -C "$SRC_DIR" rev-parse HEAD)"
# From the commit, not the clock, so rebuilding a commit gives the same binary.
DATE="$(git -C "$SRC_DIR" show -s --format=%cI HEAD 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"

STAGE="$(mktemp -d)"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

say "Building $VERSION ($COMMIT)"
echo "    into $STAGE — the live binaries are not touched until this succeeds"

# Native build; no GOOS/GOARCH, because the machine building is the machine
# running. CGO stays off to match build.sh: the SQLite driver is pure Go, and a
# static binary keeps the hardened unit's filesystem restrictions from mattering.
( cd "$SRC_DIR" && CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags "-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE" \
    -o "$STAGE/bencoscar" ./cmd/server ) \
  || die "Server build failed. Nothing was changed; $SERVICE is still running the old binary."

# The admin CLI ships with the server now. It talks to the management API, whose
# shape changes with the server, so a stale one is a real source of confusion.
( cd "$SRC_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
    -o "$STAGE/benco_admin" ./cmd/benco_admin ) \
  || die "benco_admin build failed. Nothing was changed; $SERVICE is still running the old binary."

# --- 7. Verify the artifacts before they go anywhere near /usr/local -------
# A binary for the wrong architecture installs perfectly and then fails at exec
# with "exec format error", which reads like a corrupted file rather than a
# build mistake. Never replace something that works with something unproven.
verify_binary() {
  local path="$1" name="$2" info arch
  [ -s "$path" ] || die "$name did not produce a file."
  [ -x "$path" ] || die "$name is not executable."

  if command -v file >/dev/null 2>&1; then
    info="$(file -b "$path")"
    arch="$(uname -m)"
    case "$arch:$info" in
      aarch64:*aarch64*|arm64:*aarch64*|x86_64:*x86-64*) ;;
      *) die "$name is not a binary for this machine.
       machine : $arch
       binary  : $info" ;;
    esac
    case "$info" in
      *ELF*executable*|*ELF*shared\ object*) ;;
      *) die "$name is not an ELF executable: $info" ;;
    esac
  else
    warn "file(1) is not installed, so the architecture check was skipped."
  fi

  # Cheapest possible proof that it links and runs on this kernel.
  "$path" --version >/dev/null 2>&1 || "$path" --help >/dev/null 2>&1 \
    || die "$name will not even run: $path --version failed."
}

say "Verifying artifacts"
verify_binary "$STAGE/bencoscar" "server"
verify_binary "$STAGE/benco_admin" "benco_admin"
"$STAGE/bencoscar" --version 2>/dev/null | sed 's/^/    /' || true

# --- 8. Swap ---------------------------------------------------------------
say "Stopping $SERVICE"
systemctl stop "$SERVICE" || warn "service was not running"

PREV_BIN="$BIN_DST.prev"
PREV_ADMIN="$ADMIN_BIN_DST.prev"
HAVE_ROLLBACK=0
OLD_VERSION="(unknown)"

if [ -f "$BIN_DST" ]; then
  OLD_VERSION="$("$BIN_DST" --version 2>/dev/null | tr '\n' ' ' | sed 's/  */ /g' || echo '(unknown)')"
  # cp, not mv: if this script dies between here and the install, the live path
  # still holds a working binary.
  cp -a "$BIN_DST" "$PREV_BIN"
  HAVE_ROLLBACK=1
  echo "    kept the running binary as $PREV_BIN"
else
  warn "No binary at $BIN_DST to keep — there will be nothing to roll back to."
fi
[ -f "$ADMIN_BIN_DST" ] && cp -a "$ADMIN_BIN_DST" "$PREV_ADMIN"

say "Installing"
# Same ownership and mode install.sh uses. This script does not change how
# anything is installed, only what.
install -m 0755 -o root -g root "$STAGE/bencoscar" "$BIN_DST"
install -m 0755 -o root -g root "$STAGE/benco_admin" "$ADMIN_BIN_DST"
echo "    $BIN_DST"
echo "    $ADMIN_BIN_DST"

say "Starting $SERVICE"
systemctl start "$SERVICE" || true

# --- 9. Health check -------------------------------------------------------
# `is-active` alone is not enough. The process can be up and answering nothing:
# the OSCAR listener binds before the database is opened, a migration can fail
# after start, and Restart=on-failure can mask a crash loop as "activating".
# So: the unit is running, AND the management API answers, AND the version it
# reports is the commit we just installed — that last part is what distinguishes
# a successful deploy from an old process that never actually died.

probe_api() {
  case "$API_LISTENER" in
    unix:*)
      # Root traverses the 0750 runtime directory regardless of the admin group,
      # and this script is root, so no group juggling is needed here.
      curl -fsS --max-time 5 --unix-socket "${API_LISTENER#unix:}" \
        http://localhost/version 2>/dev/null
      ;;
    '')
      return 1
      ;;
    *)
      curl -fsS --max-time 5 "http://$API_LISTENER/version" 2>/dev/null
      ;;
  esac
}

health_check() {
  local i body=""

  # Give it room: migrations run during startup and can take a few seconds on a
  # database of any size.
  for i in $(seq 1 30); do
    if systemctl is-active --quiet "$SERVICE"; then
      if [ -z "$API_LISTENER" ]; then
        # No API address to probe. Say so rather than quietly calling a weaker
        # check a pass.
        sleep 2
        systemctl is-active --quiet "$SERVICE" && return 0
        return 1
      fi
      if command -v curl >/dev/null 2>&1; then
        body="$(probe_api || true)"
        if [ -n "$body" ]; then
          printf '    management API answered: %s\n' "$body"
          # The commit is baked in at build time, so an old process still holding
          # the socket reports the OLD commit and is caught here.
          case "$body" in
            *"$COMMIT"*) return 0 ;;
            *) warn "The API answered, but reports a different build than the one just installed."
               echo "     expected commit : $COMMIT"
               echo "     reported        : $body"
               echo "     Something other than the new binary is serving that socket."
               return 1 ;;
          esac
        fi
      else
        # No curl. benco_admin is the only other thing that speaks this socket,
        # and it was just built, so use it — `user list` is read-only.
        if "$ADMIN_BIN_DST" user list --api "$API_LISTENER" >/dev/null 2>&1; then
          echo "    management API answered (via benco_admin user list)"
          echo "    note: curl is not installed, so the build could not be confirmed"
          echo "          from the API. Install curl for a stricter check."
          return 0
        fi
      fi
    fi
    sleep 1
  done
  return 1
}

say "Health check"
if health_check; then
  say "Healthy"
else
  warn "The new build did not come up healthy. Rolling back."
  echo
  echo "Recent log from the failed start:"
  journalctl -u "$SERVICE" -n 40 --no-pager | sed 's/^/    /' || true

  systemctl stop "$SERVICE" || true

  if [ "$HAVE_ROLLBACK" -eq 1 ]; then
    say "Restoring the previous binary"
    install -m 0755 -o root -g root "$PREV_BIN" "$BIN_DST"
    [ -f "$PREV_ADMIN" ] && install -m 0755 -o root -g root "$PREV_ADMIN" "$ADMIN_BIN_DST"
    systemctl start "$SERVICE" || true
    sleep 3
    if systemctl is-active --quiet "$SERVICE"; then
      warn "Rolled back. $SERVICE is running the PREVIOUS build again:"
      echo "     $OLD_VERSION"
    else
      warn "ROLLED BACK AND STILL DOWN. The old binary did not start either."
      echo "     That points at something other than this deploy — a migration that"
      echo "     already ran and is not backwards compatible, a missing certificate,"
      echo "     or a full disk. Look here first:"
      echo "         journalctl -u $SERVICE -n 100 --no-pager"
    fi
  else
    warn "There was no previous binary to restore, so nothing was rolled back."
    echo "     $SERVICE is DOWN. Reinstall a known-good build:"
    echo "         ./build.sh on a workstation, scp it over, then sudo ./install.sh"
  fi

  # The source tree stays on the new commit deliberately: leaving it there is
  # what makes the failure reproducible for whoever debugs it.
  die "Deploy failed and was rolled back. Source is left at $COMMIT in $SRC_DIR for investigation."
fi

# --- 10. Report ------------------------------------------------------------
cat <<EOF

$(printf '\033[1;32m==>\033[0m') Deployed.

  service    : $SERVICE ($(systemctl is-active "$SERVICE"))
  was        : $OLD_VERSION
  now        : $("$BIN_DST" --version 2>/dev/null | tr '\n' ' ' | sed 's/  */ /g')
  commit     : $FULL_COMMIT
  source     : $SRC_DIR (detached at $COMMIT)
  binaries   : $BIN_DST
               $ADMIN_BIN_DST

  Rollback binary kept at $PREV_BIN. To use it by hand:

      sudo systemctl stop $SERVICE
      sudo cp -a $PREV_BIN $BIN_DST
      sudo systemctl start $SERVICE

  Logs:  journalctl -u $SERVICE -f
EOF
