#!/usr/bin/env bash
# Build a BENCoscar release binary for the server.
#
# Run this on your workstation; it produces a binary to scp to the VPS alongside
# install.sh. Cross-compiling is trivial here because the SQLite driver is pure
# Go (modernc.org/sqlite) and CGO stays off — no cross toolchain needed.
#
# Defaults to linux/arm64. Override for a different box:
#   GOOS=linux GOARCH=amd64 ./build.sh

set -euo pipefail

GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-arm64}"
OUT_DIR="${OUT_DIR:-dist}"

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

cd "$(dirname "$0")/../.."
[ -f go.mod ] || die "run this from inside the BENCoscar checkout"

command -v go >/dev/null 2>&1 || die "go is not installed"

VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
# Reproducible-ish: the build date comes from the commit, not the clock, so
# rebuilding the same commit produces the same binary.
DATE="$(git show -s --format=%cI HEAD 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"

say "Building BENCoscar $VERSION ($COMMIT) for $GOOS/$GOARCH"

mkdir -p "$OUT_DIR"
BIN="$OUT_DIR/bencoscar-$GOOS-$GOARCH"

CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build \
  -trimpath \
  -ldflags "-s -w \
    -X main.version=$VERSION \
    -X main.commit=$COMMIT \
    -X main.date=$DATE" \
  -o "$BIN" ./cmd/server

say "Built $BIN"
ls -lh "$BIN"
echo
echo "Next:"
echo "    scp $BIN <vps>:~/bencoscar"
echo "    scp scripts/benco-deploy/install.sh scripts/benco-deploy/letsencrypt.sh <vps>:~/"
echo "    ssh <vps>"
echo "    sudo HOSTNAME_FQDN=chat.example.com ./install.sh"
