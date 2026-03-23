#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
PKG="./cmd/senscan"

VERSION="${VERSION:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo dev)}"
BUILD_TIME="${BUILD_TIME:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}"

mkdir -p "$DIST_DIR"
rm -f "$DIST_DIR"/senscan-*

build() {
  local goos="$1"
  local goarch="$2"
  local ext="${3:-}"
  local output="$DIST_DIR/senscan-${goos}-${goarch}${ext}"

  echo "building ${goos}/${goarch} -> ${output##*/}"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -trimpath -ldflags "$LDFLAGS" -o "$output" "$PKG"
}

build windows amd64 .exe
build linux arm64
build darwin arm64

(cd "$DIST_DIR" && shasum -a 256 senscan-* > checksums.txt)

echo "release artifacts written to $DIST_DIR"
