#!/bin/sh
set -eu

version="${VERSION:-dev}"
version="${version#v}"
dist="${DIST_DIR:-dist}"
case "$dist" in ""|/|.|..) echo "unsafe DIST_DIR: $dist" >&2; exit 2;; esac
mkdir -p "$dist"
find "$dist" -mindepth 1 -maxdepth 1 -delete

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}
  arch=${target#*/}
  name="warden-${os}-${arch}"
  binary="$dist/warden"
  if [ "$os" = windows ]; then binary="$dist/warden.exe"; fi
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$version" -o "$binary" ./cmd/warden
  if strings "$binary" | grep -F "$(pwd)" >/dev/null 2>&1; then
    echo "$name contains the build path" >&2
    exit 1
  fi
  if [ "$os" = windows ]; then
    (cd "$dist" && zip -q "$name.zip" warden.exe)
    rm "$binary"
  else
    tar -C "$dist" -czf "$dist/$name.tar.gz" warden
    rm "$binary"
  fi
done

rm -f "$dist/warden" "$dist/warden.exe"
(cd "$dist" && sha256sum warden-* > checksums.txt)
[ "$(find "$dist" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) | wc -l)" -eq 6 ]
[ "$(find "$dist" -maxdepth 1 -type f | wc -l)" -eq 7 ]
grep -Eq '^([0-9a-f]{64})  warden-linux-amd64\.tar\.gz$' "$dist/checksums.txt"
echo "verified six release archives for $version"
