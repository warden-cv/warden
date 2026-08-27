#!/bin/sh
set -eu

root="$(mktemp -d)"
pid=""
cleanup(){ if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi; rm -rf "$root"; }
trap cleanup EXIT INT TERM
mkdir -p "$root/config" "$root/files"
chmod 0755 "$root" "$root/config" "$root/files"

go build -trimpath -o "$root/warden" ./cmd/warden
runner=""
if [ "$(id -u)" -eq 0 ] && command -v setpriv >/dev/null 2>&1 && id nobody >/dev/null 2>&1; then
  uid=$(id -u nobody)
  gid=$(id -g nobody)
  if setpriv --reuid="$uid" --regid="$gid" --clear-groups true 2>/dev/null; then
    chown -R "$uid:$gid" "$root/config" "$root/files"
    runner="setpriv --reuid=$uid --regid=$gid --clear-groups"
  else
    # Rootless containers may prohibit uid changes. Drop all available process
    # capabilities and prohibit gaining new privilege for the same smoke path.
    grep -Eq '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status
    runner="setpriv --no-new-privs"
  fi
fi

# shellcheck disable=SC2086
$runner "$root/warden" -config "$root/config" -root "$root/files" -static "$(pwd)/public" -listen 127.0.0.1:18089 >"$root/warden.log" 2>&1 &
pid=$!
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS http://127.0.0.1:18089/api/setup/status >"$root/status.json"; then ready=1; break; fi
  sleep 0.2
done
[ "$ready" -eq 1 ] || { cat "$root/warden.log" >&2; exit 1; }
grep -q '"required":true' "$root/status.json"
headers=$(curl -fsSI http://127.0.0.1:18089/)
printf '%s' "$headers" | grep -qi '^Content-Security-Policy:'
printf '%s' "$headers" | grep -qi '^X-Content-Type-Options: nosniff'
kill "$pid"
wait "$pid" || true
pid=""
echo "warden least-authority deployment smoke: ok"
