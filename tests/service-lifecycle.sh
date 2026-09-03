#!/bin/sh
# Real systemd user-service lifecycle exercise for Warden.
#
# Exercises the full service contract against a genuine systemd user manager:
#   fresh install -> daemon reload -> enable/start -> active-state verification
#   -> Warden-specific health verification (exact identity contract) -> status
#   -> stop -> start -> restart (CLI-verified) -> changed reinstall ->
#   special-path runtime identity (quote/backslash/space/percent args + cwd) ->
#   injected start-limit failure and reset-failed recovery -> install-time
#   health-gate failure (foreign JSON server) -> retry -> uninstall -> reinstall
#   after uninstall -> final uninstall.
#
# The generated unit is additionally validated with `systemd-analyze --user
# verify` while it is installed, so a malformed directive fails this script
# rather than the user's next `warden service install`.
#
# The exercise ALWAYS runs in an isolated environment: a private temporary
# HOME, XDG_CONFIG_HOME, XDG_RUNTIME_DIR and session D-Bus bus, plus an
# isolated systemd user manager that this invocation spawns and terminates.
# It never touches the ambient user manager, a developer's real
# ~/.config/systemd/user directory, a real warden installation or real data,
# so no force flag exists. Every path is collision-resistant under a fresh
# mktemp base and cleanup removes only artifacts created by this invocation.
set -eu

die() { echo "service-lifecycle: $*" >&2; exit 1; }

# Capture the source binary before HOME is isolated. The CI job builds it to
# the default location; WARDEN_LIFECYCLE_BIN overrides it.
BIN_SOURCE=${WARDEN_LIFECYCLE_BIN:-"$HOME/.warden-lifecycle-bin/warden"}
[ -x "$BIN_SOURCE" ] || die "warden binary not found at $BIN_SOURCE"

# Collision-resistant private base for every path this invocation creates. The
# base lives under the real HOME (never os.TempDir) so the warden binary it
# holds is a "stable" path that `service install` accepts, and a unique mktemp
# name means a concurrent invocation never collides. Cleanup removes it wholly.
BASE=$(mktemp -d "$HOME/.warden-lifecycle.XXXXXX")
WORK="$BASE/work"
mkdir -p "$WORK"
ISOLATED_HOME="$BASE/home"
mkdir -p "$ISOLATED_HOME"
XDG_CONFIG_HOME="$BASE/xdg-config"
mkdir -p "$XDG_CONFIG_HOME"
XDG_RUNTIME_DIR="$BASE/runtime"
mkdir -p "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"

export HOME="$ISOLATED_HOME"
export XDG_CONFIG_HOME
export XDG_RUNTIME_DIR

# The unit and probe live in the isolated user config directory.
UNIT_DIR="$XDG_CONFIG_HOME/systemd/user"
UNIT="$UNIT_DIR/warden.service"
mkdir -p "$UNIT_DIR"

BIN="$BASE/bin/warden"
mkdir -p "$BASE/bin"
cp "$BIN_SOURCE" "$BIN"
chmod +x "$BIN"
cp "$BIN" "$BIN.save"

cd "$WORK"

PORT=${WARDEN_LIFECYCLE_PORT:-$(( 10000 + ($$ % 20000) ))}
CONFIG="$BASE/config"
mkdir -p "$CONFIG"
ROOT="$BASE/root"
mkdir -p "$ROOT"
CRASH="$WORK/crash.sh"
cat > "$CRASH" <<'SH'
#!/bin/sh
exit 1
SH
chmod +x "$CRASH"

DBUS_PID=0
SYSTEMD_PID=0
BLOCKER=

overwrite_bin() { # replace $BIN atomically, retrying past a transient ETXTBSY
  for _i in $(seq 1 30); do
    cp "$CRASH" "$BIN" 2>/dev/null && return 0
    sleep 0.2
  done
  die "cannot replace the installed binary at $BIN (still executing?)"
}
restore_bin() {
  for _i in $(seq 1 30); do
    cp "$BIN.save" "$BIN" 2>/dev/null && return 0
    sleep 0.2
  done
  die "cannot restore the installed binary at $BIN"
}
cleanup() {
  # Stop what the isolated manager is running, then terminate the daemons this
  # invocation spawned, then remove only the private base directory.
  systemctl --user stop warden.service >/dev/null 2>&1 || true
  systemctl --user disable warden.service >/dev/null 2>&1 || true
  systemctl --user stop warden-rtid.service >/dev/null 2>&1 || true
  [ -n "$BLOCKER" ] && { kill "$BLOCKER" 2>/dev/null || true; }
  if [ -n "$SYSTEMD_PID" ] && [ "$SYSTEMD_PID" != 0 ]; then
    kill "$SYSTEMD_PID" 2>/dev/null || true
    wait "$SYSTEMD_PID" 2>/dev/null || true
  fi
  if [ -n "$DBUS_PID" ] && [ "$DBUS_PID" != 0 ]; then
    kill "$DBUS_PID" 2>/dev/null || true
    wait "$DBUS_PID" 2>/dev/null || true
  fi
  # systemd leaves a read-only "inaccessible" directory tree in the runtime
  # dir with mode-000 special files; make it removable before removing the base.
  chmod -R u+rwX "$XDG_RUNTIME_DIR" 2>/dev/null || true
  rm -rf "$BASE"
}
trap cleanup EXIT

# Boot an isolated session D-Bus and systemd user manager on the private
# runtime directory. systemctl --user resolves the manager through the exported
# XDG_RUNTIME_DIR/DBUS_SESSION_BUS_ADDRESS, so nothing here touches the ambient
# user manager.
SYSTEMD_BIN=$(command -v systemd 2>/dev/null || true)
[ -n "$SYSTEMD_BIN" ] || SYSTEMD_BIN=/usr/lib/systemd/systemd
[ -x "$SYSTEMD_BIN" ] || die "cannot find a systemd user manager binary to boot"

# Boot an isolated session D-Bus and systemd user manager on the private
# runtime directory. systemctl --user resolves the manager through the exported
# XDG_RUNTIME_DIR/DBUS_SESSION_BUS_ADDRESS, so nothing here touches the ambient
# user manager. A single boot failure is a hard failure: an environment that
# cannot host an isolated user manager (for example a CI runner that already
# has an ambient user manager) must be reported rather than retried into a
# false pass.
SYSTEMD_BIN=$(command -v systemd 2>/dev/null || true)
[ -n "$SYSTEMD_BIN" ] || SYSTEMD_BIN=/usr/lib/systemd/systemd
[ -x "$SYSTEMD_BIN" ] || die "cannot find a systemd user manager binary to boot"

DBUS_ADDR="unix:path=$XDG_RUNTIME_DIR/bus"
export DBUS_SESSION_BUS_ADDRESS="$DBUS_ADDR"
dbus-daemon --session --address="$DBUS_ADDR" >"$WORK/dbus-boot.log" 2>&1 &
DBUS_PID=$!
"$SYSTEMD_BIN" --user >"$WORK/systemd-boot.log" 2>&1 &
SYSTEMD_PID=$!
# A freshly booted user manager can take tens of seconds to become ready on a
# loaded CI runner, so the readiness deadline is generous (60s).
ready=0
for _i in $(seq 1 300); do
  systemctl --user is-system-running >/dev/null 2>&1 && { ready=1; break; }
  sleep 0.2
done
if [ "$ready" != 1 ]; then
  BOOTLOG=$(tail -c 2000 "$WORK/systemd-boot.log" 2>/dev/null | tr '\n' ' ' | cut -c1-1200)
  die "isolated user manager did not become ready${BOOTLOG:+ (systemd --user: $BOOTLOG)}"
fi

wait_active() {
  for _i in $(seq 1 60); do
    case "$(systemctl --user is-active warden.service 2>/dev/null)" in
      active) return 0 ;;
      failed) die "warden.service entered failed state during $1" ;;
    esac
    sleep 0.5
  done
  die "warden.service did not become active during $1"
}

install() { "$BIN" service install --config "$CONFIG" --root "$ROOT" --port "$PORT"; }
install2() { "$BIN" service install --config "$CONFIG" --root "$ROOT" --port "$((PORT + 1))"; }

echo "== fresh install =="
install
wait_active "install"

echo "== daemon reload =="
systemctl --user daemon-reload

echo "== enablement =="
[ "$(systemctl --user is-enabled warden.service)" = "enabled" ] || die "warden.service not enabled"

echo "== systemd-analyze --user verify the generated unit =="
[ -f "$UNIT" ] || die "generated unit not found at $UNIT"
systemd-analyze --user verify "$UNIT"

echo "== active-state verification =="
[ "$(systemctl --user is-active warden.service)" = "active" ] || die "warden.service not active"

echo "== Warden-specific health verification =="
# The recorded listener must answer /api/setup/status with the exact Warden
# identity contract (ok:true, service:"warden", required:<bool>), not merely
# 2xx JSON.
if command -v python3 >/dev/null 2>&1; then
  python3 - "$PORT" <<'PY' || die "health endpoint did not return the Warden identity contract"
import json, sys, urllib.request
port = sys.argv[1]
with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/setup/status", timeout=5) as r:
    data = json.load(r)
assert data.get("ok") is True, data
assert data.get("service") == "warden", data
assert isinstance(data.get("required"), bool), data
PY
else
  "$BIN" service status >/dev/null
fi

echo "== status (with health check) =="
"$BIN" service status >/dev/null

echo "== stop / start / restart (CLI performs its own readiness verification) =="
"$BIN" service stop
[ "$(systemctl --user is-active warden.service)" = "inactive" ] || die "warden.service not stopped"
"$BIN" service start
wait_active "start"
"$BIN" service restart
wait_active "restart"

echo "== changed reinstall restarts onto the new listener =="
install2 >/dev/null
wait_active "changed reinstall"
grep -q -- "--port\" \"$((PORT + 1))\"" "$UNIT" || die "reinstall did not record the new port"
install >/dev/null
wait_active "reinstall back to the original listener"

echo "== special-path runtime identity (WorkingDirectory + ExecStart args) =="
SPROBE="$ROOT/special probe 100%"
mkdir -p "$SPROBE"
SPROUT="$ROOT/probe.out"
cat > "$ROOT/emit.sh" <<'SH'
#!/bin/sh
out="$1"
shift
pwd > "$out"
for a in "$@"; do printf '[%s]\n' "$a" >> "$out"; done
SH
chmod +x "$ROOT/emit.sh"
# '%' must be doubled in the unit so systemd does not treat it as a specifier.
SPROBE_ESCAPED=$(printf '%s' "$SPROBE" | sed 's/%/%%/g')
# Build the unit with printf so the ExecStart backslash escapes reach systemd
# verbatim (an unquoted heredoc would collapse them and change the runtime args).
{
  printf '[Unit]\nDescription=runtime path identity probe\n\n[Service]\nType=oneshot\n'
  printf 'ExecStart=%s "%s" "arg with \\"quote" "back\\\\slash"\n' "$ROOT/emit.sh" "$SPROUT"
  printf 'WorkingDirectory=%s\n' "$SPROBE_ESCAPED"
} > "$UNIT_DIR/warden-rtid.service"
systemctl --user daemon-reload
systemctl --user start warden-rtid.service
systemctl --user stop warden-rtid.service
rm -f "$UNIT_DIR/warden-rtid.service"
systemctl --user daemon-reload
{
  read -r wdline
  read -r arg1
  read -r arg2
} < "$SPROUT"
[ "$wdline" = "$SPROBE" ] || die "WorkingDirectory resolved differently at runtime: '$wdline' != '$SPROBE'"
[ "$arg1" = '[arg with "quote]' ] || die "quote-containing argument changed at runtime: '$arg1'"
[ "$arg2" = '[back\slash]' ] || die "backslash-containing argument changed at runtime: '$arg2'"
rm -f "$SPROUT" "$ROOT/emit.sh"

echo "== injected start-limit failure and reset-failed recovery =="
"$BIN" service stop >/dev/null
overwrite_bin
for _i in $(seq 1 12); do
  systemctl --user restart warden.service >/dev/null 2>&1 || true
done
state=$(systemctl --user is-active warden.service 2>/dev/null || true)
echo "post-crash-loop state: $state"
[ "$state" = "failed" ] || die "expected start-limit 'failed' state after crash loop, got '$state'"
# The CLI's own activation must refuse to report success while the service
# crashes, proving `service start` performs its own readiness verification.
if "$BIN" service start >/dev/null 2>&1; then
  die "service start reported success for a crashing service"
fi
restore_bin
# Reinstall over the failed unit must clear the start-limit state (reset-failed)
# and bring the service back to active.
install >/dev/null
wait_active "reinstall recovery"
[ "$(systemctl --user is-active warden.service)" = "active" ] || die "reinstall did not recover the service"
"$BIN" service restart
wait_active "CLI restart after recovery"

echo "== install-time health-gate failure (foreign JSON server on port) then retry =="
"$BIN" service uninstall >/dev/null
if command -v python3 >/dev/null 2>&1; then
  # A foreign process occupies the configured listener and answers 200 with a
  # plausible setup-shaped JSON body ({"required":...}) that is NOT the Warden
  # identity contract. It must not be able to impersonate Warden: the health
  # gate rejects the foreign body and the warden process cannot bind, so the
  # install fails and leaves a retryable state.
  cat > "$ROOT/foreign.py" <<'PY'
import http.server, json, os
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"required": False, "legacyPasswordRequired": False,
                           "tokenRequired": True, "googleEnabled": False}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.HTTPServer(('127.0.0.1', int(os.environ['PORT'])), H).serve_forever()
PY
  PORT="$PORT" python3 "$ROOT/foreign.py" &
  BLOCKER=$!
  sleep 0.6
  if "$BIN" service install --config "$CONFIG" --root "$ROOT" --port "$PORT" >/dev/null 2>&1; then
    kill "$BLOCKER" 2>/dev/null || true
    die "install succeeded although a foreign JSON server occupied the listener (health gate must reject impersonation)"
  fi
  kill "$BLOCKER" 2>/dev/null || true
  wait "$BLOCKER" 2>/dev/null || true
  BLOCKER=
  [ -e "$UNIT" ] && die "failed health-gate install left the unit installed (state not retryable)"
  # The port is free again: a fresh install must succeed. The service is left
  # installed for the uninstall section below.
  install >/dev/null
  wait_active "install retry after health-gate failure"
else
  echo "python3 unavailable; skipping port-conflict health-gate exercise"
fi

echo "== uninstall =="
"$BIN" service uninstall >/dev/null
[ -e "$UNIT" ] && die "unit still present after uninstall"
systemctl --user is-active warden.service >/dev/null 2>&1 && die "warden.service still loaded after uninstall"
leftover=0
for f in "$UNIT_DIR"/.warden.service.unit-backup-*; do
  [ -e "$f" ] || continue
  leftover=1
  break
done
[ "$leftover" = 0 ] || die "uninstall left a backup artifact behind"

echo "== reinstall after uninstall (retryable fresh state) =="
install >/dev/null
wait_active "fresh reinstall"
"$BIN" service uninstall >/dev/null

echo "service-lifecycle: ok"