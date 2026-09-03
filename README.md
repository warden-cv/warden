# Warden

Warden is a dark, security-first web console for Linux servers. Nift owns the frontend build; a small Go service owns authentication, monitoring, filesystem operations and the interactive PTY terminal.

## v1 development slice

- Secure session login with rate limiting, CSRF protection and audit events.
- Live Linux monitor backed by `/proc` and `statfs`, with browser-rendered history graphs.
- Dedicated file explorer with size/modified columns, multi-select operations, create/delete/rename/copy/move/upload/download, ZIP compress/extract, and inline image/video/audio preview.
- Separate VS Code-style editor workspace with a resizable file browser, explicit open/close workspace lifecycle, one-click “Open as Workspace” from Explorer, multi-file tabs, syntax highlighting, pale-green occurrence highlighting, Ctrl+D next-occurrence multi-editing, Ctrl+Shift+S save-all, undo/redo for editor multi-edits, atomic saves, permission preservation, searchable browsing without a workspace, undoable workspace-wide search/replace with regex support, and a bounded Git Source Control tab for status/stage/unstage/commit when the workspace root is a repository.
- Interactive Linux PTY over an authenticated WebSocket, including common ANSI/SGR colour preservation.
- Dark mode only by design.

## Build the frontend

```sh
nift build
```

Warden intentionally keeps Nift as the build-time frontend layer. The Go backend serves the generated output in `public/`.

## Build the server

```sh
go build -o warden ./cmd/warden
```

Create a password hash (the cleartext password is not stored):

```sh
./warden hash-password 'choose-a-strong-password'
```

Then run Warden:

```sh
export WARDEN_PASSWORD_HASH='pbkdf2-sha256$...'
./warden
```

Open `http://127.0.0.1:7332`. Explorer and Terminal start in the server user's home directory, while the default Explorer/Editor filesystem boundary remains `/`, so the root breadcrumb can navigate to the whole machine. Use `--root /some/subtree` (or `WARDEN_FILE_ROOT`) when you intentionally want a narrower **file-management** view. This does not sandbox the PTY shell; terminal privilege must be controlled separately when Warden gains user/role levels.

Warden binds to loopback by default. Loopback development automatically uses a non-Secure session cookie so plain `http://127.0.0.1` works correctly. Non-loopback listeners default to Secure cookies; behind an HTTPS reverse proxy enable `WARDEN_TRUST_PROXY=true`; Warden accepts forwarded scheme/client headers only from a loopback proxy and marks HTTPS sessions Secure.

The listener is configured with `--host`/`--port` and the `WARDEN_HOST`/`WARDEN_PORT` environment variables, in that precedence order:

```sh
warden                        # 127.0.0.1:7332
warden --port 7402            # 127.0.0.1:7402
WARDEN_PORT=7402 warden       # 127.0.0.1:7402
warden --host 0.0.0.0 --port 7402
```

Loopback (`127.0.0.1`) is recommended behind a reverse proxy. Binding `0.0.0.0` exposes Warden on all IPv4 interfaces and should only be deliberate. IPv6 hosts are accepted and bracketed automatically. Ports must be integers from 1 through 65535; an invalid or empty value fails rather than silently falling back. The legacy `--listen` flag and `WARDEN_LISTEN` environment variable remain accepted and cannot be combined with `--host`/`--port`. The fresh default changed from `8080` to `7332`; an existing `config.json` remains the durable source of truth, so installed instances keep their recorded listener until deliberately reinstalled.

## Run as a systemd user service

Run Warden in the foreground with `warden` or `warden serve`. To keep it running without a terminal, install a per-user systemd unit:

```sh
warden service install            # --host, --port, --config, --root accepted
warden service install --port 7402  # install on 127.0.0.1:7402
warden service status
warden service logs               # or: warden service logs --follow
warden service restart
warden service uninstall          # stops the service but keeps all Warden configuration, accounts and databases
```

The user unit is written to `~/.config/systemd/user/warden.service` and managed with `systemctl --user` and `journalctl --user-unit warden.service`. `service install` resolves the executable to a stable absolute path, refuses empty, relative or transient paths, and writes the unit atomically with a versioned integrity header. It records the resolved host and port directly in the unit command, so the selected listener survives login, restart and reboot. It accepts `--host`/`--port` (defaulting to `127.0.0.1:7332` or the current `WARDEN_HOST`/`WARDEN_PORT` values), plus the legacy single-address `--listen`/`WARDEN_LISTEN`, `--config`, `--root`. An existing unit that is not managed by Warden is never overwritten or removed silently. Install is transactional: the prior managed unit bytes are preserved, prior systemd enablement and activity are inspected before mutation, only exactly-recreatable states are accepted (`enabled`, `enabled-runtime`, `disabled` enablement × `active`, `inactive` and start-limited `failed` activity; masked enablement and non-restorable activity such as `dead`, `reloading`, `activating` or `unknown` are refused before mutation — unmask or stop/restart first), and rollback reproduces the exact prior enablement and activity states, distinguishing persistent from runtime enablement. A byte-identical unit already enabled and active is a genuine no-op, but it still must pass the same bounded health verification; an unchanged unit that is inactive or disabled receives only the lifecycle steps needed, and a changed configuration reloads systemd and restarts the service. A failed fresh install is stopped and disabled while the unit is still loaded, then removed and systemd is reloaded. Install does not report success until the unit is active and answers the public, read-only `/api/setup/status` endpoint with Warden's JSON contract within a bounded deadline, so an active-but-wedged process or a foreign process occupying the listener fails (and rolls back) instead of being reported as healthy.

The generated unit uses the approved finite crash-loop policy (`StartLimitIntervalSec=60`, `StartLimitBurst=5` in `[Unit]`, `Restart=on-failure`, `RestartSec=3` in `[Service]`), so a genuinely crashing process is rate-limited and reaches `failed`. Deliberate recovery is always available: `service start`, `service restart` and `service install` clear the accumulated start-limit failure with `reset-failed` immediately before activating, and a `reset-failed` failure is surfaced rather than swallowed. `service stop` verifies the service actually stopped, and `warden service status` reports enabled/running state, PID, version, listen address and a live health check, and exits nonzero when the service is failed or missing.

`service install --system` (system-wide units) is a documented follow-up and is not yet supported; user mode is the default.

### Persistence and lingering

The installed service runs independently of the terminal that launched it. Closing that terminal does not stop the service; `warden service uninstall` (or `systemctl --user stop warden.service`) is how you stop it deliberately.

The unit belongs to your OS user's systemd user manager, so it normally starts when that manager starts (your first login or boot, depending on the distribution). If Warden should keep running after you log out, or start at boot before any interactive login, the user manager itself must be allowed to run without a session — that is what *lingering* enables:

```sh
loginctl show-user "$USER" -p Linger
loginctl enable-linger "$USER"
```

Warden never enables lingering automatically, because it changes what the host runs without a login session — enable it deliberately only when unattended operation is actually required. The recorded unit also contains the absolute executable path that was current at install time; moving or deleting that executable breaks the service until you reinstall.

### GitHub CLI authentication and the multi-user boundary

Warden is multi-user and intentionally does **not** inherit the host account's GitHub CLI authentication for every account. Agent subprocesses isolate `XDG_CONFIG_HOME` for OpenCode, so `gh` finds no configuration by default — this is the desired default-deny behavior. To grant one account access to the host GitHub CLI deliberately, set that account's environment in **System → Access → Accounts → that account → Environment overrides**:

```text
GH_CONFIG_DIR=/home/nick/.config/gh
```

Only that account's agent (and terminal) subprocesses receive the value; other accounts remain isolated. Warden also scrubs any `GH_CONFIG_DIR`, `GH_TOKEN`, `GITHUB_TOKEN` or `GH_HOST` present in Warden's own inherited environment before applying account policy, so credentials carried by the terminal or service environment are never inherited globally by accident — they must be re-granted explicitly per account. `GH_HOST` can be added the same way if needed. This grants the selected Warden account the GitHub permissions of the Warden service OS user, so only grant it to accounts you trust with that authority. Token values are never displayed or written to the audit log or transcript.

Because a user service runs as your OS user, the GitHub token stored in the login keyring remains reachable when that keyring is unlocked. A future system-wide service would run under a dedicated account with no login keyring, so GitHub CLI authentication there would need `gh auth login` for that account or an explicit `GH_TOKEN`/`GITHUB_TOKEN` in its environment.

## Security boundary in this slice

Warden is intentionally a privileged application. This first slice establishes rather than hand-waves its boundaries:

- no default password or embedded secret;
- server-side sessions; browser stores only an HttpOnly session cookie;
- state-changing API calls require a per-session CSRF token;
- authentication attempts are rate-limited per client address;
- WebSocket terminal upgrade requires an authenticated session, matching Origin and CSRF token;
- every Explorer/Editor filesystem path is resolved inside one configured file-management root, including symlink resolution;
- that file root is not misrepresented as a terminal sandbox: the PTY runs with the Warden process user's OS authority;
- editor saves are temporary-file + fsync + atomic rename and preserve existing mode bits;
- privileged actions are written to `warden-audit.log` with mode `0600`;
- static responses receive restrictive CSP/frame/referrer/content-type headers.

The BH00-BH17 hardening campaign is complete. Its executable evidence, limits and retained risks are recorded in `HARDENING-CHECKPOINTS.md`, `docs/security/` and the public Battle Tested page. This is evidence for the tested candidate, not a universal claim that Warden or its deployment environment is vulnerability-free.

## Product direction

Warden v1 focuses on authenticated monitoring, a full filesystem explorer, workspace-oriented code/text editing with bounded Git source control, interactive PTY terminals, durable coding-agent sessions, alerts and revisioned website management. The System submenu provides structured administration for certificates, cron, Docker, fail2ban, firewall, services, SSH and users. Internet-facing deployments still require a dedicated OS account, TLS reverse proxy, tested backups and deliberate capability assignment.


## Install

Release binaries embed the Nift-built frontend. On Linux or macOS, install per-user with `curl -fsSL https://warden-deck.github.io/install.sh | sh`, or system-wide with `curl -fsSL https://warden-deck.github.io/install.sh | sudo sh -s -- --system`. `go install github.com/warden-app/warden/cmd/warden@latest` is also supported.
