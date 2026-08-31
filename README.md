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

Open `http://127.0.0.1:8080`. Explorer and Terminal start in the server user's home directory, while the default Explorer/Editor filesystem boundary remains `/`, so the root breadcrumb can navigate to the whole machine. Use `--root /some/subtree` (or `WARDEN_FILE_ROOT`) when you intentionally want a narrower **file-management** view. This does not sandbox the PTY shell; terminal privilege must be controlled separately when Warden gains user/role levels.

Warden binds to loopback by default. Loopback development automatically uses a non-Secure session cookie so plain `http://127.0.0.1` works correctly. Non-loopback listeners default to Secure cookies; behind an HTTPS reverse proxy enable `WARDEN_TRUST_PROXY=true`; Warden accepts forwarded scheme/client headers only from a loopback proxy and marks HTTPS sessions Secure.

## Run as a systemd user service

Run Warden in the foreground with `warden` or `warden serve`. To keep it running without a terminal, install a per-user systemd unit:

```sh
warden service install            # --config, --listen, --root accepted
warden service status
warden service logs               # or: warden service logs --follow
warden service restart
warden service uninstall          # stops the service but keeps all Warden configuration, accounts and databases
```

The user unit is written to `~/.config/systemd/user/warden.service` and managed with `systemctl --user` and `journalctl --user-unit warden.service`. `service install` resolves the executable to a stable absolute path, refuses empty, relative or transient paths, writes the unit atomically, reloads systemd, and enables and starts the service. An existing unit that is not managed by Warden is never overwritten or removed silently. `warden service status` reports enabled/running state, PID, version, listen address and a live health check, and exits nonzero when the service is failed or missing.

`service install --system` (system-wide units) is a documented follow-up and is not yet supported; user mode is the default.

### GitHub CLI authentication and the multi-user boundary

Warden is multi-user and intentionally does **not** inherit the host account's GitHub CLI authentication for every account. Agent subprocesses isolate `XDG_CONFIG_HOME` for OpenCode, so `gh` finds no configuration by default — this is the desired default-deny behavior. To grant one account access to the host GitHub CLI deliberately, set that account's environment in **System → Access → Accounts → that account → Environment overrides**:

```text
GH_CONFIG_DIR=/home/nick/.config/gh
```

Only that account's agent (and terminal) subprocesses receive the value; other accounts remain isolated. `GH_HOST` can be added the same way if needed. This grants the selected Warden account the GitHub permissions of the Warden service OS user, so only grant it to accounts you trust with that authority. Token values are never displayed or written to the audit log or transcript.

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
