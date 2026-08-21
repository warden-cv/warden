# Warden

Warden is a dark, security-first web console for Linux servers. Nift owns the frontend build; a small Go service owns authentication, monitoring, filesystem operations and the interactive PTY terminal.

## v1 development slice

- Secure session login with rate limiting, CSRF protection and audit events.
- Live Linux monitor backed by `/proc` and `statfs`, with browser-rendered history graphs.
- Dedicated file explorer with size/modified columns, multi-select operations, create/delete/rename/copy/move/upload/download, ZIP compress/extract, and inline image/video/audio preview.
- Separate VS Code-style editor workspace with its own file browser, multi-file tabs, syntax highlighting, native Ctrl+Z undo/redo behavior, atomic saves, permission preservation, and workspace-wide search/replace with regex support.
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
./warden --root "$HOME"
```

Open `http://127.0.0.1:8080`.

Warden binds to loopback by default. Loopback development automatically uses a non-Secure session cookie so plain `http://127.0.0.1` works correctly. Non-loopback listeners default to Secure cookies; behind an HTTPS reverse proxy set `WARDEN_SECURE_COOKIES=true` explicitly.

## Security boundary in this slice

Warden is intentionally a privileged application. This first slice establishes rather than hand-waves its boundaries:

- no default password or embedded secret;
- server-side sessions; browser stores only an HttpOnly session cookie;
- state-changing API calls require a per-session CSRF token;
- authentication attempts are rate-limited per client address;
- WebSocket terminal upgrade requires an authenticated session, matching Origin and CSRF token;
- every filesystem path is resolved inside one configured root, including symlink resolution;
- editor saves are temporary-file + fsync + atomic rename and preserve existing mode bits;
- privileged actions are written to `warden-audit.log` with mode `0600`;
- static responses receive restrictive CSP/frame/referrer/content-type headers.

This is not yet a completed security audit. Before an Internet-facing release, Warden still needs the planned adversarial security corpus, explicit reverse-proxy trust model, session revocation UX, optional 2FA, terminal resize messages, stronger audit structure/rotation, and platform/deployment hardening.

## Product direction

Warden v1 focuses on authenticated monitoring, a full filesystem explorer, workspace-oriented code/text editing, and an interactive PTY terminal. Planned later administration modules include certificates, cron, Docker, fail2ban, firewall, services, SSH, users and website management.
