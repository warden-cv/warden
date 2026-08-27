# BH17 final adversarial review

Date: 2026-08-27

Candidate baseline before BH17: Warden `14969f3`, website source `9adc6f7`,
generated website `0c83e00`.

## Campaign environment

- Linux amd64 container, Go 1.25 toolchain, CGO disabled release builds
- Node 22 frontend smoke tests
- Nift source/output consistency for the embedded app and public site
- SQLite through `modernc.org/sqlite`
- six release targets: Linux, macOS and Windows on amd64 and arm64

## Final classification

No high-severity unresolved finding remains in the tested Warden application
boundary. Findings discovered during the campaign were repaired in their owning
checkpoint and retained as regression tests. BH13 repaired a concurrent migration
startup race. BH16 added installer checksum verification and raw-artifact cleanup.

## Deployment evidence

The retained deployment smoke starts a fresh Warden instance on loopback and drops
to `nobody` when supported. This container prohibited uid changes, so the executed
run instead removed all available Linux capabilities and prohibited new privilege.
It verifies first-run state and browser security headers. Proxy tests cover trusted
loopback peers, forwarded-header ambiguity, effective HTTPS scheme, CSRF and
WebSocket origins. The documented Caddy and nginx examples are checked for the
matching forwarding and upgrade contract.

The campaign environment did not include the Caddy or nginx daemon binaries, so it
does not claim a live daemon-version compatibility matrix. Operators must run the
documented post-deployment checks with their chosen proxy release.

## Frozen security guarantees

- Every API route has a public, session, capability or WebSocket policy.
- Privileged browser mutations require a live authorized session and CSRF token.
- Terminal WebSockets additionally require a matching effective origin.
- Forwarded identity/scheme data is trusted only from a direct loopback peer.
- Filesystem APIs resolve beneath the configured root and archive publication is
  preflighted and atomic.
- Secrets use authenticated encryption at rest; portable secret backups require a
  separate password.
- SQLite migrations are transactional, integrity checked and fail on future schema.
- Release archives are trim-path, checksum-manifested and built without CGO.

## Retained risks

- Terminal and Agent subprocesses have the Warden OS user's authority. Accounts are
  not OS sandboxes.
- Local SQLite and file audit evidence is attributable, not tamper-proof.
- Anyone who reads both `master.key` and `secrets.json` can decrypt stored secrets.
- Warden is a Linux server product even though release binaries can be built for
  other hosts; privileged system integrations remain Linux-specific.
- A reverse proxy, TLS, dedicated OS account, backups and host hardening remain
  operator responsibilities.
