# Warden battle-hardening campaign

This programme turns Warden's existing security controls into tested, documented
guarantees. It does not assume that an implemented control is trustworthy merely
because a focused happy-path test passes.

The checkpoints are sequential. A checkpoint is complete only when its product
changes, adversarial evidence, public documentation and repository commits are
all complete. Findings that cannot be repaired safely remain visible in the risk
register and on the public Battle Tested page where they affect users.

## Campaign rules

For every checkpoint:

1. Start from clean Warden, website-source and generated-website repositories.
2. Record the threat, trusted inputs, hostile inputs and expected invariant.
3. Add a regression test before or with every repair.
4. Run focused tests, the complete Go suite, race tests, vet, frontend checks and
   Nift status. Run platform-specific gates where the checkpoint requires them.
5. Update `docs/battle-tested`, the affected feature documentation and any
   security or deployment claims. Never advertise planned evidence as completed.
6. Rebuild the website with Nift and validate generated links and assets.
7. Commit generated website output first, website source second and Warden last.
8. Record exact commands, results, commit IDs, retained risks and follow-up work.

No checkpoint may weaken a boundary merely to make a test pass. No fuzz crash,
race, sanitizer finding, authorization bypass or recovery failure is dismissed
without a reproducible explanation and a retained regression.

## Evidence required throughout

- `go test ./...`
- `go test -race ./...` on supported race-enabled hosts
- `go vet ./...`
- production build from clean source
- JavaScript syntax and frontend smoke checks
- `nift build` followed by an up-to-date `nift status` for both Nift projects
- generated-site link and asset validation
- clean `git status --short` and inspected `git clean -ndX`
- no credentials, generated binaries, caches or private evidence committed

Additional tools are introduced only when their results can be reproduced in CI
or in a documented campaign environment.

## BH00 - Baseline, threat model and evidence ledger

### Warden

- Inventory every HTTP route, WebSocket, subprocess, filesystem mutation,
  credential store, SQLite table, configuration file and privileged capability.
- Draw explicit browser, proxy, Warden process, OS-user, filesystem, PTY, Git,
  provider and external-service trust boundaries.
- Create a security invariant registry and a retained-risk register.
- Capture clean baseline test, race, vet, build and dependency results.
- Add a test that fails when an unclassified route or capability is introduced.

### Website

- Publish the Battle Tested page with the campaign scope, evidence standard,
  current baseline and every checkpoint marked accurately.
- Reconcile Security, Authentication, Access Control and deployment claims with
  the threat model. Remove stale future-work statements and unsupported claims.

### Exit evidence

- Every authoritative surface is classified.
- Baseline commands and toolchain versions are recorded.
- Known risks have owners or explicit acceptance criteria.

## BH01 - HTTP parsing, response and browser boundary

### Warden

- Apply bounded request bodies, upload sizes, header counts and timeouts to every
  route class, including error paths and streaming routes.
- Reject ambiguous methods, malformed content types, duplicate security headers,
  invalid JSON, trailing JSON and unsupported encodings consistently.
- Verify CSP, frame, MIME, referrer, cache and download headers across success,
  redirect, authentication and error responses.
- Test slow bodies, disconnects, malformed multipart data and handler panics.

### Website

- Document request limits and safe browser-response behaviour.
- Update Battle Tested with the exact HTTP corpus and retained compatibility
  limits.

### Exit evidence

- Malformed-input corpus passes without panic, leak or unbounded read.
- Route-wide header assertions cover success and failure responses.

## BH02 - Password authentication and session lifecycle

### Warden

- Review password derivation parameters, password-change verification, timing
  behaviour and legacy-hash migration.
- Exercise login/setup races, enumeration resistance, throttling eviction and
  IPv4/IPv6 address handling.
- Test session creation, fixation resistance, renewal, expiry, logout, password
  change, account disable, identity disable, role change and global revocation.
- Bound the session store and verify restart semantics deliberately.

### Website

- Document the exact session lifecycle and administrative revocation effects.
- Update Battle Tested with the authentication matrix and rate-limit evidence.

### Exit evidence

- Concurrent setup creates exactly one first administrator.
- Revoked or expired sessions cannot use HTTP or WebSocket authority.

## BH03 - TOTP, recovery codes and Google OAuth

### Warden

- Test TOTP clock windows, replay attempts, enrollment expiry, concurrent enable
  and disable, secret cleanup and recovery-code single use.
- Test OAuth state and PKCE binding, callback replay, account linking, email
  normalization, disabled identities, provider errors and redirect validation.
- Ensure OAuth and TOTP secrets never enter browser diagnostics, logs or exports.

### Website

- Expand Authentication with enrollment, recovery and failure-mode guidance.
- Update Battle Tested with verified MFA/OAuth properties and provider-dependent
  limitations.

### Exit evidence

- Replay and account-linking corpora pass.
- Recovery paths cannot bypass identity or account state.

## BH04 - Authorization and cross-account isolation

### Warden

- Generate a route-by-capability matrix from the server router and test every
  route as administrator, each built-in role, a custom restricted role, a
  disabled account and an unauthenticated client.
- Test ownership of conversations, terminal metadata, acknowledgements,
  credentials, environment settings, sessions and user-managed data.
- Exercise capability changes during active requests and WebSockets.
- Reject confused-deputy paths where a low-authority actor supplies another
  account, identity, job, conversation or terminal identifier.

### Website

- Publish the tested capability matrix and clarify OS authority versus Warden
  application authority.
- Update Battle Tested with negative authorization counts and exclusions.

### Exit evidence

- Every authoritative route has a tested capability and ownership rule.
- Cross-account identifier substitution yields no data or state change.

## BH05 - CSRF, origins, proxies and WebSockets

### Warden

- Test CSRF rotation, missing and duplicated tokens, unsafe content types,
  SameSite assumptions and login/logout cross-site requests.
- Verify Origin and Host handling for HTTP, terminal WebSockets and future socket
  surfaces across IPv4, IPv6 and configured public origins.
- Fuzz forwarded-header chains and prove only explicitly trusted direct peers can
  influence scheme or client identity.
- Test Caddy and nginx configurations with real upgrade and forwarded-header
  behaviour.

### Website

- Update Caddy, nginx and Security documentation with verified configurations,
  trust assumptions and failure examples.
- Update Battle Tested with the proxy matrix.

### Exit evidence

- Direct hostile clients cannot obtain proxy trust or cross-origin socket access.
- Both documented proxy stacks pass the deployment harness.

## BH06 - Filesystem confinement and archive safety

### Warden

- Build a filesystem adversarial corpus covering traversal, absolute paths,
  alternate separators, symlink chains, dangling links, hard links, rename races,
  case behaviour, device files, FIFOs and permission failures.
- Revalidate paths at mutation time to reduce time-of-check/time-of-use exposure.
- Harden upload, download, copy, move, delete, compression and extraction against
  root mutation, zip-slip, zip bombs, overwrite ambiguity and partial failure.
- Preserve atomic editor writes and mode ownership expectations.

### Website

- Document the tested confinement model, archive limits and unsupported special
  files without claiming the PTY is sandboxed.
- Update Battle Tested with corpus platforms and filesystem assumptions.

### Exit evidence

- No corpus case reads or mutates outside `WARDEN_FILE_ROOT`.
- Archive resource limits and rollback behaviour are demonstrated.

## BH07 - Editor, workspace search and source-control safety

### Warden

- Exercise atomic save failures, concurrent saves, stale tabs, permission changes,
  binary/large files and workspace replacement rollback.
- Bound search, regex complexity, replacements, undo history and result counts.
- Validate Git repository discovery, arguments, refs, filenames beginning with
  dashes, hooks, submodules and hostile status output.
- Ensure source-control operations never become an arbitrary shell bridge.

### Website

- Update Editor and Source Control with limits, concurrency behaviour and Git
  trust guidance.
- Add evidence to Battle Tested.

### Exit evidence

- Failure injection leaves original files recoverable.
- Hostile repositories cannot escape argument or workspace boundaries.

## BH08 - Terminal and subprocess lifecycle

### Warden

- Test PTY creation, resize, input, output, reconnect, close, logout, account
  disable, capability removal, server shutdown and orphan cleanup.
- Bound terminal count, scrollback, frame sizes, resize rates and queued output.
- Verify environment filtering, working directories, executable selection and
  child-process-group termination.
- Stress concurrent terminals and abrupt browser/network loss.

### Website

- Document terminal authority, quotas, lifecycle and OS-isolation deployment
  patterns.
- Update Battle Tested with leak and orphan-process evidence.

### Exit evidence

- No tested lifecycle leaves an unauthorized or orphaned PTY/process.
- Resource caps hold under concurrent stress.

## BH09 - Coding agent, providers and model-output hostility

### Warden

- Treat prompts, model output, provider streams, tool events and restored sessions
  as hostile structured input.
- Enforce server-side workspace and capability checks on every agent start,
  restore, cancel and tool-bearing operation.
- Test prompt injection that asks the agent or UI to reveal credentials, escape
  workspaces, alter permissions or forge tool events.
- Bound provider responses, Markdown rendering, token accounting, cancellations,
  subprocess cleanup and concurrent runs.
- Prove personal and shared provider credentials remain isolated and redacted.

### Website

- Expand Coding Agent and AI Providers with the real trust model, credential
  precedence, operator responsibilities and non-guarantees.
- Update Battle Tested with hostile-stream and cancellation evidence.

### Exit evidence

- Model text alone cannot grant authority or forge trusted execution evidence.
- Provider and subprocess failures leave sessions recoverable and secrets hidden.

## BH10 - Secrets, configuration and destructive lifecycle actions

### Warden

- Review key generation, AES-GCM nonce handling, file permissions, atomic writes,
  key/secrets pairing, corruption behaviour and memory/log exposure.
- Test configuration schema rejection, rollback, reload races and environment
  variable filtering.
- Adversarially test reset, uninstall preparation, authentication reset and other
  destructive confirmations for reauthentication, CSRF and exact scope.
- Define secure deletion claims conservatively for ordinary filesystems.

### Website

- Document secret recovery boundaries, configuration rollback and destructive
  lifecycle behaviour.
- Update Battle Tested with cryptographic invariants and retained limitations.

### Exit evidence

- Corrupt or mismatched secret material fails closed without silent loss.
- Destructive actions cannot be triggered by stale or low-authority sessions.

## BH11 - Typed system administration and website management

### Warden

- Audit every external command for fixed executable selection, argument arrays,
  bounded output, timeout, cancellation and environment.
- Test hostile service, user, container, cron, firewall, certificate, SSH and
  website values for command/argument/config injection.
- Validate revision races, publish rollback, loopback-proxy restrictions and
  generated Caddy fragments.
- Exercise missing tools, partial privileges and platform incompatibility.

### Website

- Add per-surface authority and failure guidance to System and Websites.
- Update Battle Tested with command-boundary and revision evidence.

### Exit evidence

- No user-controlled value crosses a shell parser.
- Generated configuration passes syntax validation before activation.

## BH12 - Audit, privacy and forensic integrity

### Warden

- Define a versioned audit-event schema with actor, account, identity, request,
  action, target, outcome and timestamp fields.
- Test coverage for successful and denied privileged operations.
- Redact passwords, tokens, provider keys, TOTP material, recovery codes, file
  contents and sensitive query/body data.
- Bound retention/export and survive malformed legacy events and write failures.
- State honestly that local SQLite/file logs are attributable, not tamper-proof.

### Website

- Expand Audit & Sessions with event fields, retention, export and trust limits.
- Update Battle Tested with coverage and redaction scans.

### Exit evidence

- Sensitive-value canaries are absent from logs, exports and error responses.
- Every classified privileged route has an expected audit outcome.

## BH13 - SQLite, migrations, backup, restore and upgrade

### Warden

- Test clean creation, every historical migration path, future-schema refusal,
  interrupted migration and concurrent startup.
- Inject failures into account, session, conversation, terminal, alert, website
  and audit transactions.
- Perform encrypted-secret-aware backup and restore drills on realistic data.
- Test update compatibility, downgrade refusal and rollback instructions.

### Website

- Expand persistence, installation and recovery guidance with exact drill steps.
- Update Battle Tested with migration and restore matrices.

### Exit evidence

- Supported historical states migrate without data loss.
- A documented restore drill recreates a working instance and verified authority.

## BH14 - Resource exhaustion, races and fuzzing

### Warden

- Add native fuzz targets for parsers, identifiers, paths, archives, filters,
  configuration, OAuth callbacks and protocol messages.
- Run race tests and stress concurrent login, permission changes, saves, terminals,
  agent runs, alerts, website jobs, backup and shutdown.
- Set and verify limits for goroutines, open files, processes, memory-amplifying
  inputs, queues, history and database growth.
- Capture CPU, memory, descriptor and goroutine baselines before and after soak.

### Website

- Publish exact fuzz durations, corpora, stress shapes and resource limits.
- Update Battle Tested without converting one campaign run into a universal claim.

### Exit evidence

- No unresolved race, panic, leak or unbounded queue remains.
- Retained fuzz seeds run in CI.

## BH15 - Frontend security, accessibility and responsive resilience

### Warden

- Test DOM injection through filenames, Git output, logs, terminal labels, alerts,
  websites, accounts, Markdown and provider/model output.
- Exercise keyboard-only use, focus order, dialogs, errors, reduced motion, zoom,
  narrow screens and long/unbroken content.
- Verify security controls remain understandable and operable without relying on
  colour, hover or hidden client-side state.
- Run automated accessibility checks plus manual critical-flow review.

### Website

- Apply the same injection, keyboard, contrast, responsive and link checks to the
  public website.
- Update Battle Tested and relevant UI documentation.

### Exit evidence

- Hostile display strings remain text, not executable markup.
- Setup, login, MFA, revocation and destructive confirmations pass critical-flow
  accessibility review.

## BH16 - Supply chain, builds, installers and release artifacts

### Warden

- Pin and review GitHub Actions permissions and third-party actions.
- Audit Go and frontend dependencies, licenses and vulnerability reports.
- Build all six release targets from a clean tag and verify version stamping,
  checksums, archive contents, embedded frontend and absence of secrets/build paths.
- Test per-user and system installers, upgrades, interrupted downloads, checksum
  failure, unsupported platforms and PATH guidance in clean environments.
- Prove no binaries or generated private evidence enter Git history.

### Website

- Keep installation commands, artifact names, checksums, supported platforms and
  update behaviour synchronized with tested releases.
- Update Battle Tested with artifact and clean-install evidence.

### Exit evidence

- Each published artifact passes a clean-machine smoke test.
- Release workflow uses least privilege and verified artifacts.

## BH17 - Deployment drills, final adversarial review and claim freeze

### Warden

- Deploy under a dedicated unprivileged OS account behind both documented proxies.
- Exercise fresh setup, multiple accounts/roles, MFA, filesystem work, terminals,
  agent runs, alerts, websites, backup, restore, upgrade and revocation end to end.
- Perform a final independent abuse-case review across all trust boundaries.
- Triage every finding as repaired, explicitly accepted, deferred with owner/date,
  or release-blocking.
- Freeze v1 security guarantees and define the disclosure/reporting process.

### Website

- Complete Battle Tested with exact campaign evidence, environment, dates,
  commits, limitations and retained risks.
- Audit every public page for stale status, unsupported guarantees and deployment
  advice. Add security-reporting guidance.

### Exit evidence

- All checkpoint gates are green at the release candidate commit.
- No high-severity unresolved finding remains.
- Public claims match tested evidence exactly.

## Completion record template

Append one record after each completed checkpoint:

```text
Checkpoint:
Date:
Warden commit:
Website source commit:
Generated website commit:
Focused evidence:
Full gates:
Battle Tested update:
Other documentation updated:
Findings repaired:
Retained risks:
Deferred work:
Reviewer:
```

## Campaign status

| Checkpoint | Status | Evidence |
| --- | --- | --- |
| BH00 | Planned | Not started |
| BH01 | Planned | Not started |
| BH02 | Planned | Not started |
| BH03 | Planned | Not started |
| BH04 | Planned | Not started |
| BH05 | Planned | Not started |
| BH06 | Planned | Not started |
| BH07 | Planned | Not started |
| BH08 | Planned | Not started |
| BH09 | Planned | Not started |
| BH10 | Planned | Not started |
| BH11 | Planned | Not started |
| BH12 | Planned | Not started |
| BH13 | Planned | Not started |
| BH14 | Planned | Not started |
| BH15 | Planned | Not started |
| BH16 | Planned | Not started |
| BH17 | Planned | Not started |
