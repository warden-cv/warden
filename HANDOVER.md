# HANDOVER.md
v0.0.5

This is a living handover for working effectively in a Nift project.

Canonical version:

https://nift.dev/HANDOVER.md

Check the version at the top of this file against the canonical copy when the
project is old, unfamiliar, or behaving differently from the current Nift
documentation.

To replace this file with the latest canonical version:

```sh
curl -fsSL https://nift.dev/HANDOVER.md -o HANDOVER.md
```

If this project has project-specific additions, preserve or reapply them when
updating the canonical handover.

This project uses Nift as part of its website build process.

Nift is the project's build-time templating and dependency layer. It does not determine what the website is about or what other technologies the project should use.

Keep the existing project architecture and use the project's normal HTML, CSS, JavaScript, frameworks, backend, and other tooling where appropriate.

Do not introduce Nift-specific machinery where ordinary web tooling is the clearer solution.

## Start here

Before making substantial changes:

1. Inspect `.nift/config.json` and `.nift/tracked.json`.
2. Inspect the existing `content/`, `templates/`, and output structure.
3. Read this project's `README.md` and other project-specific documentation.
4. Run:

```sh
nift status
```

During normal development, build frequently:

```sh
nift build
```

Use this throughout a task, not only at the end. Rebuild after meaningful
changes so Nift can surface template, path, dependency, configuration, and
tracking errors while the cause is still obvious.

In particular, run `nift build` immediately after editing
`.nift/config.json` or `.nift/tracked.json`.

Use:

```sh
nift status
```

when you want to inspect what Nift considers stale and why.

Successful `nift build` output may include indented `↳ ...` lines explaining
why a page was considered stale and rebuilt, such as a missing generated output
or a changed dependency. These are rebuild reasons, not errors. Actual build
failures are reported as errors and cause the build to fail.

Do not delete or recreate `.nift/`.

## Nift's core template model

Most Nift websites need very little Nift-specific syntax.

The three primitives you will use most often are:

```text
@content
@input(...)
@pathto(...)
```

`@content` inserts the tracked page's content into its template.

```html
<main>
    @content
</main>
```

`@content` should execute exactly once across the rendered template/input graph
for a tracked page. It is normally placed in the page's template; the tracked
content file supplies the content inserted there.

Content files may still use other Nift syntax when needed. If page text needs
to display Nift syntax literally, prefix the active sigil with `\` rather than
leaving it as template syntax:

```html
<code>\@content</code>
<code>\@pathto('about')</code>
<code>\$[title]</code>
```

This applies whenever `@...`, `$[...]`, or other Nift syntax is intended as
literal output rather than something Nift should execute or resolve.

`@input(...)` inserts a reusable file and automatically makes it a dependency of the output using it.

```html
@input('templates/header.html')

<main>
    @content
</main>

@input('templates/footer.html')
```

`@pathto(...)` creates project-aware links to tracked pages and local assets.

Nift has additional features including metadata, JSON data, loops, conditionals, pagination, contracts, and explicit dependencies. Use them when the project actually needs them; do not use advanced features merely because they exist.

When writing expressions inside constructs such as `@if(...)`, refer to values directly rather than wrapping them in `$[...]`. For example:

```html
@if(name == 'about'){...}
```

Use `$[...]` when resolving or rendering a value into output, for example `$[title]`. Consult the expressions and control-flow documentation when using more advanced expression syntax.

## Internal links: use `@pathto`

Use `@pathto(...)` for internal links.

This applies to:

- links between pages;
- stylesheets;
- JavaScript;
- images and other local assets where Nift should know the relationship.

For pages, link to the **tracked page name**, not its generated file.

```html
<nav>
    <a href="@pathto('/')">Home</a>
    <a href="@pathto('about')">About</a>
    <a href="@pathto('docs')">Docs</a>
    <a href="@pathto('contact')">Contact</a>
</nav>
```

Do this:

```html
<a href="@pathto('about')">About</a>
```

Do not do this:

```html
<a href="@pathto('about.html')">About</a>
```

and do not hard-code the generated output path:

```html
<a href="about.html">About</a>
```

The tracked page name is the stable project identity. Its output filename or location may change independently.

CSS and JavaScript includes should also use `@pathto(...)`:

```html
<link rel="stylesheet" href="@pathto('public/assets/site.css')">
<script src="@pathto('public/assets/app.js')"></script>
```

Do not calculate relative paths such as:

```html
<link rel="stylesheet" href="../../assets/site.css">
```

Using `@pathto` lets Nift resolve the correct output-relative path and check the project relationship during the build.

## Project configuration

`.nift/config.json` contains project-level Nift configuration.

`.nift/tracked.json` describes tracked pages and their metadata, including things such as their content, template, and output relationships.

These files are part of the project and should evolve with its structure.

If you add, remove, or reorganise pages, templates, outputs, deployment settings, or other Nift-managed structure, inspect the relevant `.nift` configuration and update it where necessary.

Do not treat `.nift/` as disposable generated state.

Do not invent `.nift/tracked.json` fields or assume arbitrary fields become
`$[...]` metadata. When you need tracking behaviour or metadata that is not
already demonstrated by the project, consult the tracked-files and metadata
documentation rather than guessing.

## Output directory

Do not assume the generated website always lives in `public/`.

A normal Nift project may use `public/`, but deployment targets can use a different output structure appropriate to the platform.

Inspect `.nift/config.json` before making assumptions about output paths.

Edit source files rather than generated output unless the project explicitly documents otherwise.

## Pagination

Pagination has several related pieces across `.nift/tracked.json`, page
content, pagination templates, and generated page links. Do not infer its full
behaviour from this handover.

If working with pagination, read the dedicated documentation first:

https://nift.dev/docs/pagination.html

Preserve the project's existing pagination structure unless the task actually
requires changing it, and run `nift build` frequently while doing so.

## Other stacks and tools

Nift does not need to own the whole application.

A project may use Nift alongside tools such as Vite, React, Vue, Svelte, TypeScript, Go, Node, Python, PHP, serverless functions, or other systems.

Keep responsibilities separated:

- use Nift for build-time composition, tracked relationships, and dependencies;
- use the neighbouring tool for the job it is designed to do.

Do not replace an existing stack with Nift-specific code simply to make more of the project use Nift.

## Before finishing

Run:

```sh
nift build
nift status
```

The build should succeed and `nift status` should report the project up to date.
Spot-check generated output when changes affect paths, templates, tracked
relationships, or deployment structure.

## Documentation

Nift documentation:

https://nift.dev/docs.html

When unfamiliar with the project, prioritise:

1. Getting started — https://nift.dev/docs/getting-started.html
2. the three-primitives/template-language material;
3. paths and tracked files, especially `@pathto`;
4. project structure;
5. `.nift/config.json` and `.nift/tracked.json`;
6. incremental builds and CLI commands.

Then read feature documentation only when the task requires it, for example:

- JSON and control flow;
- pagination;
- contracts;
- minification;
- deployment targets;
- integration with other application stacks.

Prefer documented Nift behaviour and the existing project structure over guessing based on another website generator or framework.
## Warden project-specific additions

Warden is a Linux server administration application. Treat it as a privileged security-sensitive product, not a demo dashboard.

Architecture boundary:

- Nift owns the build-time web frontend: HTML composition, CSS/JavaScript templating, checked asset paths, dependencies and eventual minification.
- Go owns runtime authority: authentication, sessions, API endpoints, monitoring, filesystem operations, audit logging and PTY terminal sessions.
- Browser JavaScript talks to the Go runtime over authenticated HTTP/WebSocket APIs. Do not move server authority into Nift or browser-only code.

Current v1 surfaces are Overview/Monitor, Files + syntax-highlighting Editor, and Terminal.

Security invariants for development:

- Never add default credentials, embedded secrets, or a development backdoor to the normal server path.
- Keep the server loopback-bound by default.
- State-changing HTTP APIs require an authenticated server-side session and CSRF token.
- Terminal WebSocket upgrades require session auth, CSRF and same-origin validation.
- Every filesystem operation must remain confined to the configured Warden root after symlink resolution. The configured root itself must not be destructively mutated.
- Preserve atomic file-save behavior and existing file permissions where possible.
- Treat filenames, file contents, process/system data and backend error strings as untrusted browser data.
- Privileged operations must remain auditable.
- A feature is not "secure" merely because the happy path works. Add negative/adversarial tests as security-sensitive slices mature.

Do not turn Warden into an IDE or a general orchestration platform. The editor exists to safely edit server files; the terminal exists to provide an explicitly privileged shell; the monitor exists to explain machine state clearly.

### Warden v1 editor/explorer direction

The Editor is workspace-oriented. A workspace is a directory inside the configured Warden filesystem root. Workspace search/replace may traverse regular text files beneath that directory, but must not follow symlinks or special files. Regex search uses Go's regexp/RE2 semantics. Bulk replacement is a privileged write operation. It is collected before writes, must remain atomic per file, and returns a short-lived guarded undo transaction; undo must refuse to clobber a file that changed again after the replacement.

Explorer and Editor are separate product surfaces:

- Explorer is for filesystem administration: metadata, multi-selection, upload/download, copy/move/delete, ZIP compression/extraction and media preview.
- Editor is for text/code work: resizable workspace tree, explicit open/close workspace lifecycle, multi-file tabs, syntax highlighting, readable occurrence highlighting, Ctrl+D next-occurrence multi-editing with Ctrl+Z/Ctrl+Shift+Z undo/redo for those edits, Ctrl+Shift+S save-all, accurate caret/native text behavior, save/download and undoable workspace-wide find/replace. Without an open workspace, the tree returns to the configured home directory and search remains available for the currently browsed folder, but Replace All stays disabled.
- Do not merge Explorer back into Editor. The Editor may have its own compact workspace tree, VS Code-style, without replacing the richer Explorer.
- Opening/changing an Editor workspace also retargets the shared terminal cwd to that workspace; closing the workspace returns it to the configured home start. Explorer exposes a one-click “Open as Workspace” action for its current directory, while the Editor Open Workspace prompt defaults to the directory currently shown in the Editor file pane. The PTY backend reads Bash’s Linux `/proc/<pid>/stat` foreground process-group (`tpgid`) state and queues the cwd change until Bash owns its controlling terminal again, so cwd handoff does not depend on shell prompt customisation and does not inject into a running child process. Warden suppresses terminal echo only around this internal `cd`, so the resulting prompt/cwd is visible without leaking Warden housekeeping commands into terminal scrollback.

Terminal output is a PTY stream and should preserve terminal semantics where Warden supports them, including common ANSI/SGR colours. Do not render raw control sequences as user-visible text.

### Post-v1 administration roadmap

Once Auth, Monitor, Explorer, Editor and Terminal are mature and security-tested, planned administration areas include certificates, cron jobs, Docker, fail2ban, firewall, services, SSH, user management and websites. Add these as focused modules rather than turning v1 into a shallow collection of panels.


## Warden-specific architecture notes — system pages

- Explorer and Terminal should start in the server user's home directory for normal UX.
- The default Explorer/Editor filesystem boundary is `/`, so users with full file authority can navigate from home to root. `--root` / `WARDEN_FILE_ROOT` may narrow the file-management boundary.
- Do **not** describe `--root` as a terminal sandbox. The PTY runs with the OS authority of the Warden process user and can leave its starting directory. Future Warden role/user levels must explicitly control terminal authority.
- In both Explorer and Editor, clicking a directory name navigates into it; clicking its chevron expands/collapses it inline.
- The System submenu contains structured administration pages for Certificates, Cron jobs, Docker, Fail2ban, Firewall, Services, SSH and Users. Prefer typed fields, tables, state pills, summaries and deliberate actions over dumping command stdout into a textarea.
- System mutations are now enabled during v1 development because an authenticated Warden session already exposes an intentionally privileged terminal. They still travel through authenticated + CSRF-protected APIs, emit audit events, validate structured inputs and return controlled failures; do not replace them with arbitrary browser-supplied shell command execution.
- This does **not** mean the current auth model is ready for Internet exposure. Before recommending public deployment, design real roles/authority boundaries, session revocation/2FA as appropriate, and attack the admin mutation surfaces adversarially.
