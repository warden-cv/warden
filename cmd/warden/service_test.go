package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// init configures the install-time readiness gate for the sandbox: installs
// must not require a live listener, and the readiness poll must be fast so
// every test that reaches the health gate completes deterministically.
// Health-gate tests override healthProbe and restore it via t.Cleanup.
func init() {
	healthProbe = func(string) error { return nil }
	installHealthPollInterval = time.Millisecond
	installHealthDeadline = 100 * time.Millisecond
}

// healthIdentityBody is a valid Warden liveness body: the setup-status shape
// plus the exact identity values (ok:true, service:"warden") the checker now
// requires. A plausible setup-shaped body without that identity must be
// rejected.
const healthIdentityBody = `{"required":false,"ok":true,"service":"warden"}`

type fakeRunner struct {
	mu      sync.Mutex
	calls   []string
	handler func(name string, args ...string) (string, int, error)
	out     string
	code    int
	err     error
}

func (f *fakeRunner) Run(name string, args ...string) (string, int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	h := f.handler
	f.mu.Unlock()
	if h != nil {
		return h(name, args...)
	}
	return f.out, f.code, f.err
}

func (f *fakeRunner) Stream(name string, args ...string) (int, error) {
	_, _, _ = f.Run(name, args...)
	return 0, f.err
}

func (f *fakeRunner) contains(args []string, s string) bool {
	for _, a := range args {
		if a == s {
			return true
		}
	}
	return false
}

// saw reports whether any previously recorded call contained needle. The
// current call is excluded, so handlers can branch on prior steps (e.g. a
// post-stop state query that must report inactive).
func (f *fakeRunner) saw(needle string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls[:len(f.calls)-1] {
		if strings.Contains(c, needle) {
			return true
		}
	}
	return false
}

func newFakeManager(t *testing.T) (*serviceManager, *fakeRunner, string) {
	t.Helper()
	base := t.TempDir()
	unitPath := filepath.Join(base, "systemd", "user", "warden.service")
	fr := &fakeRunner{}
	// Default model: a freshly installed service is enabled and active, so the
	// install transaction's readiness gate passes when a test does not override
	// the runner before its setup install.
	fr.handler = func(name string, args ...string) (string, int, error) {
		switch {
		case fr.contains(args, "is-active"):
			return "active", 0, nil
		case fr.contains(args, "is-enabled"):
			return "enabled", 0, nil
		}
		return "", 0, nil
	}
	m := &serviceManager{unitName: "warden.service", unitPath: unitPath, exe: "/usr/local/bin/warden", run: fr}
	return m, fr, base
}

func testOpts(configDir, listen, root string) serviceOptions {
	return serviceOptions{configDir: configDir, listen: listen, root: root}
}

func jsonServer(t *testing.T, code int, body string, ct string) *httptest.Server {
	t.Helper()
	if ct == "" {
		ct = "application/json"
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func activeHandler(fr *fakeRunner) func(name string, args ...string) (string, int, error) {
	return func(name string, args ...string) (string, int, error) {
		switch {
		case fr.contains(args, "is-active"):
			return "active", 0, nil
		case fr.contains(args, "is-enabled"):
			return "enabled", 0, nil
		}
		return "", 0, nil
	}
}

func readManagedUnitBytes(t *testing.T, data []byte) (unitMeta, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden.service")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return unitMeta{}, err
	}
	return readManagedUnit(path)
}

func TestBuildWardenUnit(t *testing.T) {
	unit := buildWardenUnit("/usr/local/bin/warden", testOpts("/home/nick/.config/warden", "127.0.0.1:8080", "/"))
	if !strings.Contains(unit, wardenUnitMarker) {
		t.Fatal("missing managed marker")
	}
	if !regexp.MustCompile(`(?m)^# warden-managed: v1 sha256=[0-9a-f]{64}$`).MatchString(unit) {
		t.Fatalf("missing valid integrity header\n%s", unit)
	}
	if !strings.Contains(unit, `ExecStart="/usr/local/bin/warden"`) {
		t.Fatal("ExecStart must invoke the binary directly")
	}
	if strings.Contains(unit, "sh -c") {
		t.Fatal("unit must not use a shell wrapper")
	}
	for _, want := range []string{`"--config" "/home/nick/.config/warden"`, `"--listen" "127.0.0.1:8080"`, `"--root" "/"`, `Environment=HOME=%h`, `Environment=PATH=%h/.opencode/bin:%h/.local/bin:/usr/local/bin:/usr/bin:/bin`, `# warden-config: /home/nick/.config/warden`, `# warden-listen: 127.0.0.1:8080`, `# warden-health: /api/setup/status`, `WantedBy=default.target`} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit missing %q\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "GH_CONFIG_DIR") || strings.Contains(unit, "GH_TOKEN") {
		t.Fatal("warden unit must not grant host GitHub authentication")
	}
	if _, err := readManagedUnitBytes(t, []byte(unit)); err != nil {
		t.Fatalf("built unit should validate: %v", err)
	}
}

func wardenTestOptsHostPort(configDir, host, port, root string) serviceOptions {
	return serviceOptions{configDir: configDir, host: host, port: port, root: root}
}

func TestBuildWardenUnitHostPort(t *testing.T) {
	// A default install resolves to 127.0.0.1:7332 and the unit must record it
	// through --host/--port so it survives login, restart and reboot.
	def := buildWardenUnit("/usr/local/bin/warden", wardenTestOptsHostPort("/home/nick/.config/warden", "127.0.0.1", "7332", "/"))
	for _, want := range []string{`"--host" "127.0.0.1"`, `"--port" "7332"`, `# warden-listen: 127.0.0.1:7332`} {
		if !strings.Contains(def, want) {
			t.Fatalf("default unit missing %q\n%s", want, def)
		}
	}
	if strings.Contains(def, "--listen") {
		t.Fatal("default unit must use --host/--port, not legacy --listen")
	}
	if _, err := readManagedUnitBytes(t, []byte(def)); err != nil {
		t.Fatalf("default unit should validate: %v", err)
	}

	// An explicit 0.0.0.0:7402 install records that exact listener.
	wide := buildWardenUnit("/usr/local/bin/warden", wardenTestOptsHostPort("/home/nick/.config/warden", "0.0.0.0", "7402", "/"))
	for _, want := range []string{`"--host" "0.0.0.0"`, `"--port" "7402"`, `# warden-listen: 0.0.0.0:7402`} {
		if !strings.Contains(wide, want) {
			t.Fatalf("wide unit missing %q\n%s", want, wide)
		}
	}
	if _, err := readManagedUnitBytes(t, []byte(wide)); err != nil {
		t.Fatalf("wide unit should validate: %v", err)
	}
}

func TestBuildWardenUnitHostPortCanonical(t *testing.T) {
	// Whitespace-surrounded host/port must never leak into the unit metadata or
	// ExecStart; only the canonical trimmed values are recorded.
	opts := wardenTestOptsHostPort("/config", "  127.0.0.1  ", "  7402  ", "/")
	unit := buildWardenUnit("/usr/local/bin/warden", opts)
	for _, want := range []string{`"--host" "127.0.0.1"`, `"--port" "7402"`, `# warden-listen: 127.0.0.1:7402`} {
		if !strings.Contains(unit, want) {
			t.Fatalf("canonical unit missing %q\n%s", want, unit)
		}
	}
	for _, bad := range []string{`"  127.0.0.1  "`, `"  7402  "`, `# warden-listen:   127.0.0.1:7402`} {
		if strings.Contains(unit, bad) {
			t.Fatalf("unit leaked untrimmed value %q\n%s", bad, unit)
		}
	}
}

func TestSystemdExecQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/usr/bin/warden", `"/usr/bin/warden"`},
		{`C:\warden\app`, `"C:\\warden\\app"`},
		{"has $dollar", `"has $$dollar"`},
		{"expand ${FOO} here", `"expand $${FOO} here"`},
		{`say "hi"`, `"say \"hi\""`},
		{"100%", `"100%%"`},
		{"a b  c", `"a b  c"`},
	}
	for _, c := range cases {
		if got := systemdExecQuote(c.in); got != c.want {
			t.Fatalf("systemdExecQuote(%q)=%q want %q", c.in, got, c.want)
		}
	}
	// Backticks and single quotes are literal in systemd command lines; a
	// backslash before them would survive as a stray character, so they must
	// not be escaped.
	if got := systemdExecQuote("a`b"); got != "\"a`b\"" {
		t.Fatalf("backtick must stay literal: %q", got)
	}
	if got := systemdExecQuote("it's"); got != `"it's"` {
		t.Fatalf("single quote must stay literal: %q", got)
	}
}

func TestSystemdEnvValue(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/home/nick/.config/warden", `"/home/nick/.config/warden"`},
		{"/path with spaces", `"/path with spaces"`},
		{`back\slash`, `"back\\slash"`},
		{`say "hi"`, `"say \"hi\""`},
		{"50%", `"50%%"`},
		{"$USER stays literal", `"$USER stays literal"`},
		{"a`b", "\"a`b\""},
	}
	for _, c := range cases {
		if got := systemdEnvValue(c.in); got != c.want {
			t.Fatalf("systemdEnvValue(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestSystemdUnitPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/usr/local/bin", "/usr/local/bin"},
		{"/home/nick/My Documents", "/home/nick/My Documents"},
		{`/tmp/foo"bar`, `/tmp/foo"bar`},
		{`/tmp/a\b`, `/tmp/a\b`},
		{"/tmp/100%", "/tmp/100%%"},
		{"/tmp/%h/secret", "/tmp/%%h/secret"},
	}
	for _, c := range cases {
		if got := systemdUnitPath(c.in); got != c.want {
			t.Fatalf("systemdUnitPath(%q)=%q want %q", c.in, got, c.want)
		}
	}
	for _, in := range []string{"/usr/local/bin", "/home/nick/My Documents", `"/usr/local/bin"`} {
		if got := systemdUnitPath(in); strings.Contains(got, "\"") && !strings.HasPrefix(got, "\"") {
			t.Fatalf("systemdUnitPath(%q) introduced quotes: %q", in, got)
		}
	}
}

// TestBuildWardenUnitWorkingDirectoryNoQuotes is the regression for the real
// Ubuntu install failure: WorkingDirectory must be an unquoted absolute path
// equivalent to "WorkingDirectory=/usr/local/bin". Literal quote characters
// around the value make systemd reject the unit ("path is not absolute"), which
// made `warden service install` fail with "bad unit file setting".
func TestBuildWardenUnitWorkingDirectoryNoQuotes(t *testing.T) {
	unit := buildWardenUnit("/usr/local/bin/warden", testOpts("/home/nick/.config/warden", "127.0.0.1:8080", "/"))
	if !strings.Contains(unit, "WorkingDirectory=/usr/local/bin\n") {
		t.Fatalf("WorkingDirectory must be an unquoted absolute path\n%s", unit)
	}
	for _, bad := range []string{`WorkingDirectory="/usr/local/bin"`, `WorkingDirectory=\"/usr/local/bin\"`, `WorkingDirectory='"/usr/local/bin"'`} {
		if strings.Contains(unit, bad) {
			t.Fatalf("unit contains a quoted WorkingDirectory value %q\n%s", bad, unit)
		}
	}
}

// TestBuildWardenUnitRestartPolicy pins the approved finite restart policy in
// its correct sections: StartLimitIntervalSec and StartLimitBurst in [Unit],
// Restart and RestartSec in [Service]. The unit must never regress to unlimited
// crash-loop restarting.
func TestBuildWardenUnitRestartPolicy(t *testing.T) {
	unit := buildWardenUnit("/usr/local/bin/warden", testOpts("/config", "127.0.0.1:8080", "/"))
	unitSection := sectionContent(unit, "[Unit]")
	serviceSection := sectionContent(unit, "[Service]")
	for _, want := range []string{"StartLimitIntervalSec=60", "StartLimitBurst=5"} {
		if !strings.Contains(unitSection, want) {
			t.Fatalf("[Unit] section missing %q\n%s", want, unit)
		}
	}
	for _, want := range []string{"Restart=on-failure", "RestartSec=3"} {
		if !strings.Contains(serviceSection, want) {
			t.Fatalf("[Service] section missing %q\n%s", want, unit)
		}
	}
	for _, bad := range []string{"Restart=always", "StartLimitIntervalSec=0", "StartLimitBurst=0"} {
		if strings.Contains(unit, bad) {
			t.Fatalf("unit regressed to %q\n%s", bad, unit)
		}
	}
}

// sectionContent returns the body of a systemd unit section, or "" when the
// section header is absent.
func sectionContent(unit, header string) string {
	lines := strings.Split(unit, "\n")
	in := false
	var b strings.Builder
	for _, ln := range lines {
		if strings.HasPrefix(ln, "[") && strings.HasSuffix(ln, "]") {
			in = ln == header
			continue
		}
		if in {
			b.WriteString(ln)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// TestBuildWardenUnitSpecialCharacters renders a unit whose executable, config
// and root paths contain systemd-sensitive characters (spaces, quotes,
// backslashes, percent, dollar) and asserts each directive escapes its value
// according to the directive's syntax: command-line quoting for ExecStart and
// unquoted path escaping for WorkingDirectory (which derives from the
// executable's parent directory). Warden records no Environment value beyond
// HOME=%h (a deliberate specifier, never doubled), so Environment escaping is
// proven by systemdEnvValue directly.
func TestBuildWardenUnitSpecialCharacters(t *testing.T) {
	opts := serviceOptions{
		host:      "127.0.0.1",
		port:      "7332",
		configDir: `/home/nick/.config/50% data "quoted"`,
		root:      `/home/nick/My Documents 100% warden`,
	}
	exe := `/usr/local/bin/My Warden 100%/warden`
	unit := buildWardenUnit(exe, opts)

	if !strings.Contains(unit, "WorkingDirectory=/usr/local/bin/My Warden 100%%\n") {
		t.Fatalf("WorkingDirectory must be the raw unquoted parent path with percent doubled\n%s", unit)
	}
	for _, want := range []string{
		`ExecStart="/usr/local/bin/My Warden 100%%/warden"`,
		`"--config" "/home/nick/.config/50%% data \"quoted\""`,
		`"--root" "/home/nick/My Documents 100%% warden"`,
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit missing %q\n%s", want, unit)
		}
	}
	if strings.Contains(unit, `WorkingDirectory="/usr/local/bin`) {
		t.Fatal("WorkingDirectory must not be quoted")
	}
}

// TestSystemdAnalyzeVerifyRenderedUnit is a genuine Linux validation of the
// rendered unit: it writes the generated unit to a temporary file and runs
// `systemd-analyze --user verify` against it. The exit code is authoritative —
// a string-only assertion is insufficient because the malformed WorkingDirectory
// line looked superficially plausible. A deliberately buggy variant (quoted
// WorkingDirectory) is verified to FAIL so the mechanism is proven to catch the
// exact observed regression, not merely to accept any input. The default Go
// suite never writes into or mutates a developer's real user systemd
// configuration: units are written only under t.TempDir and the analyzer runs
// against an isolated XDG_RUNTIME_DIR.
func TestSystemdAnalyzeVerifyRenderedUnit(t *testing.T) {
	analyze, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze not installed; skipping real systemd unit verification")
	}
	if _, err := os.Stat("/bin/true"); err != nil {
		t.Skip("/bin/true unavailable; skipping real systemd unit verification")
	}
	// specialExe installs a real executable under a path containing spaces and
	// a percent sign, so systemd-analyze's executable check passes while the
	// working directory exercises systemd-sensitive characters.
	specialExe := func(t *testing.T) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "Warden 100%")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		src, err := os.ReadFile("/bin/true")
		if err != nil {
			t.Fatal(err)
		}
		exe := filepath.Join(dir, "warden")
		if err := os.WriteFile(exe, src, 0755); err != nil {
			t.Fatal(err)
		}
		return exe
	}
	writeAndVerify := func(t *testing.T, name, unit string) (string, bool) {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(unit), 0644); err != nil {
			t.Fatal(err)
		}
		// Bootstrap the user-manager environment: systemd-analyze --user needs a
		// runtime directory to initialize a manager even in a headless build
		// environment, so an isolated XDG_RUNTIME_DIR is provided.
		runtimeDir := t.TempDir()
		if err := os.Chmod(runtimeDir, 0700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(analyze, "--user", "verify", path)
		cmd.Env = append(os.Environ(), "XDG_RUNTIME_DIR="+runtimeDir)
		out, err := cmd.CombinedOutput()
		if err != nil && isVerifyInfraFailure(string(out)) {
			// The manager itself could not initialize (no user bus/runtime
			// directory); that is an infrastructure limitation, never an
			// acceptance or rejection of the unit under test.
			t.Skipf("systemd user manager cannot initialize here: %s", strings.TrimSpace(string(out)))
		}
		ok := err == nil && !strings.Contains(string(out), path)
		return string(out), ok
	}

	opts := testOpts("/home/nick/.config/warden", "127.0.0.1:7332", "/")

	t.Run("ordinary paths verify clean", func(t *testing.T) {
		out, ok := writeAndVerify(t, "warden.service", buildWardenUnit("/bin/true", opts))
		if !ok {
			t.Fatalf("systemd-analyze verify failed for the ordinary unit\n%s", out)
		}
	})
	t.Run("special-character paths verify clean", func(t *testing.T) {
		special := serviceOptions{
			host:      "127.0.0.1",
			port:      "7332",
			configDir: `/home/nick/.config/50% data "quoted"`,
			root:      `/home/nick/My Documents 100% warden`,
		}
		out, ok := writeAndVerify(t, "warden.service", buildWardenUnit(specialExe(t), special))
		if !ok {
			t.Fatalf("systemd-analyze verify failed for the special-character unit\n%s", out)
		}
	})
	t.Run("quoted WorkingDirectory is rejected by verify", func(t *testing.T) {
		buggy := strings.Replace(buildWardenUnit("/bin/true", opts), "WorkingDirectory=/bin", `WorkingDirectory="/bin"`, 1)
		out, ok := writeAndVerify(t, "warden.service", buggy)
		if ok {
			t.Fatalf("systemd-analyze verify accepted the quoted WorkingDirectory regression\n%s", out)
		}
		if !strings.Contains(out, "not absolute") {
			t.Fatalf("verify did not report the WorkingDirectory path error\n%s", out)
		}
	})
}

// isVerifyInfraFailure reports whether a failed systemd-analyze invocation is
// an environment limitation (no user manager, no runtime directory, no bus)
// rather than a defect in the unit under test. Infrastructure initialization
// failures must never be classified as acceptance or rejection of a unit.
func isVerifyInfraFailure(out string) bool {
	lower := strings.ToLower(out)
	for _, m := range []string{
		"failed to lookup runtimedirectory path",
		"failed to initialize manager",
		"failed to create manager",
		"no such device or address",
		"failed to connect to bus",
		"cannot find any user bus",
		"cannot access user bus",
	} {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

func TestIsVerifyInfraFailure(t *testing.T) {
	for _, m := range []string{
		"Failed to lookup RuntimeDirectory path: No such device or address",
		"Failed to initialize manager: No such device or address",
		"Failed to connect to bus: No such file or directory",
	} {
		if !isVerifyInfraFailure(m) {
			t.Fatalf("infrastructure failure not recognized: %q", m)
		}
	}
	for _, m := range []string{
		"WorkingDirectory= path is not absolute: \"/usr/local/bin\"",
		"warden.service: Unit configuration has fatal error",
		"",
	} {
		if isVerifyInfraFailure(m) {
			t.Fatalf("unit defect misclassified as infrastructure failure: %q", m)
		}
	}
}

func TestResolveExecutable(t *testing.T) {
	if _, err := resolveExecutable(""); err == nil {
		t.Fatal("empty path accepted")
	}
	t.Run("real file at relative path is rejected", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := os.WriteFile("warden", []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveExecutable("warden"); err == nil || !strings.Contains(err.Error(), "not absolute") {
			t.Fatalf("relative path to a real executable was not rejected: %v", err)
		}
	})
	if _, err := resolveExecutable(os.TempDir() + "/warden"); err == nil {
		t.Fatal("transient temp path accepted")
	}
	if _, err := resolveExecutable("/tmp/go-build123/b001/exe/warden"); err == nil {
		t.Fatal("go-build path accepted")
	}
	got, err := resolveExecutable("/bin/true")
	if err != nil {
		t.Fatalf("valid path rejected: %v", err)
	}
	if got != "/bin/true" {
		t.Fatalf("resolved %q want /bin/true", got)
	}
}

func TestResolveExecutableRejectsUnsafeSystemdForms(t *testing.T) {
	// Character and whitespace rejections happen before any filesystem check,
	// so crafted absolute paths exercise them deterministically on every OS.
	for _, exe := range []string{
		`/home/nick/bin/weird"dir/warden`,
		`/home/nick/bin/it's/warden`,
		`/home/nick/bin/back\slash/warden`,
		`/home/nick/bin/$dollar/warden`,
		`  /usr/local/bin/warden`,
		"/usr/local/bin/warden\n",
		"a\x00b",
	} {
		if _, err := resolveExecutable(exe); err == nil {
			t.Fatalf("unsafe executable path accepted: %q", exe)
		}
	}
	// The rejection is independent of whether such a file exists.
	if _, err := resolveExecutable(`/tmp/no such "${file}"`); err == nil {
		t.Fatal("path with leading/trailing whitespace accepted")
	}
}

func TestClassifySystemdFailure(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Failed to restart warden.service: Unit warden.service has a bad unit file setting.", "generated unit is invalid"},
		{"warden.service: Unit configuration has fatal error, unit will not be started.", "generated unit is invalid"},
		{"WorkingDirectory= path is not absolute: \"/usr/local/bin\"", "generated unit is invalid"},
		{"warden.service: Unknown key 'Foo' in section [Service], ignoring.", "generated unit is invalid"},
		{"warden.service: Invalid argument", "generated unit is invalid"},
		{"warden.service: Start request repeated too quickly.", "start rate limit exceeded"},
		{"Failed to connect to bus: No such file or directory", "systemd bus unavailable"},
		{"Some other failure", ""},
	}
	for _, c := range cases {
		if got := classifySystemdFailure(c.in); got != c.want {
			t.Fatalf("classifySystemdFailure(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestSystemctlTolerantMissingDoesNotExist(t *testing.T) {
	fr := &fakeRunner{out: "Failed to disable unit warden.service: Unit warden.service does not exist.", code: 1}
	m := &serviceManager{unitName: "warden.service", run: fr}
	if err := m.systemctlTolerantMissing("disable", m.unitName); err != nil {
		t.Fatalf("'does not exist' must be tolerated as an absent unit: %v", err)
	}
	fr = &fakeRunner{out: "Failed to stop unit warden.service: Unit warden.service not loaded.", code: 1}
	m.run = fr
	if err := m.systemctlTolerantMissing("stop", m.unitName); err != nil {
		t.Fatalf("'not loaded' must be tolerated: %v", err)
	}
	fr = &fakeRunner{out: "systemd is broken", code: 1}
	m.run = fr
	if err := m.systemctlTolerantMissing("stop", m.unitName); err == nil {
		t.Fatal("a genuine failure must not be tolerated")
	}
}

func TestValidateNoControl(t *testing.T) {
	if err := validateNoControl("/home/nick/.config/warden", "config"); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, bad := range []string{"/config\nRestart=always", "a\x00b", "a\x0db"} {
		if err := validateNoControl(bad, "config"); err == nil {
			t.Fatalf("control characters accepted: %q", bad)
		}
	}
	m, _, _ := newFakeManager(t)
	if err := m.install(testOpts("/config\nRestart=always", "127.0.0.1:8080", "/"), os.Stderr); err == nil {
		t.Fatal("install accepted a control-character config path")
	}
}

func TestManagedUnitIntegrity(t *testing.T) {
	unit := buildWardenUnit("/usr/local/bin/warden", testOpts("/config", "127.0.0.1:8080", "/"))
	if _, err := readManagedUnitBytes(t, []byte(unit)); err != nil {
		t.Fatalf("valid unit rejected: %v", err)
	}
	t.Run("modified ExecStart", func(t *testing.T) {
		bad := strings.Replace(unit, "/usr/local/bin/warden", "/usr/bin/warden", 1)
		if _, err := readManagedUnitBytes(t, []byte(bad)); !errors.Is(err, errModified) {
			t.Fatalf("want errModified, got %v", err)
		}
	})
	t.Run("appended directive", func(t *testing.T) {
		bad := unit + "Environment=FOO=bar\n"
		if _, err := readManagedUnitBytes(t, []byte(bad)); !errors.Is(err, errModified) {
			t.Fatalf("want errModified, got %v", err)
		}
	})
	t.Run("removed directive", func(t *testing.T) {
		bad := strings.Replace(unit, "Restart=on-failure\n", "", 1)
		if _, err := readManagedUnitBytes(t, []byte(bad)); !errors.Is(err, errModified) {
			t.Fatalf("want errModified, got %v", err)
		}
	})
	t.Run("corrupted checksum", func(t *testing.T) {
		re := regexp.MustCompile(`(v1 sha256=)([0-9a-f]{64})`)
		loc := re.FindStringSubmatchIndex(unit)
		hashStart := loc[4]
		repl := "0"
		if unit[hashStart] == '0' {
			repl = "1"
		}
		bad := unit[:hashStart] + repl + unit[hashStart+1:]
		if _, err := readManagedUnitBytes(t, []byte(bad)); !errors.Is(err, errModified) {
			t.Fatalf("want errModified, got %v", err)
		}
	})
	t.Run("duplicate integrity header", func(t *testing.T) {
		lines := strings.SplitN(unit, "\n", 3)
		bad := strings.Join(lines[:2], "\n") + "\n" + lines[1] + "\n" + lines[2]
		if _, err := readManagedUnitBytes(t, []byte(bad)); !errors.Is(err, errMalformed) {
			t.Fatalf("want errMalformed, got %v", err)
		}
	})
	t.Run("missing marker", func(t *testing.T) {
		bad := "# hand written\n[Service]\n"
		if _, err := readManagedUnitBytes(t, []byte(bad)); !errors.Is(err, errNotManaged) {
			t.Fatalf("want errNotManaged, got %v", err)
		}
	})
	t.Run("wrong health path rejected", func(t *testing.T) {
		body := renderWardenUnitBody("/usr/local/bin/warden", testOpts("/config", "127.0.0.1:8080", "/"))
		content := "# warden-config: /config\n# warden-listen: 127.0.0.1:8080\n# warden-health: /other\n" + body
		sum := sha256.Sum256([]byte(content))
		bad := wardenUnitMarker + "\n" + wardenManagedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n" + content
		if _, err := readManagedUnitBytes(t, []byte(bad)); !errors.Is(err, errMalformed) {
			t.Fatalf("health path must be application-owned; want errMalformed, got %v", err)
		}
	})
	t.Run("duplicate metadata rejected even with valid checksum", func(t *testing.T) {
		body := renderWardenUnitBody("/usr/local/bin/warden", testOpts("/config", "127.0.0.1:8080", "/"))
		content := "# warden-config: /config\n# warden-config: /other\n# warden-listen: 127.0.0.1:8080\n# warden-health: /api/setup/status\n" + body
		sum := sha256.Sum256([]byte(content))
		bad := wardenUnitMarker + "\n" + wardenManagedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n" + content
		if _, err := readManagedUnitBytes(t, []byte(bad)); !errors.Is(err, errMalformed) {
			t.Fatalf("duplicate metadata with recomputed checksum; want errMalformed, got %v", err)
		}
	})
	t.Run("malformed metadata with valid checksum", func(t *testing.T) {
		body := renderWardenUnitBody("/usr/local/bin/warden", testOpts("/config", "127.0.0.1:8080", "/"))
		for _, content := range []string{
			"# warden-config: \n# warden-listen: 127.0.0.1:8080\n# warden-health: /api/setup/status\n" + body,
			"# warden-config: /config\n# warden-listen: 127.0.0.1:8080\x00x\n# warden-health: /api/setup/status\n" + body,
		} {
			sum := sha256.Sum256([]byte(content))
			bad := wardenUnitMarker + "\n" + wardenManagedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n" + content
			if _, err := readManagedUnitBytes(t, []byte(bad)); !errors.Is(err, errMalformed) {
				t.Fatalf("malformed metadata; want errMalformed, got %v", err)
			}
		}
	})
}

// fakeSystemd is a stateful model of a per-user systemd manager used by the
// service transaction tests. It holds the unit's enablement and active states,
// answers is-enabled/is-active and the lifecycle verbs against that model, and
// records every call so tests can assert both the exact calls and the final
// state rather than relying on substring assertions. The unit's loaded state is
// derived from the managed unit file's presence, so a rollback that removes the
// unit also makes is-enabled report not-found and is-active report inactive.
type fakeSystemd struct {
	mu       sync.Mutex
	unitPath string
	enable   bool // persistent enablement link
	enableRT bool // runtime enablement link
	mask     bool // persistent mask
	maskRT   bool // runtime mask
	active   string
	// Overrides simulate systemctl reports for prior states that have no
	// corresponding link layer (for example not-found on a loaded unit, or
	// static/alias unit-file states). They are used only to exercise the
	// refuse-before-mutation path.
	overrideEnabled string
	overrideActive  string
	failVerb        string
	calls           []string
}

func newFakeSystemd(unitPath string) *fakeSystemd {
	return &fakeSystemd{unitPath: unitPath, active: "inactive"}
}

func exitForEnabled(word string) int {
	switch word {
	case "enabled", "enabled-runtime", "static", "alias", "indirect", "generated":
		return 0
	case "disabled", "masked", "masked-runtime", "linked", "linked-runtime", "transient":
		return 1
	case "not-found", "unknown":
		return 4
	}
	return 1
}

func exitForActive(word string) int {
	switch word {
	case "active", "reloading":
		return 0
	case "inactive", "dead", "failed", "activating", "deactivating", "maintenance":
		return 3
	case "not-found", "unknown":
		return 4
	}
	return 3
}

// enabledWord derives the is-enabled word from the persistent/runtime
// enablement and mask layers, matching systemd's precedence: a persistent mask
// reports masked, a runtime-only mask masked-runtime, persistent enablement
// enabled, runtime-only enablement enabled-runtime, and otherwise disabled when
// the unit file is present.
func (f *fakeSystemd) enabledWord() string {
	if f.overrideEnabled != "" {
		return f.overrideEnabled
	}
	switch {
	case f.mask:
		return "masked"
	case f.maskRT:
		return "masked-runtime"
	case f.enable:
		return "enabled"
	case f.enableRT:
		return "enabled-runtime"
	}
	if _, err := os.Stat(f.unitPath); err != nil {
		return "not-found"
	}
	return "disabled"
}

func (f *fakeSystemd) activeWord() string {
	if f.overrideActive != "" {
		return f.overrideActive
	}
	if _, err := os.Stat(f.unitPath); err != nil {
		return "inactive"
	}
	return f.active
}

// runner returns a serviceRunner wired to the fake model.
func (f *fakeSystemd) runner() *fakeRunner {
	fr := &fakeRunner{}
	fr.handler = func(name string, args ...string) (string, int, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, name+" "+strings.Join(args, " "))
		verb := ""
		for _, a := range args {
			if a != "--user" {
				verb = a
				break
			}
		}
		fail := f.failVerb != "" && f.failVerb == verb
		if fail {
			f.failVerb = ""
		}
		if verb == "daemon-reload" {
			if fail {
				return "reload failed", 1, nil
			}
			return "", 0, nil
		}
		if verb == "is-enabled" {
			word := f.enabledWord()
			return word, exitForEnabled(word), nil
		}
		if verb == "is-active" {
			word := f.activeWord()
			return word, exitForActive(word), nil
		}
		// enable, enable --runtime, disable, mask, mask --runtime, start,
		// restart, stop
		switch verb {
		case "enable", "disable", "mask":
			if containsStr(args, "--runtime") {
				verb = verb + "-runtime"
			}
			switch verb {
			case "enable":
				// A masked unit cannot be enabled.
				if f.mask || f.maskRT {
					return "Failed to enable unit: masked", 1, nil
				}
				f.enable = true
			case "enable-runtime":
				if f.mask || f.maskRT {
					return "Failed to enable unit: masked", 1, nil
				}
				f.enableRT = true
			case "disable":
				// Normalization: remove both persistent and runtime links.
				f.enable = false
				f.enableRT = false
			case "mask":
				f.mask = true
				f.enable = false
				f.enableRT = false
			case "mask-runtime":
				f.maskRT = true
				f.enable = false
				f.enableRT = false
			}
		case "start", "restart":
			if f.mask || f.maskRT {
				return "Failed to start unit: masked", 1, nil
			}
			if fail {
				// A refused/unsuccessful start leaves the prior state intact.
				return verb + " failed", 1, nil
			}
			f.active = "active"
			f.overrideActive = ""
		case "stop":
			// Real systemd keeps a start-limited (failed) unit reporting failed
			// after stop, so stop preserves the overrideActive failure word.
			f.active = "inactive"
		case "reset-failed":
			if fail {
				return "reset-failed failed", 1, nil
			}
			f.active = "inactive"
			f.overrideActive = ""
		}
		if fail {
			return verb + " failed", 1, nil
		}
		return "", 0, nil
	}
	return fr
}

// setState seeds a prior enablement/active pair. Enablement words that have a
// real link representation populate the layers; words that only systemctl could
// report for a synthetic state (not-found, static, dead, unknown, ...) are kept
// as overrides so the refuse-before-mutation path sees them verbatim.
func (f *fakeSystemd) setState(enabled, active string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.overrideEnabled = ""
	f.overrideActive = ""
	f.enable = false
	f.enableRT = false
	f.mask = false
	f.maskRT = false
	switch enabled {
	case "enabled":
		f.enable = true
	case "enabled-runtime":
		f.enableRT = true
	case "masked":
		f.mask = true
	case "masked-runtime":
		f.maskRT = true
	case "disabled":
		// No link layers; is-enabled derives from the unit file's presence.
	default:
		f.overrideEnabled = enabled
	}
	switch active {
	case "active", "inactive":
		f.active = active
	default:
		f.active = active
		f.overrideActive = active
	}
}

func (f *fakeSystemd) callsContain(needle string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.Contains(c, needle) {
			return true
		}
	}
	return false
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestInstallFreshAndChanged(t *testing.T) {
	t.Run("fresh install publishes and starts", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatalf("install: %v", err)
		}
		unit, err := os.ReadFile(m.unitPath)
		if err != nil {
			t.Fatalf("unit not written: %v", err)
		}
		if _, err := readManagedUnitBytes(t, unit); err != nil {
			t.Fatalf("installed unit invalid: %v", err)
		}
		for _, want := range []string{"daemon-reload", "enable warden.service", "restart warden.service"} {
			if !fs.callsContain(want) {
				t.Fatalf("fresh install did not call %q\ncalls: %v", want, fs.calls)
			}
		}
		if fs.activeWord() != "active" {
			t.Fatalf("service not started: %q", fs.activeWord())
		}
		if fs.enabledWord() != "enabled" {
			t.Fatalf("service not enabled: %q", fs.enabledWord())
		}
	})

	t.Run("identical reinstall on enabled active service is a true no-op", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fs.setState("enabled", "active")
		fs.calls = nil
		fi, _ := os.Stat(m.unitPath)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatalf("no-op reinstall: %v", err)
		}
		for _, forbid := range []string{"daemon-reload", "enable ", "restart ", "start "} {
			if fs.callsContain(forbid) {
				t.Fatalf("no-op reinstall mutated systemd (%q)\ncalls: %v", forbid, fs.calls)
			}
		}
		if fi2, _ := os.Stat(m.unitPath); !fi.ModTime().Equal(fi2.ModTime()) {
			t.Fatal("no-op reinstall rewrote the unit file")
		}
	})

	t.Run("changed configuration restarts the service", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fs.setState("enabled", "active")
		fs.calls = nil
		if err := m.install(testOpts("/config2", "127.0.0.1:8081", "/"), os.Stderr); err != nil {
			t.Fatalf("changed reinstall: %v", err)
		}
		if !fs.callsContain("restart warden.service") {
			t.Fatalf("changed config did not restart\ncalls: %v", fs.calls)
		}
	})

	t.Run("unchanged unit on inactive service starts it", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fs.setState("enabled", "inactive")
		fs.calls = nil
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatalf("inactive reinstall: %v", err)
		}
		if !fs.callsContain("start warden.service") {
			t.Fatalf("inactive service was not started\ncalls: %v", fs.calls)
		}
		if fs.callsContain("daemon-reload") || fs.callsContain("restart ") {
			t.Fatalf("unchanged inactive reinstall did unnecessary work\ncalls: %v", fs.calls)
		}
	})

	t.Run("unchanged unit on disabled service enables then starts", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fs.setState("disabled", "inactive")
		fs.calls = nil
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatalf("disabled reinstall: %v", err)
		}
		if !fs.callsContain("enable warden.service") || !fs.callsContain("start warden.service") {
			t.Fatalf("disabled service was not enabled and started\ncalls: %v", fs.calls)
		}
		if fs.callsContain("daemon-reload") {
			t.Fatalf("unchanged disabled reinstall reloaded systemd needlessly\ncalls: %v", fs.calls)
		}
	})
}

func TestInstallRollbackMatrix(t *testing.T) {
	pairs := []struct {
		enabled, active string
		restorable      bool
		failAt          string
	}{
		{"enabled", "active", true, "restart"}, {"enabled", "inactive", true, "restart"},
		{"enabled-runtime", "active", true, "restart"}, {"enabled-runtime", "inactive", true, "restart"},
		{"disabled", "active", true, "restart"}, {"disabled", "inactive", true, "restart"},
		// A start-limited failed unit is restorable exactly: systemctl stop
		// leaves it reporting failed. The injected failure happens at enable,
		// before the install's reset-failed clears the failure, so rollback's
		// stop reproduces the exact prior "failed" word.
		{"enabled", "failed", true, "enable"}, {"enabled-runtime", "failed", true, "enable"},
		{"disabled", "failed", true, "enable"},
		// Refused: masked states (the install itself cannot enable a masked
		// unit), not exact (dead/unknown/not-found active, not-found enabled),
		// transient, and unit-file enablement states.
		{"enabled", "dead", false, "restart"}, {"enabled", "unknown", false, "restart"}, {"enabled", "not-found", false, "restart"},
		{"enabled-runtime", "reloading", false, "restart"},
		{"disabled", "refreshing", false, "restart"}, {"disabled", "activating", false, "restart"},
		{"disabled", "deactivating", false, "restart"}, {"disabled", "maintenance", false, "restart"},
		{"masked", "inactive", false, "restart"}, {"masked-runtime", "inactive", false, "restart"},
		{"masked", "active", false, "restart"}, {"masked-runtime", "active", false, "restart"},
		{"masked", "failed", false, "restart"},
		{"not-found", "active", false, "restart"}, {"not-found", "inactive", false, "restart"},
		{"static", "active", false, "restart"}, {"alias", "active", false, "restart"}, {"indirect", "active", false, "restart"},
		{"generated", "active", false, "restart"}, {"linked", "active", false, "restart"},
		{"linked-runtime", "active", false, "restart"}, {"transient", "active", false, "restart"},
		{"unknown", "active", false, "restart"},
	}
	for _, p := range pairs {
		t.Run("enabled="+p.enabled+"/active="+p.active, func(t *testing.T) {
			m, _, _ := newFakeManager(t)
			fs := newFakeSystemd(m.unitPath)
			m.run = fs.runner()
			if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
				t.Fatal(err)
			}
			priorUnit, _ := os.ReadFile(m.unitPath)
			fs.setState(p.enabled, p.active)
			fs.calls = nil
			if !p.restorable {
				err := m.install(testOpts("/configX", "127.0.0.1:8082", "/"), os.Stderr)
				if err == nil {
					t.Fatalf("non-restorable pair (%q/%q) was not refused", p.enabled, p.active)
				}
				after, _ := os.ReadFile(m.unitPath)
				if string(after) != string(priorUnit) {
					t.Fatal("refusal changed the unit file")
				}
				for _, forbid := range []string{"daemon-reload", "enable ", "mask ", "disable ", "restart ", "start ", "stop ", "reset-failed"} {
					if fs.callsContain(forbid) {
						t.Fatalf("refusal performed a lifecycle mutation (%q)\ncalls: %v", forbid, fs.calls)
					}
				}
				return
			}
			// Restorable: fail a lifecycle step, run rollback, and assert
			// the final raw state exactly matches the prior raw state.
			fs.failVerb = p.failAt
			err := m.install(testOpts("/configY", "127.0.0.1:8083", "/"), os.Stderr)
			if err == nil {
				t.Fatalf("install should fail at %s for restorable pair (%q/%q)", p.failAt, p.enabled, p.active)
			}
			after, _ := os.ReadFile(m.unitPath)
			if string(after) != string(priorUnit) {
				t.Fatal("rollback did not restore the prior unit bytes")
			}
			ew, _, _ := m.systemctl("is-enabled", m.unitName)
			aw, _, _ := m.systemctl("is-active", m.unitName)
			if strings.TrimSpace(ew) != p.enabled || strings.TrimSpace(aw) != p.active {
				t.Fatalf("rollback final raw state %q/%q want %q/%q", ew, aw, p.enabled, p.active)
			}
			if fs.enabledWord() != p.enabled || fs.activeWord() != p.active {
				t.Fatalf("rollback final model state %q/%q want %q/%q", fs.enabledWord(), fs.activeWord(), p.enabled, p.active)
			}
		})
	}
}

// TestInstallRestoresEnablementLayers proves the rollback normalizes
// enablement links before recreating them, so a runtime-only prior never keeps
// the persistent link created by the attempted install.
func TestInstallRestoresEnablementLayers(t *testing.T) {
	cases := []struct {
		prior              string
		wantEnable, wantRT bool
	}{
		{"enabled", true, false},
		{"enabled-runtime", false, true},
		{"disabled", false, false},
	}
	for _, tc := range cases {
		t.Run("prior="+tc.prior, func(t *testing.T) {
			m, _, _ := newFakeManager(t)
			fs := newFakeSystemd(m.unitPath)
			m.run = fs.runner()
			if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
				t.Fatal(err)
			}
			fs.setState(tc.prior, "inactive")
			fs.failVerb = "restart"
			if err := m.install(testOpts("/configY", "127.0.0.1:8083", "/"), os.Stderr); err == nil {
				t.Fatal("install should fail at restart")
			}
			ew, _, _ := m.systemctl("is-enabled", m.unitName)
			if strings.TrimSpace(ew) != tc.prior {
				t.Fatalf("is-enabled %q want %q", ew, tc.prior)
			}
			if fs.enable != tc.wantEnable || fs.enableRT != tc.wantRT {
				t.Fatalf("links enable=%v enableRT=%v want %v/%v", fs.enable, fs.enableRT, tc.wantEnable, tc.wantRT)
			}
			if fs.mask || fs.maskRT {
				t.Fatal("unexpected mask link after rollback")
			}
		})
	}
}

// TestInstallReachesInstalledStateForAcceptedPriors proves every accepted prior
// state lets the install reach the documented enabled-and-active state, so a
// state is never accepted merely because rollback could recover from an install
// that can never succeed.
func TestInstallReachesInstalledStateForAcceptedPriors(t *testing.T) {
	for _, p := range [][2]string{
		{"enabled", "active"}, {"enabled", "inactive"}, {"enabled", "failed"},
		{"enabled-runtime", "active"}, {"enabled-runtime", "inactive"}, {"enabled-runtime", "failed"},
		{"disabled", "active"}, {"disabled", "inactive"}, {"disabled", "failed"},
	} {
		t.Run(p[0]+"/"+p[1], func(t *testing.T) {
			m, _, _ := newFakeManager(t)
			fs := newFakeSystemd(m.unitPath)
			m.run = fs.runner()
			if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
				t.Fatal(err)
			}
			fs.setState(p[0], p[1])
			if err := m.install(testOpts("/configY", "127.0.0.1:8083", "/"), os.Stderr); err != nil {
				t.Fatalf("accepted prior %s/%s could not reach the installed state: %v", p[0], p[1], err)
			}
			ew, _, _ := m.systemctl("is-enabled", m.unitName)
			aw, _, _ := m.systemctl("is-active", m.unitName)
			if strings.TrimSpace(ew) != "enabled" || strings.TrimSpace(aw) != "active" {
				t.Fatalf("final %q/%q want enabled/active", ew, aw)
			}
		})
	}
}

// TestInstallResetFailedRecovery proves the install clears a prior start-limit
// failed state with reset-failed before starting, so a crash-looped unit can be
// reinstalled without manual systemctl intervention. A reset-failed failure on
// an unloaded unit (fresh install) is tolerated and reported distinctly when it
// fails for a real reason.
func TestInstallResetFailedRecovery(t *testing.T) {
	t.Run("reinstall over a start-limited unit clears the failure", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fs.setState("enabled", "failed")
		fs.calls = nil
		if err := m.install(testOpts("/config", "127.0.0.1:8081", "/"), os.Stderr); err != nil {
			t.Fatalf("reinstall over a failed unit failed: %v", err)
		}
		if !fs.callsContain("reset-failed warden.service") {
			t.Fatalf("install did not reset the failed state\ncalls: %v", fs.calls)
		}
		if fs.activeWord() != "active" {
			t.Fatalf("service did not reach active after reset-failed recovery, got %q", fs.activeWord())
		}
	})
	t.Run("unchanged unit on a failed unit resets then starts", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fs.setState("enabled", "failed")
		fs.calls = nil
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatalf("unchanged install over a failed unit failed: %v", err)
		}
		if !fs.callsContain("reset-failed warden.service") || !fs.callsContain("start warden.service") {
			t.Fatalf("unchanged install did not reset and start\ncalls: %v", fs.calls)
		}
		if fs.callsContain("daemon-reload") {
			t.Fatalf("unchanged install reloaded systemd needlessly\ncalls: %v", fs.calls)
		}
	})
	t.Run("fresh install tolerates reset-failed on an unloaded unit", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatalf("fresh install failed: %v", err)
		}
		if !fs.callsContain("reset-failed warden.service") {
			t.Fatalf("fresh install did not call reset-failed\ncalls: %v", fs.calls)
		}
		if fs.activeWord() != "active" {
			t.Fatalf("fresh install did not reach active, got %q", fs.activeWord())
		}
	})
	t.Run("reset-failed hard failure is reported distinctly", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fs.setState("enabled", "inactive")
		fs.failVerb = "reset-failed"
		err := m.install(testOpts("/config", "127.0.0.1:8081", "/"), os.Stderr)
		if err == nil {
			t.Fatal("install did not report the reset-failed failure")
		}
		if !strings.Contains(err.Error(), "clearing previous failed state") {
			t.Fatalf("reset-failed failure not attributed to the reset step: %v", err)
		}
	})
}

func TestInstallFailureRestoresPriorState(t *testing.T) {
	steps := []struct {
		verb string
		call string
	}{
		{"daemon-reload", "daemon-reload"},
		{"enable", "enable warden.service"},
		{"restart", "restart warden.service"},
	}
	t.Run("fresh install", func(t *testing.T) {
		for _, st := range steps {
			t.Run(st.verb, func(t *testing.T) {
				m, _, _ := newFakeManager(t)
				fs := newFakeSystemd(m.unitPath)
				m.run = fs.runner()
				fs.failVerb = st.verb
				err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr)
				if err == nil {
					t.Fatalf("install with %s failure did not fail", st.verb)
				}
				if _, statErr := os.Stat(m.unitPath); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("failed fresh install left the unit behind")
				}
				if fs.enabledWord() != "not-found" {
					t.Fatalf("failed fresh install left enablement %q", fs.enabledWord())
				}
				if fs.activeWord() != "inactive" {
					t.Fatalf("failed fresh install left active %q", fs.activeWord())
				}
			})
		}
	})
	t.Run("reinstall restores prior unit and lifecycle", func(t *testing.T) {
		for _, st := range steps {
			t.Run(st.verb, func(t *testing.T) {
				m, _, _ := newFakeManager(t)
				fs := newFakeSystemd(m.unitPath)
				m.run = fs.runner()
				if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
					t.Fatal(err)
				}
				priorUnit, _ := os.ReadFile(m.unitPath)
				fs.setState("enabled-runtime", "inactive")
				fs.failVerb = st.verb
				err := m.install(testOpts("/configY", "127.0.0.1:8083", "/"), os.Stderr)
				if err == nil {
					t.Fatalf("reinstall with %s failure did not fail", st.verb)
				}
				after, _ := os.ReadFile(m.unitPath)
				if string(priorUnit) != string(after) {
					t.Fatal("failed reinstall did not restore the prior unit bytes")
				}
				if fs.enabledWord() != "enabled-runtime" {
					t.Fatalf("rollback did not restore enablement %q", fs.enabledWord())
				}
				if fs.activeWord() != "inactive" {
					t.Fatalf("rollback did not restore active %q", fs.activeWord())
				}
			})
		}
	})
	t.Run("reinstall failure at restart restores enabled active prior", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fs.setState("enabled", "active")
		fs.failVerb = "restart"
		if err := m.install(testOpts("/configZ", "127.0.0.1:8084", "/"), os.Stderr); err == nil {
			t.Fatal("reinstall with restart failure did not fail")
		}
		if fs.enabledWord() != "enabled" || fs.activeWord() != "active" {
			t.Fatalf("rollback did not restore enabled+active, got %q/%q", fs.enabledWord(), fs.activeWord())
		}
	})
	t.Run("failed fresh install keeps no enablement link or active service", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		fs.failVerb = "restart"
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err == nil {
			t.Fatal("install did not fail")
		}
		word, _, _ := m.systemctl("is-enabled", m.unitName)
		if strings.TrimSpace(word) != "not-found" {
			t.Fatalf("unit still reports enablement %q after failed fresh install", word)
		}
		word2, _, _ := m.systemctl("is-active", m.unitName)
		if strings.TrimSpace(word2) != "inactive" {
			t.Fatalf("unit still reports active %q after failed fresh install", word2)
		}
		if _, statErr := os.Stat(m.unitPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("failed fresh install left the unit file")
		}
	})
}

// TestInstallInvalidUnitCleanRollback reproduces the real Ubuntu failure: a
// generated unit that systemd refuses to load. The install fails at restart
// with "bad unit file setting", the rollback's stop/disable see the unloadable
// unit as "does not exist" and must be tolerated as a clean absence, and the
// reported error must distinguish the invalid generated unit while leaving a
// retryable (unit-file-removed) state.
func TestInstallInvalidUnitCleanRollback(t *testing.T) {
	m, fr, _ := newFakeManager(t)
	fr.handler = func(name string, args ...string) (string, int, error) {
		switch {
		case fr.contains(args, "daemon-reload"):
			return "", 0, nil
		case fr.contains(args, "enable"):
			return "Created symlink", 0, nil
		case fr.contains(args, "restart"):
			return "Failed to restart warden.service: Unit warden.service has a bad unit file setting.", 1, nil
		case fr.contains(args, "stop"), fr.contains(args, "disable"):
			return "Failed to disable unit warden.service: Unit warden.service does not exist.", 1, nil
		}
		return "", 0, nil
	}
	err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr)
	if err == nil {
		t.Fatal("install with an unloadable unit did not fail")
	}
	if !strings.Contains(err.Error(), "generated unit is invalid") {
		t.Fatalf("install did not classify the invalid generated unit: %v", err)
	}
	if strings.Contains(err.Error(), "rollback incomplete") {
		t.Fatalf("rollback over an unloadable unit must be reported as clean: %v", err)
	}
	if _, statErr := os.Stat(m.unitPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("failed install left the unit file behind (state not retryable)")
	}
}

func TestInstallRefusesForeignUnit(t *testing.T) {
	m, _, _ := newFakeManager(t)
	if err := os.MkdirAll(filepath.Dir(m.unitPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.unitPath, []byte("# hand written\n[Service]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err == nil {
		t.Fatal("install overwrote a foreign unit")
	}
}

func TestInstallRefusesModifiedManagedUnit(t *testing.T) {
	m, _, _ := newFakeManager(t)
	if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
		t.Fatal(err)
	}
	unit, _ := os.ReadFile(m.unitPath)
	tampered := strings.Replace(string(unit), "Restart=on-failure", "Restart=always", 1)
	if err := os.WriteFile(m.unitPath, []byte(tampered), 0644); err != nil {
		t.Fatal(err)
	}
	if err := m.install(testOpts("/config", "127.0.0.1:8081", "/"), os.Stderr); err == nil {
		t.Fatal("install silently overwrote a modified managed unit")
	}
}

func TestActionsRequireManagedUnit(t *testing.T) {
	m, fr, _ := newFakeManager(t)
	if err := m.action("start", os.Stderr); err == nil {
		t.Fatal("start on a missing unit succeeded")
	}
	if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
		t.Fatal(err)
	}
	unit, _ := os.ReadFile(m.unitPath)
	if err := os.WriteFile(m.unitPath, []byte(strings.Replace(string(unit), "Restart=on-failure", "Restart=always", 1)), 0644); err != nil {
		t.Fatal(err)
	}
	fr.calls = nil
	if err := m.action("restart", os.Stderr); err == nil {
		t.Fatal("restart on a modified managed unit succeeded")
	}
	if len(fr.calls) != 0 {
		t.Fatalf("lifecycle command ran against a modified unit: %v", fr.calls)
	}
}

// TestActionsResetFailedBeforeStartRestart proves the deliberate activation
// paths (`service start`, `service restart`) clear accumulated failed state
// with reset-failed immediately before the activation and surface a real reset
// failure, and that `service stop` verifies the service actually stopped.
func TestActionsResetFailedBeforeStartRestart(t *testing.T) {
	t.Run("start clears failed state before activating", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fs.setState("enabled", "failed")
		fs.calls = nil
		if err := m.action("start", os.Stderr); err != nil {
			t.Fatalf("start over a failed unit failed: %v", err)
		}
		if !fs.callsContain("reset-failed warden.service") || !fs.callsContain("start warden.service") {
			t.Fatalf("start did not reset then activate\ncalls: %v", fs.calls)
		}
		if fs.activeWord() != "active" {
			t.Fatalf("service not active after start, got %q", fs.activeWord())
		}
	})
	t.Run("restart clears failed state before restarting", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fs.setState("enabled", "failed")
		fs.calls = nil
		if err := m.action("restart", os.Stderr); err != nil {
			t.Fatalf("restart over a failed unit failed: %v", err)
		}
		if !fs.callsContain("reset-failed warden.service") || !fs.callsContain("restart warden.service") {
			t.Fatalf("restart did not reset then restart\ncalls: %v", fs.calls)
		}
	})
	t.Run("reset-failed failure prevents start", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.calls = nil
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "reset-failed") {
				return "reset-failed failed", 1, nil
			}
			return "", 0, nil
		}
		err := m.action("start", os.Stderr)
		if err == nil {
			t.Fatal("start succeeded despite a reset-failed failure")
		}
		if !strings.Contains(err.Error(), "clearing previous failed state") {
			t.Fatalf("reset failure not attributed to the reset step: %v", err)
		}
		if strings.Contains(strings.Join(fr.calls, "\n"), "start warden.service") {
			t.Fatal("start ran after a reset-failed failure")
		}
	})
	t.Run("stop verifies the service actually stopped", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.calls = nil
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "active", 0, nil
			}
			return "", 0, nil
		}
		err := m.action("stop", os.Stderr)
		if err == nil {
			t.Fatal("stop succeeded although the service still reports active")
		}
		if !strings.Contains(err.Error(), "still reports") {
			t.Fatalf("stop verification failure not reported: %v", err)
		}
	})
}

// TestActionsReadinessGate proves `service start` and `service restart` apply
// the same bounded active-state plus Warden-identity readiness gate that
// install uses: a successful systemctl job is not enough. An immediate crash,
// an active-but-unhealthy process, a foreign process on the resolved listener,
// a readiness timeout and a state-query failure each return nonzero for both
// activation commands.
func TestActionsReadinessGate(t *testing.T) {
	origProbe, origDeadline, origInterval := healthProbe, installHealthDeadline, installHealthPollInterval
	t.Cleanup(func() {
		healthProbe, installHealthDeadline, installHealthPollInterval = origProbe, origDeadline, origInterval
	})
	installHealthPollInterval = time.Millisecond
	installHealthDeadline = 80 * time.Millisecond

	installAndReset := func(t *testing.T) (*serviceManager, *fakeRunner) {
		t.Helper()
		healthProbe = func(string) error { return nil }
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		fr := fs.runner()
		m.run = fr
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fs.setState("enabled", "active")
		fr.calls = nil
		return m, fr
	}

	t.Run("start verifies healthy activation", func(t *testing.T) {
		m, _ := installAndReset(t)
		healthProbe = func(string) error { return nil }
		if err := m.action("start", os.Stderr); err != nil {
			t.Fatalf("start on a healthy service failed: %v", err)
		}
	})
	t.Run("restart verifies healthy activation", func(t *testing.T) {
		m, _ := installAndReset(t)
		healthProbe = func(string) error { return nil }
		if err := m.action("restart", os.Stderr); err != nil {
			t.Fatalf("restart on a healthy service failed: %v", err)
		}
	})
	t.Run("start fails when the process crashes immediately after the start job", func(t *testing.T) {
		m, fr := installAndReset(t)
		orig := fr.handler
		healthProbe = func(string) error { return nil }
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "is-active") {
				return "failed", exitForActive("failed"), nil
			}
			return orig(name, args...)
		}
		err := m.action("start", os.Stderr)
		if err == nil {
			t.Fatal("start reported success for a service that crashed immediately")
		}
		if !strings.Contains(err.Error(), "did not become healthy") {
			t.Fatalf("immediate crash not attributed to the readiness gate: %v", err)
		}
	})
	t.Run("restart fails for an active but unhealthy process", func(t *testing.T) {
		m, fr := installAndReset(t)
		orig := fr.handler
		healthProbe = func(string) error { return errors.New("boom: not healthy") }
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "is-active") {
				return "active", 0, nil
			}
			return orig(name, args...)
		}
		err := m.action("restart", os.Stderr)
		if err == nil {
			t.Fatal("restart reported success for an unhealthy process")
		}
		if !strings.Contains(err.Error(), "health check failed") {
			t.Fatalf("unhealthy activation not reported: %v", err)
		}
	})
	t.Run("start rejects a foreign process on the resolved listener", func(t *testing.T) {
		// A plausible setup-shaped impostor ({"required":false}) answers the
		// resolved listener; the real healthCheck must reject it.
		srv := jsonServer(t, 200, `{"required":false}`, "application/json")
		m, _, base := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		fr2 := fs.runner()
		m.run = fr2
		configDir := filepath.Join(base, "config")
		if err := os.MkdirAll(configDir, 0700); err != nil {
			t.Fatal(err)
		}
		healthProbe = func(string) error { return nil }
		if err := m.install(testOpts(configDir, "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		listen := strings.TrimPrefix(srv.URL, "http://")
		if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"listen":"`+listen+`"}`), 0600); err != nil {
			t.Fatal(err)
		}
		fs.setState("enabled", "active")
		fr2.calls = nil
		orig := fr2.handler
		healthProbe = healthCheck
		fr2.handler = func(name string, args ...string) (string, int, error) {
			if fr2.contains(args, "is-active") {
				return "active", 0, nil
			}
			return orig(name, args...)
		}
		err := m.action("start", os.Stderr)
		if err == nil {
			t.Fatal("start reported success against a foreign process on the listener")
		}
		if !strings.Contains(err.Error(), "identity contract") {
			t.Fatalf("foreign listener rejection not attributed to identity: %v", err)
		}
	})
	t.Run("start fails when readiness times out", func(t *testing.T) {
		m, fr := installAndReset(t)
		orig := fr.handler
		healthProbe = func(string) error { return nil }
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "is-active") {
				return "activating", exitForActive("activating"), nil
			}
			return orig(name, args...)
		}
		err := m.action("start", os.Stderr)
		if err == nil {
			t.Fatal("start reported success for a service that never became ready")
		}
		if !strings.Contains(err.Error(), "did not become active and healthy") {
			t.Fatalf("readiness timeout not reported: %v", err)
		}
	})
	t.Run("restart fails on a state-query failure", func(t *testing.T) {
		m, fr := installAndReset(t)
		orig := fr.handler
		healthProbe = func(string) error { return nil }
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "is-active") {
				return "", -1, errors.New("systemctl not found")
			}
			return orig(name, args...)
		}
		err := m.action("restart", os.Stderr)
		if err == nil {
			t.Fatal("restart reported success despite a state-query failure")
		}
		if !strings.Contains(err.Error(), "did not become healthy") || !strings.Contains(err.Error(), "cannot verify") {
			t.Fatalf("state-query failure not surfaced: %v", err)
		}
	})
}

// TestInstallFinalStateQueryFailure proves the install's post-readiness
// confirmation query is transactional: a final is-active query error or a
// non-active result after a successful readiness check is a transaction
// failure that executes the same rollback as any other step, and a rollback
// failure is surfaced explicitly.
func TestInstallFinalStateQueryFailure(t *testing.T) {
	origProbe, origDeadline, origInterval := healthProbe, installHealthDeadline, installHealthPollInterval
	t.Cleanup(func() {
		healthProbe, installHealthDeadline, installHealthPollInterval = origProbe, origDeadline, origInterval
	})
	installHealthPollInterval = time.Millisecond
	installHealthDeadline = 80 * time.Millisecond
	healthProbe = func(string) error { return nil }

	run := func(t *testing.T, finalActive func(calls int) (string, int, error), failRollbackReload bool) (*serviceManager, error) {
		t.Helper()
		m, fr, _ := newFakeManager(t)
		activeCalls, reloads := 0, 0
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "daemon-reload"):
				reloads++
				if failRollbackReload && reloads == 2 {
					return "reload failed", 1, nil
				}
				return "", 0, nil
			case fr.contains(args, "is-active"):
				activeCalls++
				if activeCalls == 1 {
					return "active", 0, nil
				}
				return finalActive(activeCalls)
			case fr.contains(args, "is-enabled"):
				return "enabled", 0, nil
			}
			return "", 0, nil
		}
		err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr)
		return m, err
	}

	t.Run("final state query failure rolls back the fresh install", func(t *testing.T) {
		m, err := run(t, func(int) (string, int, error) { return "", -1, errors.New("bus gone") }, false)
		if err == nil {
			t.Fatal("install reported success despite a final state-query failure")
		}
		if !strings.Contains(err.Error(), "cannot confirm warden.service active state after install") {
			t.Fatalf("final query failure not reported: %v", err)
		}
		if strings.Contains(err.Error(), "rollback incomplete") {
			t.Fatalf("rollback should have been clean: %v", err)
		}
		if _, statErr := os.Stat(m.unitPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed install left the unit behind (state not retryable): %v", statErr)
		}
	})
	t.Run("final state inactive after readiness rolls back the fresh install", func(t *testing.T) {
		m, err := run(t, func(int) (string, int, error) { return "inactive", 3, nil }, false)
		if err == nil {
			t.Fatal("install reported success although the unit ended inactive")
		}
		if !strings.Contains(err.Error(), `ended "inactive"`) {
			t.Fatalf("non-active final state not reported: %v", err)
		}
		if strings.Contains(err.Error(), "rollback incomplete") {
			t.Fatalf("rollback should have been clean: %v", err)
		}
		if _, statErr := os.Stat(m.unitPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed install left the unit behind (state not retryable): %v", statErr)
		}
	})
	t.Run("rollback failure during the final-state query rollback is surfaced", func(t *testing.T) {
		m, err := run(t, func(int) (string, int, error) { return "", -1, errors.New("bus gone") }, true)
		if err == nil {
			t.Fatal("install reported success despite a final state-query failure")
		}
		if !strings.Contains(err.Error(), "rollback incomplete") || !strings.Contains(err.Error(), "reload systemd") {
			t.Fatalf("rollback failure not surfaced explicitly: %v", err)
		}
		if _, statErr := os.Stat(m.unitPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed install left the unit behind (state not retryable): %v", statErr)
		}
	})
	t.Run("rollback failure after a non-active final state is surfaced", func(t *testing.T) {
		m, err := run(t, func(int) (string, int, error) { return "inactive", 3, nil }, true)
		if err == nil {
			t.Fatal("install reported success although the unit ended inactive")
		}
		if !strings.Contains(err.Error(), "rollback incomplete") {
			t.Fatalf("rollback failure not surfaced explicitly: %v", err)
		}
		if _, statErr := os.Stat(m.unitPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed install left the unit behind (state not retryable): %v", statErr)
		}
	})
}

// TestInstallHealthGate covers the install-time readiness verification: after
// start/restart the install must require a valid active state and a successful
// /api/setup/status response within a bounded deadline, and must roll the
// install transaction back for every failure class (immediate failure,
// state-query failure, health timeout, invalid health response, not-found
// state). The real health probe is exercised against an httptest server at the
// end.
func TestInstallHealthGate(t *testing.T) {
	origProbe, origDeadline, origInterval := healthProbe, installHealthDeadline, installHealthPollInterval
	t.Cleanup(func() {
		healthProbe, installHealthDeadline, installHealthPollInterval = origProbe, origDeadline, origInterval
	})
	installHealthPollInterval = time.Millisecond
	installHealthDeadline = 80 * time.Millisecond

	t.Run("delayed successful startup waits for active and health", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		fr := fs.runner()
		orig := fr.handler
		healthCalls := 0
		healthProbe = func(string) error { healthCalls++; return nil }
		// Simulate delayed readiness: the first three is-active polls report a
		// transitional state before the service becomes active.
		activeCalls := 0
		m.run = fr
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "is-active") {
				activeCalls++
				if activeCalls < 3 {
					return "activating", exitForActive("activating"), nil
				}
				return "active", 0, nil
			}
			return orig(name, args...)
		}
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatalf("delayed startup should install successfully: %v", err)
		}
		if healthCalls == 0 {
			t.Fatal("health probe was never invoked after the service became active")
		}
	})

	t.Run("immediate process failure after start fails and rolls back", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		fr := fs.runner()
		orig := fr.handler
		healthProbe = func(string) error { return nil }
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "is-active") {
				return "failed", exitForActive("failed"), nil
			}
			return orig(name, args...)
		}
		m.run = fr
		err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr)
		if err == nil {
			t.Fatal("install reported success for a service that failed immediately")
		}
		if !strings.Contains(err.Error(), "immediately after start") {
			t.Fatalf("immediate failure not attributed to the health gate: %v", err)
		}
		if _, statErr := os.Stat(m.unitPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("failed fresh install did not roll back the unit file")
		}
	})

	t.Run("not-found state after start fails and rolls back", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		fr := fs.runner()
		orig := fr.handler
		healthProbe = func(string) error { return nil }
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "is-active") {
				return "not-found", exitForActive("not-found"), nil
			}
			return orig(name, args...)
		}
		m.run = fr
		err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr)
		if err == nil {
			t.Fatal("install reported success for a not-found unit")
		}
		if _, statErr := os.Stat(m.unitPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("failed install did not roll back the unit file")
		}
	})

	t.Run("active service with failing health fails and rolls back", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		fr := fs.runner()
		orig := fr.handler
		healthProbe = func(string) error { return errors.New("boom: not healthy") }
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "is-active") {
				return "active", 0, nil
			}
			return orig(name, args...)
		}
		m.run = fr
		err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr)
		if err == nil {
			t.Fatal("install reported success with a failing health check")
		}
		if !strings.Contains(err.Error(), "health check failed") {
			t.Fatalf("failing health not reported: %v", err)
		}
		if _, statErr := os.Stat(m.unitPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("failed install did not roll back the unit file")
		}
	})

	t.Run("health timeout fails and rolls back", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		fr := fs.runner()
		orig := fr.handler
		healthProbe = func(string) error { return nil }
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "is-active") {
				return "activating", exitForActive("activating"), nil
			}
			return orig(name, args...)
		}
		m.run = fr
		err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr)
		if err == nil {
			t.Fatal("install reported success for a service that never became ready")
		}
		if !strings.Contains(err.Error(), "did not become active and healthy") {
			t.Fatalf("timeout not reported: %v", err)
		}
		if _, statErr := os.Stat(m.unitPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("timed-out install did not roll back the unit file")
		}
	})

	t.Run("state-query failure fails and rolls back", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		fr := fs.runner()
		orig := fr.handler
		healthProbe = func(string) error { return nil }
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "is-active") {
				return "", -1, errors.New("systemctl not found")
			}
			return orig(name, args...)
		}
		m.run = fr
		err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr)
		if err == nil {
			t.Fatal("install reported success despite a state-query failure")
		}
		if !strings.Contains(err.Error(), "cannot verify warden.service state after start") {
			t.Fatalf("state-query failure not reported: %v", err)
		}
		if _, statErr := os.Stat(m.unitPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("failed install did not roll back the unit file")
		}
	})

	t.Run("reinstall health failure restores the prior working install", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		priorUnit, _ := os.ReadFile(m.unitPath)
		fs.setState("enabled", "active")
		healthProbe = func(string) error { return errors.New("health broken") }
		err := m.install(testOpts("/config", "127.0.0.1:8081", "/"), os.Stderr)
		if err == nil {
			t.Fatal("reinstall reported success despite failing health")
		}
		after, _ := os.ReadFile(m.unitPath)
		if string(after) != string(priorUnit) {
			t.Fatal("failed reinstall did not restore the prior working unit")
		}
		ew, _, _ := m.systemctl("is-enabled", m.unitName)
		aw, _, _ := m.systemctl("is-active", m.unitName)
		if strings.TrimSpace(ew) != "enabled" || strings.TrimSpace(aw) != "active" {
			t.Fatalf("rollback final state %q/%q want enabled/active", ew, aw)
		}
	})

	t.Run("real health probe succeeds against a live endpoint", func(t *testing.T) {
		hit := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == wardenHealthPath {
				hit = true
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"required":false,"legacyPasswordRequired":false,"tokenRequired":true,"googleEnabled":false,"ok":true,"service":"warden"}`))
				return
			}
			http.NotFound(w, r)
		}))
		t.Cleanup(srv.Close)
		m, _, _ := newFakeManager(t)
		fs := newFakeSystemd(m.unitPath)
		m.run = fs.runner()
		healthProbe = healthCheck
		opts := testOpts("/config", strings.TrimPrefix(srv.URL, "http://"), "/")
		if err := m.install(opts, os.Stderr); err != nil {
			t.Fatalf("install with a live healthy endpoint failed: %v", err)
		}
		if !hit {
			t.Fatal("the install health gate never probed the live endpoint")
		}
	})
}

// TestHealthCheckRequiresWardenContract verifies the identity contract of the
// install health gate: only a 2xx JSON object carrying the exact identity
// values (ok:true, service:"warden") and the setup-status `required` boolean is
// accepted, so a foreign JSON-speaking process cannot impersonate Warden with a
// plausible setup-shaped body such as {"required":false} alone.
func TestHealthCheckRequiresWardenContract(t *testing.T) {
	probe := func(code int, body, ct string) error {
		srv := jsonServer(t, code, body, ct)
		return healthCheck(srv.URL + wardenHealthPath)
	}
	if err := probe(200, healthIdentityBody, "application/json"); err != nil {
		t.Fatalf("the real Warden health identity contract must pass: %v", err)
	}
	if err := probe(200, `{"required":true,"legacyPasswordRequired":false,"tokenRequired":true,"googleEnabled":false,"ok":true,"service":"warden"}`, "application/json"); err != nil {
		t.Fatalf("a setup-required Warden response must pass: %v", err)
	}
	if err := probe(200, `{"required":false,"ok":true,"service":"warden","extra":1}`, "application/json"); err != nil {
		t.Fatalf("a body with exact identity values must pass: %v", err)
	}
	for _, c := range []struct {
		code     int
		body, ct string
	}{
		// A plausible setup-shaped impostor body is rejected: it carries the
		// `required` boolean but none of the identity values.
		{200, `{"required":false}`, "application/json"},
		{200, `{"required":true,"legacyPasswordRequired":false,"tokenRequired":true,"googleEnabled":false}`, "application/json"},
		{200, `{"required":false,"ok":true}`, "application/json"},
		{200, `{"required":false,"service":"warden"}`, "application/json"},
		{200, `{"required":false,"ok":true,"service":"cortex"}`, "application/json"},
		{200, `{"required":false,"ok":false,"service":"warden"}`, "application/json"},
		{200, `{"required":false,"ok":"true","service":"warden"}`, "application/json"},
		{200, `{"ok":true,"service":"warden"}`, "application/json"},
		{200, `{"required":false,"ok":1,"service":"warden"}`, "application/json"},
		{200, `{"required":false,"ok":true,"service":42}`, "application/json"},
		{200, `{}`, "application/json"},
		{200, `{"ok":true}`, "application/json"},
		{200, `{"required":"false","ok":true,"service":"warden"}`, "application/json"},
		{200, `[1,2,3]`, "application/json"},
		{200, `{"required":false}`, "text/plain"},
		{200, `not json at all`, "application/json"},
		{500, `{"required":false,"ok":true,"service":"warden"}`, "application/json"},
		{404, `{"required":false,"ok":true,"service":"warden"}`, "application/json"},
	} {
		if err := probe(c.code, c.body, c.ct); err == nil {
			t.Fatalf("health check accepted an impostor response %d %q %q", c.code, c.body, c.ct)
		}
	}
}

// TestInstallIdenticalEnabledActiveUnhealthy proves the identical no-op install
// still requires the Warden readiness contract: an enabled, active but wedged
// (or incorrectly listening) service is reported as an install failure without
// any systemd mutation, because the no-op path made no changes and needs no
// rollback.
func TestInstallIdenticalEnabledActiveUnhealthy(t *testing.T) {
	origProbe := healthProbe
	t.Cleanup(func() { healthProbe = origProbe })
	m, _, _ := newFakeManager(t)
	fs := newFakeSystemd(m.unitPath)
	m.run = fs.runner()
	if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
		t.Fatal(err)
	}
	fs.setState("enabled", "active")
	fs.calls = nil
	healthProbe = func(string) error { return errors.New("wedged: /api/setup/status not answering") }
	err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr)
	if err == nil {
		t.Fatal("identical install reported success despite a wedged health endpoint")
	}
	for _, forbid := range []string{"daemon-reload", "enable ", "restart ", "start ", "stop ", "reset-failed"} {
		if fs.callsContain(forbid) {
			t.Fatalf("identical-unhealthy install mutated systemd (%q)\ncalls: %v", forbid, fs.calls)
		}
	}
}

func TestUninstallFailClosed(t *testing.T) {
	t.Run("active and enabled", func(t *testing.T) {
		m, fr, base := newFakeManager(t)
		configDir := filepath.Join(base, "warden-config")
		if err := os.MkdirAll(configDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"listen":"127.0.0.1:8080"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := m.install(testOpts(configDir, "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				if fr.saw("stop warden.service") {
					return "inactive", 3, nil
				}
				return "active", 0, nil
			case fr.contains(args, "is-enabled"):
				if fr.saw("disable warden.service") {
					return "disabled", 1, nil
				}
				return "enabled", 0, nil
			}
			return "", 0, nil
		}
		if err := m.uninstall(os.Stderr); err != nil {
			t.Fatalf("uninstall: %v", err)
		}
		if _, err := os.Stat(m.unitPath); !os.IsNotExist(err) {
			t.Fatal("unit still present after uninstall")
		}
		if _, err := os.Stat(filepath.Join(configDir, "config.json")); err != nil {
			t.Fatalf("config removed by uninstall: %v", err)
		}
		joined := strings.Join(fr.calls, "\n")
		for _, want := range []string{"systemctl --user stop warden.service", "systemctl --user disable warden.service", "systemctl --user daemon-reload"} {
			if !strings.Contains(joined, want) {
				t.Fatalf("uninstall did not call %q\n%s", want, joined)
			}
		}
	})
	t.Run("inactive and disabled with normal exit codes", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.calls = nil
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "inactive", 3, nil
			case fr.contains(args, "is-enabled"):
				return "disabled", 1, nil
			}
			return "", 0, nil
		}
		if err := m.uninstall(os.Stderr); err != nil {
			t.Fatalf("uninstall with inactive/disabled states: %v", err)
		}
		if _, err := os.Stat(m.unitPath); !os.IsNotExist(err) {
			t.Fatal("unit still present after uninstall")
		}
		joined := strings.Join(fr.calls, "\n")
		if strings.Contains(joined, "stop warden.service") {
			t.Fatalf("stop was attempted on an inactive unit: %s", joined)
		}
		if strings.Contains(joined, "disable warden.service") {
			t.Fatalf("disable was attempted on a disabled unit: %s", joined)
		}
	})
	t.Run("stop failure is not swallowed", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.calls = nil
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "active", 0, nil
			case fr.contains(args, "stop"):
				return "Failed to stop", 1, nil
			}
			return "", 0, nil
		}
		if err := m.uninstall(os.Stderr); err == nil {
			t.Fatal("uninstall succeeded despite stop failure")
		}
		if _, err := os.Stat(m.unitPath); err != nil {
			t.Fatalf("unit was removed despite stop failure: %v", err)
		}
	})
	t.Run("modified unit is refused", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		unit, _ := os.ReadFile(m.unitPath)
		if err := os.WriteFile(m.unitPath, []byte(strings.Replace(string(unit), "Restart=on-failure", "Restart=always", 1)), 0644); err != nil {
			t.Fatal(err)
		}
		if err := m.uninstall(os.Stderr); err == nil {
			t.Fatal("uninstall removed a modified managed unit")
		}
		if _, err := os.Stat(m.unitPath); err != nil {
			t.Fatalf("unit removed despite modification: %v", err)
		}
	})
}

func TestUninstallStateQueryFailures(t *testing.T) {
	t.Run("is-active launch failure", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.calls = nil
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "is-active") {
				return "", -1, errors.New("systemctl not found")
			}
			return "", 0, nil
		}
		if err := m.uninstall(os.Stderr); err == nil {
			t.Fatal("uninstall ignored an is-active launch failure")
		}
		if _, err := os.Stat(m.unitPath); err != nil {
			t.Fatalf("unit removed despite query failure: %v", err)
		}
		joined := strings.Join(fr.calls, "\n")
		if strings.Contains(joined, "stop warden.service") || strings.Contains(joined, "disable warden.service") || strings.Contains(joined, "daemon-reload") {
			t.Fatalf("destructive steps ran after an active-state query failure: %s", joined)
		}
	})
	t.Run("is-active bus failure is not read as inactive", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "is-active") {
				return "Failed to connect to bus: No such file or directory", 1, nil
			}
			return "", 0, nil
		}
		if err := m.uninstall(os.Stderr); err == nil {
			t.Fatal("uninstall treated a bus failure as inactive")
		} else if !strings.Contains(err.Error(), "unrecognized") {
			t.Fatalf("bus failure should surface as unrecognized state, got: %v", err)
		}
		if _, serr := os.Stat(m.unitPath); serr != nil {
			t.Fatalf("unit removed despite bus failure: %v", serr)
		}
	})
	t.Run("unrecognized is-active output", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "is-active") {
				return "something-else", 1, nil
			}
			return "", 0, nil
		}
		if err := m.uninstall(os.Stderr); err == nil {
			t.Fatal("uninstall accepted unrecognized is-active output")
		}
		if _, err := os.Stat(m.unitPath); err != nil {
			t.Fatalf("unit removed despite unrecognized state: %v", err)
		}
	})
	t.Run("is-enabled bus failure", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.calls = nil
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "inactive", 3, nil
			case fr.contains(args, "is-enabled"):
				return "Failed to connect to bus: No such file or directory", 1, nil
			}
			return "", 0, nil
		}
		if err := m.uninstall(os.Stderr); err == nil {
			t.Fatal("uninstall ignored an is-enabled bus failure")
		}
		if _, err := os.Stat(m.unitPath); err != nil {
			t.Fatalf("unit removed despite enablement query failure: %v", err)
		}
		joined := strings.Join(fr.calls, "\n")
		if strings.Contains(joined, "disable warden.service") || strings.Contains(joined, "daemon-reload") {
			t.Fatalf("disable/reload ran after an enablement query failure: %s", joined)
		}
	})
}

func TestWardenEffectiveListen(t *testing.T) {
	dir := t.TempDir()
	if got, err := wardenEffectiveListen(dir, "127.0.0.1:8080"); err != nil || got != "127.0.0.1:8080" {
		t.Fatalf("fallback = %q, %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"listen":"127.0.0.1:9000"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := wardenEffectiveListen(dir, "127.0.0.1:8080"); err != nil || got != "127.0.0.1:9000" {
		t.Fatalf("durable config listen = %q, %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`not json`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := wardenEffectiveListen(dir, "127.0.0.1:8080"); err == nil {
		t.Fatal("malformed durable config should error")
	}
}

func TestStatus(t *testing.T) {
	t.Run("missing unit", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		if err := m.status(os.Stderr, "1.0"); err == nil {
			t.Fatal("status of a missing unit should fail")
		}
	})
	t.Run("invalid unit", func(t *testing.T) {
		m, _, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		unit, _ := os.ReadFile(m.unitPath)
		if err := os.WriteFile(m.unitPath, []byte(strings.Replace(string(unit), "Restart=on-failure", "Restart=always", 1)), 0644); err != nil {
			t.Fatal(err)
		}
		if err := m.status(os.Stderr, "1.0"); err == nil {
			t.Fatal("status of an invalid unit should fail")
		}
	})
	t.Run("inactive service", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "inactive", 3, nil
			case fr.contains(args, "is-enabled"):
				return "enabled", 0, nil
			}
			return "", 0, nil
		}
		if err := m.status(os.Stderr, "1.0"); err == nil {
			t.Fatal("status of an inactive service should fail")
		}
	})
	t.Run("surfaces is-active bus failure", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "Failed to connect to bus", 1, nil
			case fr.contains(args, "is-enabled"):
				return "enabled", 0, nil
			}
			return "", 0, nil
		}
		err := m.status(os.Stderr, "1.0")
		if err == nil {
			t.Fatal("status swallowed an is-active bus failure")
		}
		if !strings.Contains(err.Error(), "unrecognized") {
			t.Fatalf("bus failure should surface as unrecognized state: %v", err)
		}
	})
	t.Run("durable config overrides bootstrap listen", func(t *testing.T) {
		srv := jsonServer(t, 200, healthIdentityBody, "application/json")
		effective := strings.TrimPrefix(srv.URL, "http://")
		m, fr, base := newFakeManager(t)
		configDir := filepath.Join(base, "config")
		if err := os.MkdirAll(configDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := m.install(testOpts(configDir, "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"listen":"`+effective+`"}`), 0600); err != nil {
			t.Fatal(err)
		}
		fr.handler = activeHandler(fr)
		if err := m.status(os.Stderr, "1.0"); err != nil {
			t.Fatalf("status with durable listen failed: %v", err)
		}
	})
	t.Run("404 health response", func(t *testing.T) {
		srv := jsonServer(t, 404, `{"error":"not found"}`, "application/json")
		m, fr, base := newFakeManager(t)
		configDir := filepath.Join(base, "config")
		if err := os.MkdirAll(configDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := m.install(testOpts(configDir, strings.TrimPrefix(srv.URL, "http://"), "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"listen":"`+strings.TrimPrefix(srv.URL, "http://")+`"}`), 0600); err != nil {
			t.Fatal(err)
		}
		fr.handler = activeHandler(fr)
		if err := m.status(os.Stderr, "1.0"); err == nil {
			t.Fatal("status with a 404 health response should fail")
		}
	})
	t.Run("401 health response", func(t *testing.T) {
		srv := jsonServer(t, 401, `{"error":"unauthorized"}`, "application/json")
		m, fr, base := newFakeManager(t)
		configDir := filepath.Join(base, "config")
		if err := os.MkdirAll(configDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := m.install(testOpts(configDir, strings.TrimPrefix(srv.URL, "http://"), "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"listen":"`+strings.TrimPrefix(srv.URL, "http://")+`"}`), 0600); err != nil {
			t.Fatal(err)
		}
		fr.handler = activeHandler(fr)
		if err := m.status(os.Stderr, "1.0"); err == nil {
			t.Fatal("status with a 401 health response should fail")
		}
	})
	t.Run("non-JSON 200 health response", func(t *testing.T) {
		srv := jsonServer(t, 200, `ok`, "text/plain")
		m, fr, base := newFakeManager(t)
		configDir := filepath.Join(base, "config")
		if err := os.MkdirAll(configDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := m.install(testOpts(configDir, strings.TrimPrefix(srv.URL, "http://"), "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"listen":"`+strings.TrimPrefix(srv.URL, "http://")+`"}`), 0600); err != nil {
			t.Fatal(err)
		}
		fr.handler = activeHandler(fr)
		if err := m.status(os.Stderr, "1.0"); err == nil {
			t.Fatal("status with a non-JSON 200 health response should fail")
		}
	})
}

func TestStatusReportsListenerURL(t *testing.T) {
	srv := jsonServer(t, 200, healthIdentityBody, "application/json")
	listen := strings.TrimPrefix(srv.URL, "http://")
	m, fr, base := newFakeManager(t)
	configDir := filepath.Join(base, "config")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.install(testOpts(configDir, listen, "/"), os.Stderr); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"listen":"`+listen+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	fr.handler = activeHandler(fr)
	var out bytes.Buffer
	if err := m.status(&out, "1.0"); err != nil {
		t.Fatalf("status failed: %v", err)
	}
	if !strings.Contains(out.String(), "listen:  "+listen) {
		t.Fatalf("status missing listen address:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "url:     http://"+listen) {
		t.Fatalf("status missing effective listener URL:\n%s", out.String())
	}
}

func splitListen(t *testing.T, addr string) (string, string) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return h, p
}

func TestWardenListenModeMarkers(t *testing.T) {
	explicit := buildWardenUnit("/usr/local/bin/warden", wardenTestOptsHostPort("/config", "127.0.0.1", "7332", "/"))
	if !strings.Contains(explicit, "# warden-listen-mode: explicit") {
		t.Fatalf("host/port unit missing explicit mode marker:\n%s", explicit)
	}
	if _, err := readManagedUnitBytes(t, []byte(explicit)); err != nil {
		t.Fatalf("explicit unit should validate: %v", err)
	}
	legacy := buildWardenUnit("/usr/local/bin/warden", testOpts("/config", "127.0.0.1:8080", "/"))
	if !strings.Contains(legacy, "# warden-listen-mode: bootstrap") {
		t.Fatalf("legacy unit missing bootstrap mode marker:\n%s", legacy)
	}
	if _, err := readManagedUnitBytes(t, []byte(legacy)); err != nil {
		t.Fatalf("legacy unit should validate: %v", err)
	}
	// A hostile mode value is rejected.
	bad := strings.Replace(legacy, "# warden-listen-mode: bootstrap", "# warden-listen-mode: attacker", 1)
	if _, err := readManagedUnitBytes(t, []byte(bad)); err == nil {
		t.Fatal("invalid listen-mode accepted")
	}
}

func TestStatusUsesExplicitUnitListenerOverConfig(t *testing.T) {
	// A new host/port unit records an authoritative listener; status must
	// report and health-check it even when config.json holds an older address.
	srv := jsonServer(t, 200, healthIdentityBody, "application/json")
	unitListen := strings.TrimPrefix(srv.URL, "http://")
	host, port := splitListen(t, unitListen)
	m, fr, base := newFakeManager(t)
	configDir := filepath.Join(base, "config")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.install(wardenTestOptsHostPort(configDir, host, port, "/"), os.Stderr); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"listen":"127.0.0.1:8080"}`), 0600); err != nil {
		t.Fatal(err)
	}
	fr.handler = activeHandler(fr)
	var out bytes.Buffer
	if err := m.status(&out, "1.0"); err != nil {
		t.Fatalf("status failed: %v", err)
	}
	if !strings.Contains(out.String(), "listen:  "+unitListen) {
		t.Fatalf("explicit unit status must use the recorded listener, got:\n%s", out.String())
	}
	if strings.Contains(out.String(), "8080") {
		t.Fatalf("explicit unit status must not fall back to durable config:\n%s", out.String())
	}
}

func TestStatusLegacyUsesDurableConfig(t *testing.T) {
	// A legacy --listen unit resolves its effective listener from config.json.
	srv := jsonServer(t, 200, healthIdentityBody, "application/json")
	configListen := strings.TrimPrefix(srv.URL, "http://")
	m, fr, base := newFakeManager(t)
	configDir := filepath.Join(base, "config")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.install(testOpts(configDir, "127.0.0.1:8080", "/"), os.Stderr); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"listen":"`+configListen+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	fr.handler = activeHandler(fr)
	var out bytes.Buffer
	if err := m.status(&out, "1.0"); err != nil {
		t.Fatalf("status failed: %v", err)
	}
	if !strings.Contains(out.String(), "listen:  "+configListen) {
		t.Fatalf("legacy unit status must use durable config listener, got:\n%s", out.String())
	}
}

func TestReinstallChangesUnitListenerWithoutConfig(t *testing.T) {
	// Reinstalling with a different --port rewrites the unit's --host/--port and
	// leaves the runtime listener authoritative without creating config.json.
	m, _, _ := newFakeManager(t)
	fsd := newFakeSystemd(m.unitPath)
	m.run = fsd.runner()
	configDir := "/config"
	opts1 := wardenTestOptsHostPort(configDir, "127.0.0.1", "7402", "/")
	if err := m.install(opts1, os.Stderr); err != nil {
		t.Fatal(err)
	}
	unit1, _ := os.ReadFile(m.unitPath)
	if !strings.Contains(string(unit1), `"--port" "7402"`) {
		t.Fatalf("first install must record 7402:\n%s", unit1)
	}
	if !strings.Contains(string(unit1), "# warden-listen-mode: explicit") {
		t.Fatalf("first install must be explicit mode:\n%s", unit1)
	}
	fsd.setState("enabled", "active")
	fsd.calls = nil
	opts2 := wardenTestOptsHostPort(configDir, "127.0.0.1", "7403", "/")
	if err := m.install(opts2, os.Stderr); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	unit2, _ := os.ReadFile(m.unitPath)
	if !strings.Contains(string(unit2), `"--port" "7403"`) {
		t.Fatalf("reinstall must record 7403:\n%s", unit2)
	}
	if !strings.Contains(string(unit2), "# warden-listen-mode: explicit") {
		t.Fatalf("reinstall unit must remain explicit mode:\n%s", unit2)
	}
	if !fsd.callsContain("restart ") {
		t.Fatalf("changed listener must restart the service\ncalls: %v", fsd.calls)
	}
	if _, err := os.Stat(filepath.Join(configDir, "config.json")); !os.IsNotExist(err) {
		t.Fatal("service install must not create config.json")
	}
}

func TestInstallHonorsLegacyWardenListenEnv(t *testing.T) {
	// WARDEN_LISTEN drives a legacy bootstrap install when no new host/port form
	// is selected.
	t.Setenv("WARDEN_LISTEN", "127.0.0.1:8080")
	os.Unsetenv("WARDEN_HOST")
	os.Unsetenv("WARDEN_PORT")
	h, p, l, hs, ps, ls := listenerFlags()
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:8080" {
		t.Fatalf("WARDEN_LISTEN install address = %q", addr)
	}
	opts, err := installOptions("/config", "/", addr, true)
	if err != nil {
		t.Fatal(err)
	}
	unit := buildWardenUnit("/usr/local/bin/warden", opts)
	if !strings.Contains(unit, `"--listen" "127.0.0.1:8080"`) {
		t.Fatalf("legacy install must record --listen:\n%s", unit)
	}
	if !strings.Contains(unit, "# warden-listen-mode: bootstrap") {
		t.Fatalf("legacy install must be bootstrap mode:\n%s", unit)
	}
}

func TestStatusIgnoresMalformedListenerEnv(t *testing.T) {
	// Non-install service commands must ignore malformed WARDEN_HOST/WARDEN_PORT
	// in the invoking shell.
	srv := jsonServer(t, 200, healthIdentityBody, "application/json")
	listen := strings.TrimPrefix(srv.URL, "http://")
	t.Setenv("WARDEN_HOST", "not a host")
	t.Setenv("WARDEN_PORT", "not-a-port")
	m, fr, base := newFakeManager(t)
	configDir := filepath.Join(base, "config")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.install(testOpts(configDir, listen, "/"), os.Stderr); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"listen":"`+listen+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	fr.handler = activeHandler(fr)
	var out bytes.Buffer
	if err := m.status(&out, "1.0"); err != nil {
		t.Fatalf("status must ignore malformed listener env: %v", err)
	}
	if !strings.Contains(out.String(), "listen:  "+listen) {
		t.Fatalf("status output missing listener:\n%s", out.String())
	}
}

func TestStrictExitFailures(t *testing.T) {
	t.Run("install daemon-reload nonzero prevents enable and restart", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "daemon-reload") {
				return "Failed to reload", 1, nil
			}
			return "", 0, nil
		}
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err == nil {
			t.Fatal("install succeeded despite a failed daemon-reload")
		}
		joined := strings.Join(fr.calls, "\n")
		if strings.Contains(joined, "enable warden.service") || strings.Contains(joined, "restart warden.service") {
			t.Fatalf("enable/restart ran after a failed daemon-reload: %s", joined)
		}
	})
	t.Run("install enable nonzero prevents restart", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "enable") {
				return "Failed to enable", 1, nil
			}
			return "", 0, nil
		}
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err == nil {
			t.Fatal("install succeeded despite a failed enable")
		}
		if strings.Contains(strings.Join(fr.calls, "\n"), "restart warden.service") {
			t.Fatal("restart ran after a failed enable")
		}
	})
	t.Run("install restart nonzero reports failure", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "restart") {
				return "Failed to start", 1, nil
			}
			return "", 0, nil
		}
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err == nil {
			t.Fatal("install succeeded despite a failed restart")
		}
	})
	t.Run("lifecycle start/stop/restart nonzero reports failure", func(t *testing.T) {
		for _, verb := range []string{"start", "stop", "restart"} {
			m, fr, _ := newFakeManager(t)
			if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
				t.Fatal(err)
			}
			fr.calls = nil
			fr.handler = func(name string, args ...string) (string, int, error) {
				if fr.contains(args, verb) {
					return "Failed", 1, nil
				}
				return "", 0, nil
			}
			if err := m.action(verb, os.Stderr); err == nil {
				t.Fatalf("%s succeeded despite a nonzero exit", verb)
			}
		}
	})
	t.Run("uninstall stop nonzero preserves the unit", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.calls = nil
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "active", 0, nil
			case fr.contains(args, "stop"):
				return "Failed to stop", 1, nil
			}
			return "", 0, nil
		}
		if err := m.uninstall(os.Stderr); err == nil {
			t.Fatal("uninstall succeeded despite a failed stop")
		}
		if _, err := os.Stat(m.unitPath); err != nil {
			t.Fatalf("unit removed despite stop failure: %v", err)
		}
		joined := strings.Join(fr.calls, "\n")
		if strings.Contains(joined, "disable warden.service") || strings.Contains(joined, "daemon-reload") {
			t.Fatalf("disable/reload ran after a failed stop: %s", joined)
		}
	})
	t.Run("uninstall disable nonzero preserves the unit", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.calls = nil
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "inactive", 3, nil
			case fr.contains(args, "is-enabled"):
				return "enabled", 0, nil
			case fr.contains(args, "disable"):
				return "Failed to disable", 1, nil
			}
			return "", 0, nil
		}
		if err := m.uninstall(os.Stderr); err == nil {
			t.Fatal("uninstall succeeded despite a failed disable")
		}
		if _, err := os.Stat(m.unitPath); err != nil {
			t.Fatalf("unit removed despite disable failure: %v", err)
		}
		if strings.Contains(strings.Join(fr.calls, "\n"), "daemon-reload") {
			t.Fatal("daemon-reload ran after a failed disable")
		}
	})
	t.Run("final daemon-reload nonzero is reported", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.calls = nil
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "inactive", 3, nil
			case fr.contains(args, "is-enabled"):
				return "disabled", 1, nil
			case fr.contains(args, "daemon-reload"):
				return "Failed to reload", 1, nil
			}
			return "", 0, nil
		}
		err := m.uninstall(os.Stderr)
		if err == nil {
			t.Fatal("uninstall did not report the daemon-reload failure")
		}
		if !strings.Contains(err.Error(), "reloading systemd") {
			t.Fatalf("daemon-reload failure not reported accurately: %v", err)
		}
	})
	t.Run("logs reports nonzero journalctl", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.handler = func(name string, args ...string) (string, int, error) {
			if name == "journalctl" {
				return "no journal found", 1, nil
			}
			return "", 0, nil
		}
		if err := m.logs(false, os.Stderr); err == nil {
			t.Fatal("logs ignored a nonzero journalctl exit")
		}
	})
}

func stateTestManager(t *testing.T, activeOut string, activeCode int, enabledOut string, enabledCode int) (*serviceManager, *fakeRunner) {
	t.Helper()
	m, fr, _ := newFakeManager(t)
	fr.handler = func(name string, args ...string) (string, int, error) {
		switch {
		case fr.contains(args, "is-active"):
			return activeOut, activeCode, nil
		case fr.contains(args, "is-enabled"):
			return enabledOut, enabledCode, nil
		}
		return "", 0, nil
	}
	return m, fr
}

func TestStateExitValidation(t *testing.T) {
	valid := []struct {
		verb, out string
		code      int
		want      svcState
	}{
		// is-active exit-0 states: active and reloading (v252-256), plus
		// refreshing from v257; refreshing accepts either exit.
		{"is-active", "active", 0, stateActive},
		{"is-active", "reloading", 0, stateReloading},
		{"is-active", "refreshing", 0, stateRefreshing},
		{"is-active", "refreshing", 3, stateRefreshing},
		{"is-active", "inactive", 3, stateInactive},
		{"is-active", "dead", 3, stateInactive},
		{"is-active", "failed", 3, stateInactive},
		{"is-active", "activating", 3, stateTransition},
		{"is-active", "deactivating", 3, stateTransition},
		{"is-active", "maintenance", 3, stateTransition},
		{"is-active", "unknown", 3, stateUnknown},
		{"is-active", "not-found", 3, stateUnknown},
		{"is-active", "not-found", 4, stateUnknown},
		// is-enabled: only enabled/enabled-runtime are lifecycle enabled.
		{"is-enabled", "enabled", 0, stateEnabled},
		{"is-enabled", "enabled-runtime", 0, stateEnabled},
		// static/alias/indirect/generated exit 0 but are lifecycle not-enabled.
		{"is-enabled", "static", 0, stateNotEnabled},
		{"is-enabled", "alias", 0, stateNotEnabled},
		{"is-enabled", "indirect", 0, stateNotEnabled},
		{"is-enabled", "generated", 0, stateNotEnabled},
		{"is-enabled", "disabled", 1, stateNotEnabled},
		{"is-enabled", "linked", 1, stateNotEnabled},
		{"is-enabled", "linked-runtime", 1, stateNotEnabled},
		{"is-enabled", "transient", 1, stateNotEnabled},
		{"is-enabled", "not-found", 4, stateNotEnabled},
		{"is-enabled", "not-found", 1, stateNotEnabled},
		{"is-enabled", "masked", 1, stateMasked},
		{"is-enabled", "masked-runtime", 1, stateMasked},
	}
	for _, tc := range valid {
		m, _ := stateTestManager(t, tc.out, tc.code, tc.out, tc.code)
		got, err := m.queryState(tc.verb)
		if err != nil {
			t.Fatalf("%s %q exit %d: unexpected error %v", tc.verb, tc.out, tc.code, err)
		}
		if got != tc.want {
			t.Fatalf("%s %q exit %d = %q want %q", tc.verb, tc.out, tc.code, got, tc.want)
		}
	}
	invalid := []struct {
		verb, out string
		code      int
	}{
		{"is-active", "active", 3},
		{"is-active", "reloading", 3},
		{"is-active", "inactive", 0},
		{"is-active", "dead", 0},
		{"is-active", "failed", 0},
		{"is-active", "activating", 0},
		{"is-active", "maintenance", 0},
		{"is-active", "unknown", 0},
		{"is-active", "not-found", 0},
		{"is-enabled", "enabled", 1},
		{"is-enabled", "enabled-runtime", 1},
		{"is-enabled", "static", 1},
		{"is-enabled", "alias", 1},
		{"is-enabled", "indirect", 1},
		{"is-enabled", "generated", 1},
		{"is-enabled", "disabled", 0},
		{"is-enabled", "linked", 0},
		{"is-enabled", "transient", 0},
		{"is-enabled", "masked", 0},
	}
	for _, tc := range invalid {
		m, _ := stateTestManager(t, tc.out, tc.code, tc.out, tc.code)
		if _, err := m.queryState(tc.verb); err == nil {
			t.Fatalf("%s %q exit %d should be rejected as inconsistent", tc.verb, tc.out, tc.code)
		}
	}
}

func TestTransitionalUninstall(t *testing.T) {
	for _, tc := range []struct {
		state string
		code  int
	}{
		{"activating", 3}, {"deactivating", 3}, {"maintenance", 3}, {"refreshing", 3}, {"reloading", 0},
	} {
		t.Run(tc.state, func(t *testing.T) {
			m, fr, _ := newFakeManager(t)
			if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
				t.Fatal(err)
			}
			fr.calls = nil
			fr.handler = func(name string, args ...string) (string, int, error) {
				switch {
				case fr.contains(args, "is-active"):
					if fr.saw("stop warden.service") {
						return "inactive", 3, nil
					}
					return tc.state, tc.code, nil
				case fr.contains(args, "is-enabled"):
					return "disabled", 1, nil
				}
				return "", 0, nil
			}
			if err := m.uninstall(os.Stderr); err != nil {
				t.Fatalf("uninstall of a %s service failed: %v", tc.state, err)
			}
			if _, err := os.Stat(m.unitPath); !os.IsNotExist(err) {
				t.Fatal("unit still present after uninstall")
			}
			if !strings.Contains(strings.Join(fr.calls, "\n"), "stop warden.service") {
				t.Fatalf("%s service was not stopped before removal", tc.state)
			}
		})
	}
	t.Run("stop succeeds but service still active preserves unit", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.calls = nil
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "active", 0, nil
			}
			return "", 0, nil
		}
		if err := m.uninstall(os.Stderr); err == nil {
			t.Fatal("uninstall succeeded even though the service stayed active")
		}
		if _, err := os.Stat(m.unitPath); err != nil {
			t.Fatalf("unit removed despite the service still being active: %v", err)
		}
		if strings.Contains(strings.Join(fr.calls, "\n"), "daemon-reload") {
			t.Fatal("daemon-reload ran although the service was not safely stopped")
		}
	})
	t.Run("disable succeeds but service still enabled preserves unit", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.calls = nil
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "inactive", 3, nil
			case fr.contains(args, "is-enabled"):
				return "enabled", 0, nil
			}
			return "", 0, nil
		}
		if err := m.uninstall(os.Stderr); err == nil {
			t.Fatal("uninstall succeeded even though the service stayed enabled")
		}
		if _, err := os.Stat(m.unitPath); err != nil {
			t.Fatalf("unit removed despite the service still being enabled: %v", err)
		}
		if strings.Contains(strings.Join(fr.calls, "\n"), "daemon-reload") {
			t.Fatal("daemon-reload ran although the service was not safely disabled")
		}
	})
}

func TestDisableVerificationFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name             string
		afterDisableOut  string
		afterDisableCode int
		afterDisableErr  error
	}{
		{"unknown", "unknown", 3, nil},
		{"unrecognized", "bogus-state", 1, nil},
		{"launch failure", "", -1, errors.New("bus gone")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, fr, _ := newFakeManager(t)
			if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
				t.Fatal(err)
			}
			fr.calls = nil
			fr.handler = func(name string, args ...string) (string, int, error) {
				switch {
				case fr.contains(args, "is-active"):
					return "inactive", 3, nil
				case fr.contains(args, "is-enabled"):
					if fr.saw("disable warden.service") {
						return tc.afterDisableOut, tc.afterDisableCode, tc.afterDisableErr
					}
					return "enabled", 0, nil
				}
				return "", 0, nil
			}
			if err := m.uninstall(os.Stderr); err == nil {
				t.Fatalf("uninstall proceeded after a %q disable verification", tc.name)
			}
			if _, err := os.Stat(m.unitPath); err != nil {
				t.Fatalf("unit removed despite failed disable verification: %v", err)
			}
			joined := strings.Join(fr.calls, "\n")
			if strings.Contains(joined, "daemon-reload") {
				t.Fatalf("daemon-reload ran after a failed disable verification: %s", joined)
			}
		})
	}
}

func TestIsEnabledUninstallPolicy(t *testing.T) {
	cases := []struct {
		state string
		code  int
		want  svcState
	}{
		{"enabled", 0, stateEnabled},
		{"enabled-runtime", 0, stateEnabled},
		{"static", 0, stateNotEnabled},
		{"alias", 0, stateNotEnabled},
		{"indirect", 0, stateNotEnabled},
		{"generated", 0, stateNotEnabled},
		{"disabled", 1, stateNotEnabled},
		{"linked", 1, stateNotEnabled},
		{"linked-runtime", 1, stateNotEnabled},
		{"transient", 1, stateNotEnabled},
		{"not-found", 4, stateNotEnabled},
		{"masked", 1, stateMasked},
		{"masked-runtime", 1, stateMasked},
		{"unknown", 1, stateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			m, fr, _ := newFakeManager(t)
			if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
				t.Fatal(err)
			}
			fr.calls = nil
			fr.handler = func(name string, args ...string) (string, int, error) {
				switch {
				case fr.contains(args, "is-active"):
					return "inactive", 3, nil
				case fr.contains(args, "is-enabled"):
					if fr.saw("disable warden.service") {
						return "disabled", 1, nil
					}
					return tc.state, tc.code, nil
				}
				return "", 0, nil
			}
			err := m.uninstall(os.Stderr)
			joined := strings.Join(fr.calls, "\n")
			disabled := strings.Contains(joined, "disable warden.service")
			if tc.want == stateEnabled {
				if !disabled {
					t.Fatalf("%s should invoke disable", tc.state)
				}
			} else if disabled {
				t.Fatalf("%s must not invoke disable", tc.state)
			}
			if tc.want == stateUnknown {
				if err == nil {
					t.Fatalf("%s should fail closed", tc.state)
				}
				if _, serr := os.Stat(m.unitPath); serr != nil {
					t.Fatalf("unit removed for unknown enablement %s: %v", tc.state, serr)
				}
			} else {
				if err != nil {
					t.Fatalf("uninstall for %s failed: %v", tc.state, err)
				}
				if _, serr := os.Stat(m.unitPath); !os.IsNotExist(serr) {
					t.Fatalf("unit not removed for %s", tc.state)
				}
			}
		})
	}
}

func TestUninstallRollback(t *testing.T) {
	backupFiles := func(dir string) []string {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return nil
		}
		var out []string
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".warden.service.unit-backup-") {
				out = append(out, e.Name())
			}
		}
		return out
	}

	t.Run("success removes the unit and leaves no backup artifacts", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "inactive", 3, nil
			case fr.contains(args, "is-enabled"):
				return "disabled", 1, nil
			}
			return "", 0, nil
		}
		if err := m.uninstall(os.Stderr); err != nil {
			t.Fatalf("uninstall: %v", err)
		}
		if _, err := os.Stat(m.unitPath); !os.IsNotExist(err) {
			t.Fatal("unit still present after uninstall")
		}
		if len(backupFiles(filepath.Dir(m.unitPath))) != 0 {
			t.Fatal("backup artifacts remain after a successful uninstall")
		}
	})

	t.Run("reload failure restores the original unit and removes the backup", func(t *testing.T) {
		m, fr, base := newFakeManager(t)
		configDir := filepath.Join(base, "warden-config")
		if err := os.MkdirAll(configDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"listen":"127.0.0.1:8080"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := m.install(testOpts(configDir, "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		orig, _ := os.ReadFile(m.unitPath)
		origInfo, _ := os.Stat(m.unitPath)
		fr.calls = nil
		reloadCalls := 0
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "inactive", 3, nil
			case fr.contains(args, "is-enabled"):
				return "disabled", 1, nil
			case fr.contains(args, "daemon-reload"):
				reloadCalls++
				if reloadCalls == 1 {
					return "Failed to reload", 1, nil
				}
				return "", 0, nil
			}
			return "", 0, nil
		}
		err := m.uninstall(os.Stderr)
		if err == nil {
			t.Fatal("uninstall did not report the reload failure")
		}
		if !strings.Contains(err.Error(), "restored") {
			t.Fatalf("reload failure did not restore the unit: %v", err)
		}
		got, _ := os.ReadFile(m.unitPath)
		if string(got) != string(orig) {
			t.Fatal("restored unit does not match the original byte-for-byte")
		}
		gotInfo, _ := os.Stat(m.unitPath)
		if !os.SameFile(origInfo, gotInfo) {
			t.Fatal("restored unit is not the original inode")
		}
		if len(backupFiles(filepath.Dir(m.unitPath))) != 0 {
			t.Fatal("backup artifacts remain after restoration")
		}
		if _, err := os.Stat(filepath.Join(configDir, "config.json")); err != nil {
			t.Fatalf("config was lost during rollback: %v", err)
		}
	})

	t.Run("concurrent replacement is preserved and the backup is recoverable", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		orig, _ := os.ReadFile(m.unitPath)
		fr.calls = nil
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "inactive", 3, nil
			case fr.contains(args, "is-enabled"):
				return "disabled", 1, nil
			case fr.contains(args, "daemon-reload"):
				_ = os.WriteFile(m.unitPath, []byte("# replacement\n"), 0644)
				return "Failed to reload", 1, nil
			}
			return "", 0, nil
		}
		err := m.uninstall(os.Stderr)
		if err == nil {
			t.Fatal("uninstall did not report the reload failure")
		}
		if !strings.Contains(err.Error(), "concurrently created") || !strings.Contains(err.Error(), "preserved at") {
			t.Fatalf("restoration conflict not reported clearly: %v", err)
		}
		got, _ := os.ReadFile(m.unitPath)
		if string(got) != "# replacement\n" {
			t.Fatalf("concurrently created file was overwritten: %q", got)
		}
		backs := backupFiles(filepath.Dir(m.unitPath))
		if len(backs) != 1 {
			t.Fatalf("expected exactly one retained backup, got %v", backs)
		}
		recovered, _ := os.ReadFile(filepath.Join(filepath.Dir(m.unitPath), backs[0]))
		if string(recovered) != string(orig) {
			t.Fatal("retained backup does not contain the original unit")
		}
		if !strings.Contains(err.Error(), backs[0]) {
			t.Fatalf("reported recovery path does not match the retained backup: %v", err)
		}
	})

	t.Run("second reload failure is surfaced after restoration", func(t *testing.T) {
		m, fr, _ := newFakeManager(t)
		if err := m.install(testOpts("/config", "127.0.0.1:8080", "/"), os.Stderr); err != nil {
			t.Fatal(err)
		}
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "inactive", 3, nil
			case fr.contains(args, "is-enabled"):
				return "disabled", 1, nil
			case fr.contains(args, "daemon-reload"):
				return "Failed to reload", 1, nil
			}
			return "", 0, nil
		}
		err := m.uninstall(os.Stderr)
		if err == nil {
			t.Fatal("uninstall did not report the reload failure")
		}
		if !strings.Contains(err.Error(), "follow-up reload also failed") {
			t.Fatalf("second reload failure not surfaced: %v", err)
		}
	})
}

func TestBackupManagedUnitNoReplace(t *testing.T) {
	dirEntries := func(dir string) []string {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return nil
		}
		var out []string
		for _, e := range ents {
			out = append(out, e.Name())
		}
		return out
	}

	t.Run("random source failure leaves the original intact", func(t *testing.T) {
		orig := randomSuffix
		randomSuffix = func() (string, error) { return "", errors.New("rand failed") }
		t.Cleanup(func() { randomSuffix = orig })
		dir := t.TempDir()
		unit := filepath.Join(dir, "app.service")
		if err := os.WriteFile(unit, []byte("unit"), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := backupManagedUnit(unit); err == nil {
			t.Fatal("random-source failure should error")
		}
		if got, _ := os.ReadFile(unit); string(got) != "unit" {
			t.Fatalf("original changed: %q", got)
		}
		if entries := dirEntries(dir); len(entries) != 1 {
			t.Fatalf("unexpected entries after failure: %v", entries)
		}
	})

	t.Run("collision never overwrites a retained backup", func(t *testing.T) {
		orig := randomSuffix
		randomSuffix = func() (string, error) { return "aa", nil }
		t.Cleanup(func() { randomSuffix = orig })
		dir := t.TempDir()
		unit := filepath.Join(dir, "app.service")
		retained := filepath.Join(dir, ".app.service.unit-backup-aa")
		if err := os.WriteFile(unit, []byte("unit"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(retained, []byte("retained"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := backupManagedUnit(unit); err == nil {
			t.Fatal("all candidates collided; should error")
		}
		if got, _ := os.ReadFile(retained); string(got) != "retained" {
			t.Fatalf("retained backup was overwritten: %q", got)
		}
		if got, _ := os.ReadFile(unit); string(got) != "unit" {
			t.Fatalf("original changed: %q", got)
		}
	})

	t.Run("unlink failure aborts and leaves no artifact", func(t *testing.T) {
		origSuffix, origRemove := randomSuffix, removeFile
		randomSuffix = func() (string, error) { return "bb", nil }
		removeFile = func(p string) error { return errors.New("remove failed") }
		t.Cleanup(func() { randomSuffix, removeFile = origSuffix, origRemove })
		dir := t.TempDir()
		unit := filepath.Join(dir, "app.service")
		if err := os.WriteFile(unit, []byte("unit"), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := backupManagedUnit(unit); err == nil {
			t.Fatal("unlink failure should error")
		}
		if got, _ := os.ReadFile(unit); string(got) != "unit" {
			t.Fatalf("original changed: %q", got)
		}
		if entries := dirEntries(dir); len(entries) != 1 {
			t.Fatalf("backup artifact left after aborted transaction: %v", entries)
		}
	})
}

func TestRunServiceDispatchErrors(t *testing.T) {
	if code := runService([]string{"--system", "install"}, version); code == 0 {
		t.Fatal("--system mode should be rejected")
	}
	if code := runService([]string{"bogus"}, version); code != 2 {
		t.Fatalf("unknown command exit=%d want 2", code)
	}
}

func TestReleaseMatrixBuilds(t *testing.T) {
	targets := []struct{ goos, goarch string }{
		{"linux", "amd64"}, {"linux", "arm64"},
		{"darwin", "amd64"}, {"darwin", "arm64"},
		{"windows", "amd64"}, {"windows", "arm64"},
	}
	for _, tc := range targets {
		t.Run(tc.goos+"/"+tc.goarch, func(t *testing.T) {
			name := "warden"
			if tc.goos == "windows" {
				name = "warden.exe"
			}
			dir := t.TempDir()
			cmd := exec.Command("go", "build", "-o", filepath.Join(dir, name), ".")
			cmd.Env = append(os.Environ(), "GOOS="+tc.goos, "GOARCH="+tc.goarch, "CGO_ENABLED=0")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s/%s build failed: %v\n%s", tc.goos, tc.goarch, err, out)
			}
		})
	}
}
