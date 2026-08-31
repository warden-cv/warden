package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/warden-app/warden/internal/server"
)

// wardenUnitMarker marks unit files written by `warden service`.
const wardenUnitMarker = "# Managed by warden. Do not edit manually."

// wardenManagedPrefix introduces the versioned integrity header. The header is
// followed by a SHA-256 of everything below it (managed metadata plus the unit
// body), so any hand edit is detected on the next write, action or uninstall.
const wardenManagedPrefix = "# warden-managed: "

// wardenHealthPath is the public, read-only health endpoint the service
// health check targets.
const wardenHealthPath = "/api/setup/status"

var (
	errNotManaged = errors.New("not a managed unit")
	errMalformed  = errors.New("malformed managed unit header")
	errModified   = errors.New("managed unit body no longer matches its recorded checksum")
)

// serviceRunner abstracts systemctl/journalctl so the CLI is testable without
// touching a real systemd user manager. Run returns the captured combined
// output, the process exit code (0 on success, -1 when the command could not
// be launched) and a launch error only.
type serviceRunner interface {
	Run(name string, args ...string) (string, int, error)
	Stream(name string, args ...string) (int, error)
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) (string, int, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode(), nil
	}
	return string(out), -1, err
}

func (execRunner) Stream(name string, args ...string) (int, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return -1, err
}

type serviceManager struct {
	unitName string
	unitPath string
	exe      string
	run      serviceRunner
}

type unitMeta struct {
	config string
	listen string
	health string
}

func userUnitPath(unitName string) string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.Getenv("HOME")
	}
	return filepath.Join(base, "systemd", "user", unitName)
}

func (m *serviceManager) systemctl(args ...string) (string, int, error) {
	return m.run.Run("systemctl", append([]string{"--user"}, args...)...)
}

// svcState is a deliberately resolved systemd state category. It preserves
// enough information to distinguish definitely-active, reloading,
// transitional, safely-stopped, unknown, enabled, disabled and masked states
// so uninstall can fail closed correctly.
type svcState string

const (
	stateActive     svcState = "active"
	stateReloading  svcState = "reloading"
	stateTransition svcState = "transitioning"
	stateInactive   svcState = "inactive"
	stateUnknown    svcState = "unknown"
	stateEnabled    svcState = "enabled"
	stateDisabled   svcState = "disabled"
	stateMasked     svcState = "masked"
)

func stateName(s svcState) string { return string(s) }

// classifyActive maps an is-active output word to a state category and whether
// that state requires exit 0. This follows systemd's documented contract
// (systemctl-is-active.c, v252): only active and reloading are considered
// "active" (exit 0); every other state exits 3.
func classifyActive(word string) (svcState, bool, bool) {
	switch word {
	case "active":
		return stateActive, true, true
	case "reloading":
		return stateReloading, true, true
	case "inactive", "dead", "failed":
		return stateInactive, false, true
	case "activating", "deactivating", "maintenance", "refreshing":
		return stateTransition, false, true
	case "unknown", "not-found":
		return stateUnknown, false, true
	}
	return "", false, false
}

// classifyEnabled maps an is-enabled output word to a state category and
// whether that state requires exit 0. This follows systemd's documented
// contract (systemctl-is-enabled.c, v252): enabled, enabled-runtime, static,
// alias, indirect and generated are considered "enabled" (exit 0); disabled,
// linked, linked-runtime, transient and not-found are not enabled (exit 1);
// masked and masked-runtime are distinct not-enabled states that cannot start.
func classifyEnabled(word string) (svcState, bool, bool) {
	switch word {
	case "enabled", "enabled-runtime", "static", "alias", "indirect", "generated":
		return stateEnabled, true, true
	case "disabled", "linked", "linked-runtime", "transient", "not-found":
		return stateDisabled, false, true
	case "masked", "masked-runtime":
		return stateMasked, false, true
	case "unknown":
		return stateUnknown, false, true
	}
	return "", false, false
}

// queryState resolves an is-active or is-enabled state and validates the
// output/exit pair together: positive states require exit 0, negative states
// require a documented nonzero exit, launch failures surface as errors, and
// inconsistent or unrecognized pairs surface as errors.
func (m *serviceManager) queryState(verb string) (svcState, error) {
	out, code, err := m.systemctl(verb, m.unitName)
	if err != nil {
		return "", fmt.Errorf("cannot run systemctl %s %s: %w", verb, m.unitName, err)
	}
	word := strings.TrimSpace(out)
	var st svcState
	var needZero bool
	var ok bool
	switch verb {
	case "is-active":
		st, needZero, ok = classifyActive(word)
	case "is-enabled":
		st, needZero, ok = classifyEnabled(word)
	}
	if !ok {
		return "", fmt.Errorf("systemctl %s %s returned unrecognized state %q (exit %d)", verb, m.unitName, word, code)
	}
	if needZero && code != 0 {
		return "", fmt.Errorf("systemctl %s %s reported %q but exited %d; inconsistent state result", verb, m.unitName, word, code)
	}
	if !needZero && code == 0 {
		return "", fmt.Errorf("systemctl %s %s reported %q but exited 0; inconsistent state result", verb, m.unitName, word)
	}
	return st, nil
}

// bounded caps captured command output used in errors.
func bounded(s string) string {
	const max = 2000
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// systemctlSuccess runs a systemctl operation that must exit zero; launch
// failures and nonzero exits are both errors. Call sites must never discard
// the exit code at strict-operation sites.
func (m *serviceManager) systemctlSuccess(args ...string) error {
	out, code, err := m.systemctl(args...)
	if err != nil {
		return fmt.Errorf("cannot run systemctl %s: %w", strings.Join(args, " "), err)
	}
	if code != 0 {
		return fmt.Errorf("systemctl %s exited %d: %s", strings.Join(args, " "), code, bounded(strings.TrimSpace(out)))
	}
	return nil
}

// validateNoControl rejects CR, LF, NUL and other control characters so no
// user-supplied value can inject directives into a systemd unit or confuse
// status metadata.
func validateNoControl(v, what string) error {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return fmt.Errorf("%s %q contains a control character", what, v)
		}
	}
	return nil
}

func systemdQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '%':
			b.WriteString("%%")
		case '"', '\\', '$', '`':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// renderWardenUnitBody renders the systemd directives (no managed header).
// It intentionally does NOT set GH_CONFIG_DIR or any host GitHub
// authentication: Warden is multi-user and host credentials are only shared
// for accounts that explicitly configure their own environment.
func renderWardenUnitBody(exe, configDir, listen, root string) string {
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Warden server console\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("ExecStart=" + systemdQuote(exe))
	b.WriteString(" " + systemdQuote("--config") + " " + systemdQuote(configDir))
	b.WriteString(" " + systemdQuote("--listen") + " " + systemdQuote(listen))
	b.WriteString(" " + systemdQuote("--root") + " " + systemdQuote(root))
	b.WriteString("\n")
	b.WriteString("WorkingDirectory=" + systemdQuote(filepath.Dir(exe)) + "\n")
	b.WriteString("Restart=on-failure\n")
	b.WriteString("Environment=HOME=%h\n")
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=default.target\n")
	return b.String()
}

func buildWardenUnit(exe, configDir, listen, root string) string {
	content := "# warden-config: " + configDir + "\n# warden-listen: " + listen + "\n# warden-health: " + wardenHealthPath + "\n" + renderWardenUnitBody(exe, configDir, listen, root)
	sum := sha256.Sum256([]byte(content))
	header := wardenUnitMarker + "\n" + wardenManagedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n"
	return header + content
}

func readManagedUnit(path string) (unitMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return unitMeta{}, err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 3 || lines[0] != wardenUnitMarker {
		return unitMeta{}, errNotManaged
	}
	count := 0
	for _, ln := range lines {
		if strings.HasPrefix(ln, wardenManagedPrefix) {
			count++
		}
	}
	if count != 1 || !strings.HasPrefix(lines[1], wardenManagedPrefix) {
		return unitMeta{}, errMalformed
	}
	sm := regexp.MustCompile(`^# warden-managed: v1 sha256=([0-9a-f]{64})$`).FindStringSubmatch(lines[1])
	if sm == nil {
		return unitMeta{}, errMalformed
	}
	content := strings.Join(lines[2:], "\n")
	sum := sha256.Sum256([]byte(content))
	if hex.EncodeToString(sum[:]) != sm[1] {
		return unitMeta{}, errModified
	}
	meta := unitMeta{}
	configSeen, listenSeen, healthSeen := 0, 0, 0
	for _, ln := range lines[2:] {
		switch {
		case strings.HasPrefix(ln, "# warden-config: "):
			configSeen++
			if configSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.config = strings.TrimSpace(strings.TrimPrefix(ln, "# warden-config: "))
		case strings.HasPrefix(ln, "# warden-listen: "):
			listenSeen++
			if listenSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.listen = strings.TrimSpace(strings.TrimPrefix(ln, "# warden-listen: "))
		case strings.HasPrefix(ln, "# warden-health: "):
			healthSeen++
			if healthSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.health = strings.TrimSpace(strings.TrimPrefix(ln, "# warden-health: "))
		}
	}
	if configSeen != 1 || listenSeen != 1 || healthSeen != 1 || meta.config == "" || meta.listen == "" || meta.health == "" {
		return unitMeta{}, errMalformed
	}
	if meta.health != wardenHealthPath {
		return unitMeta{}, errMalformed
	}
	for _, v := range []struct{ val, name string }{{meta.config, "config"}, {meta.listen, "listen"}} {
		if err := validateNoControl(v.val, v.name); err != nil {
			return unitMeta{}, errMalformed
		}
	}
	return meta, nil
}

func writeManagedUnit(path, content string) error {
	if _, err := os.Stat(path); err == nil {
		if _, err := readManagedUnit(path); err != nil {
			return fmt.Errorf("refusing to overwrite %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".warden-unit-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func resolveExecutable(exe string) (string, error) {
	if strings.TrimSpace(exe) == "" {
		return "", errors.New("empty executable path")
	}
	if !filepath.IsAbs(exe) {
		return "", fmt.Errorf("executable path %q is not absolute", exe)
	}
	abs := filepath.Clean(exe)
	if strings.HasPrefix(abs, os.TempDir()) {
		return "", fmt.Errorf("executable path %q is transient; install warden somewhere stable first", abs)
	}
	if strings.Contains(abs, string(filepath.Separator)+"go-build"+string(filepath.Separator)) {
		return "", fmt.Errorf("executable path %q looks like a Go build cache path", abs)
	}
	if st, err := os.Stat(abs); err != nil || st.IsDir() {
		return "", fmt.Errorf("executable %q is not a file", abs)
	}
	return abs, nil
}

func healthCheck(url string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("expected 2xx, got HTTP %d", resp.StatusCode)
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "json") {
		return fmt.Errorf("expected a JSON response, got %q", resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		return fmt.Errorf("expected a JSON object response: %v", err)
	}
	return nil
}

// wardenEffectiveListen resolves the actual listen address from Warden's
// durable config when it exists; the recorded unit value is only a bootstrap
// fallback. The command-line --listen default is not authoritative once a
// durable config exists.
func wardenEffectiveListen(configDir, fallback string) (string, error) {
	data, err := os.ReadFile(filepath.Join(configDir, "config.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fallback, nil
		}
		return "", err
	}
	var cfg struct {
		Listen string `json:"listen"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("config.json is malformed: %w", err)
	}
	if strings.TrimSpace(cfg.Listen) == "" {
		return "", errors.New("config.json has an empty listen address")
	}
	return cfg.Listen, nil
}

func (m *serviceManager) requireManaged(verb string) error {
	if _, err := readManagedUnit(m.unitPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("refusing to %s %s: unit is not installed", verb, m.unitName)
		}
		return fmt.Errorf("refusing to %s %s: %w", verb, m.unitName, err)
	}
	return nil
}

func (m *serviceManager) install(configDir, listen, root string, out io.Writer) error {
	for _, v := range []struct{ val, name string }{
		{configDir, "config"}, {listen, "listen"}, {root, "root"},
	} {
		if err := validateNoControl(v.val, v.name); err != nil {
			return err
		}
	}
	unit := buildWardenUnit(m.exe, configDir, listen, root)
	if err := writeManagedUnit(m.unitPath, unit); err != nil {
		return err
	}
	for _, step := range []struct {
		verb string
		args []string
	}{
		{"reloading systemd", []string{"daemon-reload"}},
		{"enabling", []string{"enable", m.unitName}},
		{"starting", []string{"start", m.unitName}},
	} {
		if err := m.systemctlSuccess(step.args...); err != nil {
			return fmt.Errorf("%s %s: %w", step.verb, m.unitName, err)
		}
	}
	active, _, _ := m.systemctl("is-active", m.unitName)
	fmt.Fprintf(out, "unit:   %s\n", m.unitName)
	fmt.Fprintf(out, "file:   %s\n", m.unitPath)
	fmt.Fprintf(out, "state:  %s\n", strings.TrimSpace(active))
	fmt.Fprintf(out, "url:    http://%s\n", listen)
	return nil
}

func (m *serviceManager) action(verb string, out io.Writer) error {
	if err := m.requireManaged(verb); err != nil {
		return err
	}
	o, code, err := m.systemctl(verb, m.unitName)
	if out != nil && strings.TrimSpace(o) != "" {
		fmt.Fprintln(out, strings.TrimSpace(o))
	}
	if err != nil {
		return fmt.Errorf("cannot run systemctl %s %s: %w", verb, m.unitName, err)
	}
	if code != 0 {
		return fmt.Errorf("systemctl %s %s exited %d: %s", verb, m.unitName, code, bounded(strings.TrimSpace(o)))
	}
	return nil
}

func (m *serviceManager) status(out io.Writer, version string) error {
	meta, err := readManagedUnit(m.unitPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s is not installed (no unit at %s)", m.unitName, m.unitPath)
		}
		return fmt.Errorf("%s unit is not valid: %w", m.unitName, err)
	}
	listen, err := wardenEffectiveListen(meta.config, meta.listen)
	if err != nil {
		return fmt.Errorf("cannot resolve the effective listen address: %w", err)
	}
	enabled, err := m.queryState("is-enabled")
	if err != nil {
		return fmt.Errorf("cannot determine %s enablement state: %w", m.unitName, err)
	}
	active, err := m.queryState("is-active")
	if err != nil {
		return fmt.Errorf("cannot determine %s service state: %w", m.unitName, err)
	}
	pid, _, _ := m.systemctl("show", "-p", "MainPID", "--value", m.unitName)
	fmt.Fprintf(out, "unit:    %s\n", m.unitName)
	fmt.Fprintf(out, "file:    %s\n", m.unitPath)
	fmt.Fprintf(out, "config:  %s\n", meta.config)
	fmt.Fprintf(out, "enabled: %s\n", enabled)
	fmt.Fprintf(out, "active:  %s\n", active)
	fmt.Fprintf(out, "pid:     %s\n", strings.TrimSpace(pid))
	fmt.Fprintf(out, "version: %s\n", version)
	fmt.Fprintf(out, "listen:  %s\n", listen)
	if active != stateActive {
		return fmt.Errorf("%s is %q; expected active", m.unitName, active)
	}
	if err := healthCheck("http://" + listen + meta.health); err != nil {
		fmt.Fprintf(out, "health:  unreachable (%v)\n", err)
		return fmt.Errorf("service is active but its health check failed: %v", err)
	}
	fmt.Fprintln(out, "health:  ok")
	return nil
}

func (m *serviceManager) logs(follow bool, out io.Writer) error {
	if err := m.requireManaged("view logs for"); err != nil {
		return err
	}
	args := []string{"--user-unit", m.unitName}
	if follow {
		args = append(args, "-f")
		code, err := m.run.Stream("journalctl", args...)
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("journalctl exited with status %d", code)
		}
		return nil
	}
	o, code, err := m.run.Run("journalctl", args...)
	if err != nil {
		return fmt.Errorf("cannot run journalctl: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("journalctl exited %d: %s", code, bounded(strings.TrimSpace(o)))
	}
	fmt.Fprint(out, o)
	return nil
}

// restoreUnitFile writes the original managed unit back after a failed final
// daemon-reload. O_EXCL ensures a concurrently created replacement is never
// overwritten; the original permissions are preserved.
func restoreUnitFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite a concurrently created unit at %s", path)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (m *serviceManager) uninstall(out io.Writer) error {
	data, err := os.ReadFile(m.unitPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s is not installed", m.unitName)
		}
		return err
	}
	if _, err := readManagedUnit(m.unitPath); err != nil {
		return fmt.Errorf("refusing to uninstall %s: %w", m.unitName, err)
	}
	info, err := os.Stat(m.unitPath)
	if err != nil {
		return err
	}
	active, err := m.queryState("is-active")
	if err != nil {
		return fmt.Errorf("cannot determine %s state before uninstall: %w", m.unitName, err)
	}
	if active == stateActive || active == stateReloading || active == stateTransition {
		if err := m.systemctlSuccess("stop", m.unitName); err != nil {
			return fmt.Errorf("stop %s failed: %w", m.unitName, err)
		}
		after, err := m.queryState("is-active")
		if err != nil {
			return fmt.Errorf("cannot verify %s stopped after stop: %w", m.unitName, err)
		}
		if after != stateInactive {
			return fmt.Errorf("%s still reports %q after stop; not removing the unit", m.unitName, stateName(after))
		}
	} else if active == stateInactive {
		fmt.Fprintf(out, "note: %s is inactive; nothing to stop\n", m.unitName)
	} else {
		return fmt.Errorf("%s is in %q; cannot confirm it is safely stopped before uninstall", m.unitName, stateName(active))
	}
	enabled, err := m.queryState("is-enabled")
	if err != nil {
		return fmt.Errorf("cannot determine %s enablement before uninstall: %w", m.unitName, err)
	}
	if enabled == stateEnabled {
		if err := m.systemctlSuccess("disable", m.unitName); err != nil {
			return fmt.Errorf("disable %s failed: %w", m.unitName, err)
		}
		after, err := m.queryState("is-enabled")
		if err != nil {
			return fmt.Errorf("cannot verify %s disabled after disable: %w", m.unitName, err)
		}
		if after != stateDisabled && after != stateMasked {
			return fmt.Errorf("%s still reports %q after disable; not removing the unit", m.unitName, stateName(after))
		}
	} else if enabled == stateDisabled || enabled == stateMasked {
		fmt.Fprintf(out, "note: %s is %s; nothing to disable\n", m.unitName, stateName(enabled))
	} else {
		return fmt.Errorf("%s enablement is %q; cannot confirm it is disabled before uninstall", m.unitName, stateName(enabled))
	}
	if err := os.Remove(m.unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := m.systemctlSuccess("daemon-reload"); err != nil {
		if restoreErr := restoreUnitFile(m.unitPath, data, info.Mode()); restoreErr != nil {
			return fmt.Errorf("reloading systemd after removing %s: %w; additionally failed to restore the unit: %v", m.unitName, err, restoreErr)
		}
		_ = m.systemctlSuccess("daemon-reload") // best-effort reload after restoring the unit
		return fmt.Errorf("reloading systemd after removing %s: %w; the managed unit was restored", m.unitName, err)
	}
	fmt.Fprintf(out, "Removed %s. Warden configuration, accounts and databases were preserved.\n", m.unitName)
	return nil
}

func runService(args []string, version string) int {
	cmd := "status"
	rest := args
	for i, a := range args {
		if a != "" && !strings.HasPrefix(a, "-") {
			cmd = a
			rest = append(append([]string{}, args[:i]...), args[i+1:]...)
			break
		}
	}
	fs := flag.NewFlagSet("warden service "+cmd, flag.ContinueOnError)
	system := fs.Bool("system", false, "install a system-wide unit (not yet supported; user mode is the default)")
	follow := fs.Bool("follow", false, "follow new journal output")
	configDir := fs.String("config", server.DefaultConfigDir(), "Warden configuration directory recorded in the unit")
	listen := fs.String("listen", env("WARDEN_LISTEN", "127.0.0.1:8080"), "bootstrap listen address recorded in the unit")
	root := fs.String("root", env("WARDEN_FILE_ROOT", "/"), "filesystem root recorded in the unit")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if *system {
		fmt.Fprintln(os.Stderr, "warden: system-wide service mode is not yet supported; use user mode (default) or the foreground command")
		return 2
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		fmt.Fprintln(os.Stderr, "warden: systemctl not found; is systemd installed?")
		return 1
	}
	if !filepath.IsAbs(*configDir) {
		fmt.Fprintln(os.Stderr, "warden: --config must be an absolute path")
		return 2
	}
	if err := validateNoControl(*configDir, "config"); err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 2
	}
	if err := validateNoControl(*listen, "listen"); err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 2
	}
	if err := validateNoControl(*root, "root"); err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		return 2
	}
	m := &serviceManager{
		unitName: "warden.service",
		unitPath: userUnitPath("warden.service"),
		run:      execRunner{},
	}
	switch cmd {
	case "install":
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, "warden:", err)
			return 1
		}
		exe, err = resolveExecutable(exe)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warden:", err)
			return 1
		}
		m.exe = exe
		if err := m.install(*configDir, *listen, *root, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "warden:", err)
			return 1
		}
		return 0
	case "start", "stop", "restart":
		if err := m.action(cmd, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "warden:", err)
			return 1
		}
		return 0
	case "status":
		if err := m.status(os.Stdout, version); err != nil {
			fmt.Fprintln(os.Stderr, "warden:", err)
			return 1
		}
		return 0
	case "logs":
		if err := m.logs(*follow, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "warden:", err)
			return 1
		}
		return 0
	case "uninstall":
		if err := m.uninstall(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "warden:", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "warden: unknown service command %q\n\nUsage: warden service <install|start|stop|restart|status|logs|uninstall> [flags]\n", cmd)
		return 2
	}
}