package main

import (
	"crypto/rand"
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

// svcState is a deliberately resolved systemd state category that separates
// command-result validation from the lifecycle meaning uninstall needs:
// definitely running, reloading, refreshing, transitioning, safely-stopped,
// unknown, enabled, not-enabled and masked.
type svcState string

const (
	stateActive     svcState = "active"
	stateReloading  svcState = "reloading"
	stateRefreshing svcState = "refreshing"
	stateTransition svcState = "transitioning"
	stateInactive   svcState = "inactive"
	stateUnknown    svcState = "unknown"
	stateEnabled    svcState = "enabled"
	stateNotEnabled svcState = "not-enabled"
	stateMasked     svcState = "masked"
)

func stateName(s svcState) string { return string(s) }

// exitExpect describes how strongly an output word's exit code is fixed by the
// systemd contract across the supported range (systemd 252 through current).
type exitExpect int

const (
	exitZero    exitExpect = iota // the state must exit 0
	exitNonzero                   // the state must exit nonzero
	exitEither                    // the exit code varies across versions
)

// classifyActive maps an is-active output word to a lifecycle category and its
// exit expectation. Per systemctl-is-active.c: only active and reloading are
// exit 0 in systemd 252-256; refreshing joins them at exit 0 in systemd 257+.
// Inactive, failed, activating, deactivating and maintenance exit 3; not-found
// exits 3 (<=254) or 4 (>=255).
func classifyActive(word string) (svcState, exitExpect, bool) {
	switch word {
	case "active":
		return stateActive, exitZero, true
	case "reloading":
		return stateReloading, exitZero, true
	case "refreshing":
		return stateRefreshing, exitEither, true
	case "inactive", "dead", "failed":
		return stateInactive, exitNonzero, true
	case "activating", "deactivating", "maintenance":
		return stateTransition, exitNonzero, true
	case "not-found", "unknown":
		return stateUnknown, exitNonzero, true
	}
	return "", 0, false
}

// classifyEnabled maps an is-enabled output word to a lifecycle category and
// its exit expectation. Per systemctl-is-enabled.c, enabled, enabled-runtime,
// static, alias, indirect and generated exit 0, but only enabled and
// enabled-runtime have enablement links that `systemctl disable` removes; the
// others are lifecycle not-enabled. Disabled, linked, linked-runtime,
// transient, masked, masked-runtime and not-found exit nonzero (not-found 4).
func classifyEnabled(word string) (svcState, exitExpect, bool) {
	switch word {
	case "enabled", "enabled-runtime":
		return stateEnabled, exitZero, true
	case "static", "alias", "indirect", "generated":
		return stateNotEnabled, exitZero, true
	case "disabled", "linked", "linked-runtime", "transient":
		return stateNotEnabled, exitNonzero, true
	case "masked", "masked-runtime":
		return stateMasked, exitNonzero, true
	case "not-found":
		return stateNotEnabled, exitNonzero, true
	case "unknown":
		return stateUnknown, exitNonzero, true
	}
	return "", 0, false
}

// queryState resolves an is-active or is-enabled state, validating the
// output/exit pair against the supported systemd contract: exit-0 states must
// exit 0, exit-nonzero states must exit nonzero, and version-varying states
// accept either. Launch failures, unrecognized output and inconsistent pairs
// surface as errors.
func (m *serviceManager) queryState(verb string) (svcState, error) {
	out, code, err := m.systemctl(verb, m.unitName)
	if err != nil {
		return "", fmt.Errorf("cannot run systemctl %s %s: %w", verb, m.unitName, err)
	}
	word := strings.TrimSpace(out)
	var st svcState
	var expect exitExpect
	var ok bool
	switch verb {
	case "is-active":
		st, expect, ok = classifyActive(word)
	case "is-enabled":
		st, expect, ok = classifyEnabled(word)
	}
	if !ok {
		return "", fmt.Errorf("systemctl %s %s returned unrecognized state %q (exit %d)", verb, m.unitName, word, code)
	}
	switch expect {
	case exitZero:
		if code != 0 {
			return "", fmt.Errorf("systemctl %s %s reported %q but exited %d; inconsistent state result", verb, m.unitName, word, code)
		}
	case exitNonzero:
		if code == 0 {
			return "", fmt.Errorf("systemctl %s %s reported %q but exited 0; inconsistent state result", verb, m.unitName, word)
		}
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

// rawState returns the exact systemctl is-enabled/is-active output word. The
// install transaction snapshots these raw words rather than the resolved
// lifecycle categories so rollback can reproduce the precise prior state.
func (m *serviceManager) rawState(verb string) (string, error) {
	out, _, err := m.systemctl(verb, m.unitName)
	if err != nil {
		return "", fmt.Errorf("cannot run systemctl %s %s: %w", verb, m.unitName, err)
	}
	word := strings.TrimSpace(out)
	if word == "" {
		return "", fmt.Errorf("systemctl %s %s returned no state", verb, m.unitName)
	}
	return word, nil
}

// restorableEnabledWord reports whether a prior is-enabled raw word can be
// restored exactly by the rollback sequence. Persistent/runtime enablement
// links (enabled, enabled-runtime, masked, masked-runtime) and their absence
// (disabled) are restorable; not-found is not (disabling a loaded unit yields
// disabled, never not-found), and unit-file states that enable/disable cannot
// reproduce (static, alias, indirect, generated, linked, linked-runtime,
// transient, unknown) are not.
func restorableEnabledWord(word string) bool {
	switch word {
	case "enabled", "enabled-runtime", "masked", "masked-runtime", "disabled":
		return true
	}
	return false
}

// restorableActiveWord reports whether a prior is-active raw word can be
// restored exactly by the rollback sequence. Running and stopped are
// restorable (restart/stop); dead, unknown and not-found are not, because stop
// produces inactive rather than those words, and transient/failed states
// cannot be reproduced deterministically.
func restorableActiveWord(word string) bool {
	switch word {
	case "active", "inactive":
		return true
	}
	return false
}

// restorablePriorState reports whether the enablement/active pair can be
// reproduced exactly by the rollback ordering (enablement restored first, then
// active state). A masked unit cannot be restarted, so masked + active is
// refused before mutation.
func restorablePriorState(enabledWord, activeWord string) bool {
	if !restorableEnabledWord(enabledWord) || !restorableActiveWord(activeWord) {
		return false
	}
	if (enabledWord == "masked" || enabledWord == "masked-runtime") && activeWord == "active" {
		return false
	}
	return true
}

// enableRestoreArgs returns the systemctl call that reproduces a prior
// is-enabled word exactly.
func enableRestoreArgs(word, unit string) []string {
	switch word {
	case "enabled":
		return []string{"enable", unit}
	case "enabled-runtime":
		return []string{"enable", "--runtime", unit}
	case "masked":
		return []string{"mask", unit}
	case "masked-runtime":
		return []string{"mask", "--runtime", unit}
	}
	return []string{"disable", unit}
}

// activeRestoreArgs returns the systemctl call that reproduces a prior
// is-active word exactly.
func activeRestoreArgs(word, unit string) []string {
	if word == "active" {
		return []string{"restart", unit}
	}
	return []string{"stop", unit}
}

// systemctlTolerantMissing runs a systemctl operation that must exit zero,
// tolerating systemd's "not loaded"/"not found" results that signal the unit
// was already absent.
func (m *serviceManager) systemctlTolerantMissing(args ...string) error {
	out, code, err := m.systemctl(args...)
	if err != nil {
		return fmt.Errorf("cannot run systemctl %s: %w", strings.Join(args, " "), err)
	}
	if code != 0 {
		lower := strings.ToLower(strings.TrimSpace(out))
		if strings.Contains(lower, "not loaded") || strings.Contains(lower, "not found") || strings.Contains(lower, "no such") {
			return nil
		}
		return fmt.Errorf("systemctl %s exited %d: %s", strings.Join(args, " "), code, bounded(strings.TrimSpace(out)))
	}
	return nil
}

// rollbackInstall restores the pre-install state after a failed publish or
// lifecycle step. For a reinstall it restores the prior unit bytes, reloads
// systemd, then reproduces the exact prior enablement and active states. For a
// failed fresh install it stops and disables the newly installed unit while it
// is still loaded, then removes the unit file and reloads systemd, so no
// enablement link or active service is left behind. It returns a "rollback
// incomplete" description when any restoration step fails.
func (m *serviceManager) rollbackInstall(priorUnit []byte, hadUnit bool, priorEnabledWord, priorActiveWord string) string {
	var errs []string
	if hadUnit {
		if err := writeManagedUnit(m.unitPath, string(priorUnit)); err != nil {
			errs = append(errs, fmt.Sprintf("restore unit: %v", err))
		}
	} else {
		if err := m.systemctlTolerantMissing("stop", m.unitName); err != nil {
			errs = append(errs, fmt.Sprintf("stop new unit: %v", err))
		}
		if err := m.systemctlTolerantMissing("disable", m.unitName); err != nil {
			errs = append(errs, fmt.Sprintf("disable new unit: %v", err))
		}
		if err := os.Remove(m.unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Sprintf("remove new unit: %v", err))
		}
	}
	if err := m.systemctlSuccess("daemon-reload"); err != nil {
		errs = append(errs, fmt.Sprintf("reload systemd: %v", err))
	}
	if hadUnit {
		if err := m.systemctlSuccess(enableRestoreArgs(priorEnabledWord, m.unitName)...); err != nil {
			errs = append(errs, fmt.Sprintf("restore enablement %q: %v", priorEnabledWord, err))
		}
		if err := m.systemctlSuccess(activeRestoreArgs(priorActiveWord, m.unitName)...); err != nil {
			errs = append(errs, fmt.Sprintf("restore active state %q: %v", priorActiveWord, err))
		}
	}
	if len(errs) == 0 {
		return ""
	}
	return "; rollback incomplete: " + strings.Join(errs, "; ")
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
	priorUnit, hadUnit := []byte(nil), false
	if b, err := os.ReadFile(m.unitPath); err == nil {
		hadUnit = true
		priorUnit = b
		if _, err := readManagedUnit(m.unitPath); err != nil {
			return fmt.Errorf("refusing to reinstall %s: %w", m.unitName, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Snapshot the exact prior enablement and active states before any
	// mutation so rollback can reproduce them precisely. States that cannot be
	// restored exactly are refused up front rather than flattened.
	priorEnabledWord, priorActiveWord := "", ""
	if hadUnit {
		var err error
		if priorEnabledWord, err = m.rawState("is-enabled"); err != nil {
			return err
		}
		if !restorableEnabledWord(priorEnabledWord) {
			return fmt.Errorf("refusing to reinstall %s: prior enablement state %q cannot be restored exactly; disable or unmask it first", m.unitName, priorEnabledWord)
		}
		if priorActiveWord, err = m.rawState("is-active"); err != nil {
			return err
		}
		if !restorableActiveWord(priorActiveWord) {
			return fmt.Errorf("refusing to reinstall %s: prior active state %q cannot be restored exactly; stop or restart it first", m.unitName, priorActiveWord)
		}
		if !restorablePriorState(priorEnabledWord, priorActiveWord) {
			return fmt.Errorf("refusing to reinstall %s: prior state %s+%s cannot be restored exactly; unmask it first", m.unitName, priorEnabledWord, priorActiveWord)
		}
		// True no-op: a byte-identical unit that is already enabled and active
		// needs no rewrite, reload or restart.
		if string(priorUnit) == unit && priorEnabledWord == "enabled" && priorActiveWord == "active" {
			fmt.Fprintf(out, "%s is already installed, enabled and active; nothing to do.\n", m.unitName)
			return nil
		}
	}
	changed := !hadUnit || string(priorUnit) != unit
	if changed {
		if err := writeManagedUnit(m.unitPath, unit); err != nil {
			return err
		}
		// A changed unit must restart (not merely start) so the new
		// configuration takes effect on an already-running process.
		for _, step := range []struct {
			verb string
			args []string
		}{
			{"reloading systemd", []string{"daemon-reload"}},
			{"enabling", []string{"enable", m.unitName}},
			{"starting", []string{"restart", m.unitName}},
		} {
			if err := m.systemctlSuccess(step.args...); err != nil {
				if rb := m.rollbackInstall(priorUnit, hadUnit, priorEnabledWord, priorActiveWord); rb != "" {
					return fmt.Errorf("%s %s: %w%s", step.verb, m.unitName, err, rb)
				}
				return fmt.Errorf("%s %s: %w", step.verb, m.unitName, err)
			}
		}
	} else {
		// Unit bytes are unchanged: only perform the lifecycle work required
		// to reach the documented installed state (enabled and active).
		steps := [][]string{}
		if priorEnabledWord != "enabled" {
			steps = append(steps, []string{"enable", m.unitName})
		}
		if priorActiveWord != "active" {
			steps = append(steps, []string{"start", m.unitName})
		}
		for _, args := range steps {
			if err := m.systemctlSuccess(args...); err != nil {
				if rb := m.rollbackInstall(priorUnit, hadUnit, priorEnabledWord, priorActiveWord); rb != "" {
					return fmt.Errorf("bringing %s to the installed state: %w%s", m.unitName, err, rb)
				}
				return fmt.Errorf("bringing %s to the installed state: %w", m.unitName, err)
			}
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

func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
}

var (
	linkFile     = os.Link
	removeFile   = os.Remove
	randomSuffix = func() (string, error) {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return hex.EncodeToString(b), nil
	}
)

// backupManagedUnit moves the managed unit aside to a unique hidden backup name
// in the same directory. It uses an exclusive hard link so an existing retained
// backup is never overwritten; the original is unlinked only after the backup
// link exists, and on any failure the original stays intact with no backup
// artifact left behind.
func backupManagedUnit(path string) (string, error) {
	dir := filepath.Dir(path)
	for i := 0; i < 32; i++ {
		suffix, err := randomSuffix()
		if err != nil {
			return "", fmt.Errorf("cannot generate a backup name: %w", err)
		}
		backup := filepath.Join(dir, "."+filepath.Base(path)+".unit-backup-"+suffix)
		if err := linkFile(path, backup); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue // candidate already exists; try another name
			}
			return "", err
		}
		if err := removeFile(path); err != nil {
			_ = os.Remove(backup)
			return "", fmt.Errorf("cannot remove the original after backing it up: %w", err)
		}
		syncDir(dir)
		return backup, nil
	}
	return "", errors.New("could not allocate a unique backup name")
}

// restoreFromBackup atomically restores the managed unit at its original path
// after a failed final daemon-reload. It uses a hard link so a concurrently
// created replacement is never overwritten; on conflict the backup is retained
// at its recovery path and that path is reported.
func restoreFromBackup(orig, backup string) error {
	if err := os.Link(backup, orig); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite a concurrently created unit at %s; the original unit is preserved at %s", orig, backup)
		}
		return err
	}
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	syncDir(filepath.Dir(orig))
	return nil
}

func (m *serviceManager) uninstall(out io.Writer) error {
	if _, err := readManagedUnit(m.unitPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s is not installed", m.unitName)
		}
		return fmt.Errorf("refusing to uninstall %s: %w", m.unitName, err)
	}
	active, err := m.queryState("is-active")
	if err != nil {
		return fmt.Errorf("cannot determine %s state before uninstall: %w", m.unitName, err)
	}
	if active == stateActive || active == stateReloading || active == stateRefreshing || active == stateTransition {
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
		if after != stateNotEnabled && after != stateMasked {
			return fmt.Errorf("%s still reports %q after disable; not removing the unit", m.unitName, stateName(after))
		}
	} else if enabled == stateNotEnabled || enabled == stateMasked {
		fmt.Fprintf(out, "note: %s is %s; nothing to disable\n", m.unitName, stateName(enabled))
	} else {
		return fmt.Errorf("%s enablement is %q; cannot confirm it is disabled before uninstall", m.unitName, stateName(enabled))
	}
	// Move the managed unit aside, then reload: on failure the original inode
	// is atomically restored, so no partial managed file can ever exist at the
	// managed path.
	backup, err := backupManagedUnit(m.unitPath)
	if err != nil {
		return fmt.Errorf("cannot move %s aside for uninstall: %w", m.unitName, err)
	}
	if err := m.systemctlSuccess("daemon-reload"); err != nil {
		if restoreErr := restoreFromBackup(m.unitPath, backup); restoreErr != nil {
			return fmt.Errorf("reloading systemd after removing %s: %w; additionally failed to restore the unit: %v", m.unitName, err, restoreErr)
		}
		if reloadErr := m.systemctlSuccess("daemon-reload"); reloadErr != nil {
			return fmt.Errorf("reloading systemd after removing %s: %w; the managed unit was restored but the follow-up reload also failed: %v", m.unitName, err, reloadErr)
		}
		return fmt.Errorf("reloading systemd after removing %s: %w; the managed unit was restored", m.unitName, err)
	}
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	syncDir(filepath.Dir(m.unitPath))
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
