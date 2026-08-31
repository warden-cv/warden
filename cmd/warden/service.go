package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/warden-app/warden/internal/server"
)

// wardenUnitMarker marks unit files written by `warden service`. Unmanaged or
// hand-modified units are never overwritten or removed silently.
const wardenUnitMarker = "# Managed by warden. Do not edit manually."

// serviceRunner abstracts systemctl/journalctl so the CLI is testable without
// touching a real systemd user manager.
type serviceRunner interface {
	Run(name string, args ...string) (string, error)
	Stream(name string, args ...string) (int, error)
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
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

func userUnitPath(unitName string) string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.Getenv("HOME")
	}
	return filepath.Join(base, "systemd", "user", unitName)
}

func (m *serviceManager) systemctl(args ...string) (string, error) {
	return m.run.Run("systemctl", append([]string{"--user"}, args...)...)
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

// renderWardenUnit renders the user unit. It intentionally does NOT set
// GH_CONFIG_DIR or any host GitHub authentication: Warden is multi-user and
// host credentials are only shared for accounts that explicitly configure
// their own environment.
func renderWardenUnit(exe, configDir, listen, root string) string {
	var b strings.Builder
	b.WriteString(wardenUnitMarker + "\n")
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

func writeManagedUnit(path, content string) error {
	if existing, err := os.ReadFile(path); err == nil {
		if !strings.Contains(string(existing), wardenUnitMarker) {
			return fmt.Errorf("refusing to overwrite %s: not a managed unit", path)
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
	abs, err := filepath.Abs(exe)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if !filepath.IsAbs(abs) {
		return "", fmt.Errorf("executable path %q is not absolute", abs)
	}
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
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (m *serviceManager) install(configDir, listen, root string, out io.Writer) error {
	unit := renderWardenUnit(m.exe, configDir, listen, root)
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
		o, err := m.systemctl(step.args...)
		if err != nil {
			return fmt.Errorf("%s %s: %w: %s", step.verb, m.unitName, err, strings.TrimSpace(o))
		}
	}
	active, _ := m.systemctl("is-active", m.unitName)
	fmt.Fprintf(out, "unit:   %s\n", m.unitName)
	fmt.Fprintf(out, "file:   %s\n", m.unitPath)
	fmt.Fprintf(out, "state:  %s\n", strings.TrimSpace(active))
	fmt.Fprintf(out, "url:    http://%s\n", listen)
	return nil
}

func (m *serviceManager) action(verb string, out io.Writer) error {
	o, err := m.systemctl(verb, m.unitName)
	if out != nil && strings.TrimSpace(o) != "" {
		fmt.Fprintln(out, strings.TrimSpace(o))
	}
	if err != nil {
		return fmt.Errorf("%s %s: %w", verb, m.unitName, err)
	}
	return nil
}

func (m *serviceManager) status(out io.Writer, version, listen, healthPath string) error {
	if _, err := os.Stat(m.unitPath); err != nil {
		return fmt.Errorf("%s is not installed (no unit at %s)", m.unitName, m.unitPath)
	}
	enabled, _ := m.systemctl("is-enabled", m.unitName)
	active, _ := m.systemctl("is-active", m.unitName)
	pid, _ := m.systemctl("show", "-p", "MainPID", "--value", m.unitName)
	fmt.Fprintf(out, "unit:    %s\n", m.unitName)
	fmt.Fprintf(out, "file:    %s\n", m.unitPath)
	fmt.Fprintf(out, "enabled: %s\n", strings.TrimSpace(enabled))
	fmt.Fprintf(out, "active:  %s\n", strings.TrimSpace(active))
	fmt.Fprintf(out, "pid:     %s\n", strings.TrimSpace(pid))
	fmt.Fprintf(out, "version: %s\n", version)
	fmt.Fprintf(out, "listen:  %s\n", listen)
	state := strings.TrimSpace(active)
	switch state {
	case "active":
		if err := healthCheck("http://" + listen + healthPath); err != nil {
			fmt.Fprintf(out, "health:  unreachable (%v)\n", err)
			return fmt.Errorf("service is active but its health check failed: %v", err)
		}
		fmt.Fprintln(out, "health:  ok")
		return nil
	case "failed":
		return fmt.Errorf("%s is in a failed state; run '%s service logs'", m.unitName, "warden")
	default:
		return nil
	}
}

func (m *serviceManager) logs(follow bool, out io.Writer) error {
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
	o, err := m.run.Run("journalctl", args...)
	if err != nil {
		return fmt.Errorf("journalctl: %w: %s", err, strings.TrimSpace(o))
	}
	fmt.Fprint(out, o)
	return nil
}

func (m *serviceManager) uninstall(out io.Writer) error {
	existing, err := os.ReadFile(m.unitPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s is not installed", m.unitName)
		}
		return err
	}
	if !strings.Contains(string(existing), wardenUnitMarker) {
		return fmt.Errorf("refusing to remove %s: not a managed unit", m.unitPath)
	}
	_, _ = m.systemctl("stop", m.unitName)
	_, _ = m.systemctl("disable", m.unitName)
	if err := os.Remove(m.unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := m.systemctl("daemon-reload"); err != nil {
		return err
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
	listen := fs.String("listen", env("WARDEN_LISTEN", "127.0.0.1:8080"), "listen address recorded in the unit")
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
		if err := m.status(os.Stdout, version, *listen, "/api/setup/status"); err != nil {
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