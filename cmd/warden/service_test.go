package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	out   string
	err   error
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	return f.out, f.err
}

func (f *fakeRunner) Stream(name string, args ...string) (int, error) {
	_, _ = f.Run(name, args...)
	return 0, f.err
}

func newFakeManager(t *testing.T, out string, runErr error) (*serviceManager, *fakeRunner, string) {
	t.Helper()
	base := t.TempDir()
	unitPath := filepath.Join(base, "systemd", "user", "warden.service")
	fr := &fakeRunner{out: out, err: runErr}
	m := &serviceManager{unitName: "warden.service", unitPath: unitPath, exe: "/usr/local/bin/warden", run: fr}
	return m, fr, base
}

func TestRenderWardenUnit(t *testing.T) {
	unit := renderWardenUnit("/usr/local/bin/warden", "/home/nick/.config/warden", "127.0.0.1:8080", "/")
	if !strings.Contains(unit, wardenUnitMarker) {
		t.Fatal("missing managed marker")
	}
	if !strings.Contains(unit, `ExecStart="/usr/local/bin/warden"`) {
		t.Fatal("ExecStart must invoke the binary directly")
	}
	if strings.Contains(unit, "sh -c") {
		t.Fatal("unit must not use a shell wrapper")
	}
	for _, want := range []string{`"--config" "/home/nick/.config/warden"`, `"--listen" "127.0.0.1:8080"`, `"--root" "/"`, `Environment=HOME=%h`, `WantedBy=default.target`} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit missing %q\n%s", want, unit)
		}
	}
	// Multi-user boundary: host GitHub authentication must never be injected
	// into the service unit or otherwise granted to all accounts.
	if strings.Contains(unit, "GH_CONFIG_DIR") {
		t.Fatal("warden unit must not grant host GitHub authentication")
	}
}

func TestInstallAndIdempotence(t *testing.T) {
	m, fr, _ := newFakeManager(t, "active", nil)
	if err := m.install("/home/nick/.config/warden", "127.0.0.1:8080", "/", os.Stderr); err != nil {
		t.Fatalf("install: %v", err)
	}
	unit, err := os.ReadFile(m.unitPath)
	if err != nil {
		t.Fatalf("unit not written: %v", err)
	}
	if !strings.Contains(string(unit), wardenUnitMarker) {
		t.Fatal("unit lacks marker")
	}
	joined := strings.Join(fr.calls, "\n")
	for _, want := range []string{"systemctl --user daemon-reload", "systemctl --user enable warden.service", "systemctl --user start warden.service"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("install did not call %q\n%s", want, joined)
		}
	}
	fr.calls = nil
	if err := m.install("/home/nick/.config/warden", "127.0.0.1:8080", "/", os.Stderr); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	if !strings.Contains(strings.Join(fr.calls, "\n"), "systemctl --user start warden.service") {
		t.Fatal("reinstall did not restart the unit")
	}
}

func TestInstallRefusesUnmanagedUnit(t *testing.T) {
	m, _, _ := newFakeManager(t, "", nil)
	if err := os.MkdirAll(filepath.Dir(m.unitPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.unitPath, []byte("# hand written\n[Service]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	err := m.install("/config", "127.0.0.1:8080", "/", os.Stderr)
	if err == nil || !strings.Contains(err.Error(), "not a managed unit") {
		t.Fatalf("install overwrote an unmanaged unit: %v", err)
	}
}

func TestUninstallPreservesConfig(t *testing.T) {
	m, fr, base := newFakeManager(t, "", nil)
	configDir := filepath.Join(base, "warden-config")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.install(configDir, "127.0.0.1:8080", "/", os.Stderr); err != nil {
		t.Fatal(err)
	}
	if err := m.uninstall(os.Stderr); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if _, err := os.Stat(m.unitPath); !os.IsNotExist(err) {
		t.Fatal("unit still present after uninstall")
	}
	if _, err := os.Stat(filepath.Join(configDir, "config.json")); err != nil {
		t.Fatalf("config was removed by uninstall: %v", err)
	}
	joined := strings.Join(fr.calls, "\n")
	for _, want := range []string{"systemctl --user stop warden.service", "systemctl --user disable warden.service", "systemctl --user daemon-reload"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("uninstall did not call %q\n%s", want, joined)
		}
	}
}

func TestUninstallRefusesUnmanagedUnit(t *testing.T) {
	m, _, _ := newFakeManager(t, "", nil)
	if err := os.MkdirAll(filepath.Dir(m.unitPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.unitPath, []byte("# mine\n"), 0644); err != nil {
		t.Fatal(err)
	}
	err := m.uninstall(os.Stderr)
	if err == nil || !strings.Contains(err.Error(), "not a managed unit") {
		t.Fatalf("uninstall removed an unmanaged unit: %v", err)
	}
}

func TestStatus(t *testing.T) {
	t.Run("missing unit", func(t *testing.T) {
		m, _, _ := newFakeManager(t, "", nil)
		if err := m.status(os.Stderr, "1.0", "127.0.0.1:8080", "/api/setup/status"); err == nil {
			t.Fatal("status of a missing unit should fail")
		}
	})
	t.Run("failed state", func(t *testing.T) {
		m, _, _ := newFakeManager(t, "failed", nil)
		if err := m.install("/config", "127.0.0.1:8080", "/", os.Stderr); err != nil {
			t.Fatal(err)
		}
		if err := m.status(os.Stderr, "1.0", "127.0.0.1:8080", "/api/setup/status"); err == nil {
			t.Fatal("status of a failed unit should fail")
		}
	})
	t.Run("active and healthy", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
		defer srv.Close()
		m, _, _ := newFakeManager(t, "active", nil)
		if err := m.install("/config", "127.0.0.1:8080", "/", os.Stderr); err != nil {
			t.Fatal(err)
		}
		listen := strings.TrimPrefix(srv.URL, "http://")
		if err := m.status(os.Stderr, "1.0", listen, ""); err != nil {
			t.Fatalf("healthy status failed: %v", err)
		}
	})
	t.Run("active but unhealthy", func(t *testing.T) {
		m, _, _ := newFakeManager(t, "active", nil)
		if err := m.install("/config", "127.0.0.1:8080", "/", os.Stderr); err != nil {
			t.Fatal(err)
		}
		if err := m.status(os.Stderr, "1.0", "127.0.0.1:1", "/api/setup/status"); err == nil {
			t.Fatal("unhealthy status should fail")
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