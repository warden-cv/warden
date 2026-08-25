package server

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func permissionTestApp(t *testing.T) (*app, account, session, *http.Cookie) {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{Listen: "127.0.0.1:8080", FileRoot: dir, HomeDir: dir, StaticDir: "public", ConfigDir: dir}
	store, err := loadConfigStore(dir, instanceFromConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := loadAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.createInitialAdmin("Admin", "admin", "administrator-password"); err != nil {
		t.Fatal(err)
	}
	user, err := accounts.createAccount("Restricted", "restricted", "restricted-password", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.setRole("user", "User", []string{"files.read"}); err != nil {
		t.Fatal(err)
	}
	secrets, err := loadSecretStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := loadAIUsageStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{cfg: cfg, config: store, accounts: accounts, secrets: secrets, aiUsage: usage, audit: log.New(io.Discard, "", 0)}
	a.auth = newAuth(accounts, false, dir)
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/login", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	sess, err := a.auth.login(rec, req, "restricted", "restricted-password")
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not set session cookie")
	}
	return a, user, sess, cookies[0]
}

func TestCapabilityMiddlewareDeniesRepresentativeRestrictedRoutes(t *testing.T) {
	a, _, sess, cookie := permissionTestApp(t)
	tests := []struct {
		name, capability, method, target string
		handler                          http.HandlerFunc
	}{
		{"file mutation", "files.manage", http.MethodPost, "http://warden/api/files/mutate", a.mutate},
		{"workspace replace", "workspace.replace", http.MethodPost, "http://warden/api/workspace/replace", a.workspaceReplace},
		{"source write", "source.write", http.MethodPost, "http://warden/api/source-control/mutate", a.sourceControlMutate},
		{"monitor", "monitor.read", http.MethodGet, "http://warden/api/monitor", a.monitor},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(`{}`))
			req.AddCookie(cookie)
			if tc.method != http.MethodGet {
				req.Header.Set("X-Warden-CSRF", sess.CSRF)
			}
			rec := httptest.NewRecorder()
			a.require(tc.capability, tc.handler).ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCapabilityMiddlewareAllowsGrantedRead(t *testing.T) {
	a, _, _, cookie := permissionTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "http://warden/api/files", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	called := false
	a.require("files.read", func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusNoContent) }).ServeHTTP(rec, req)
	if !called {
		t.Fatal("granted handler was not called")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}
