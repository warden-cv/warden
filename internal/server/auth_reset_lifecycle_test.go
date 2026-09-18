package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestStaleSessionsAfterAuthResetCannotBreakStartup reproduces the post-reset
// service failure: an authentication reset empties accounts while a persisted
// sessions.json still references the deleted account. Migrating those stale
// sessions into the SQLite mirror violates the browser_sessions foreign key,
// which previously aborted startup ("inactive immediately after start").
func TestStaleSessionsAfterAuthResetCannotBreakStartup(t *testing.T) {
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
	if _, err := accounts.createInitialAdmin("Admin", "admin", "admin@example.com", "administrator-password"); err != nil {
		t.Fatal(err)
	}
	secrets, err := loadSecretStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	aiUsage, err := loadAIUsageStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &app{cfg: cfg, db: db, config: store, accounts: accounts, secrets: secrets, aiUsage: aiUsage}
	a.auth = newAuth(accounts, false, dir)

	// Establish a session so sessions.json carries an account reference.
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/login", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	if _, err := a.auth.login(rec, req, "admin", "administrator-password"); err != nil {
		t.Fatal(err)
	}
	if err := a.migrateLegacyState(); err != nil {
		t.Fatalf("healthy state must migrate: %v", err)
	}

	// Auth reset: accounts emptied, stale sessions left in place.
	if err := a.accounts.resetAccounts(); err != nil {
		t.Fatal(err)
	}
	if got := migrateErr(a); got == nil {
		t.Fatal("stale sessions referencing deleted accounts must fail startup migration")
	}

	// CLI reset also clears sessions.json: startup must succeed again.
	if err := os.Remove(filepath.Join(dir, "sessions.json")); err != nil {
		t.Fatal(err)
	}
	a.auth = newAuth(accounts, false, dir)
	if err := a.migrateLegacyState(); err != nil {
		t.Fatalf("startup after auth reset must succeed once sessions are cleared: %v", err)
	}
	status := httptest.NewRecorder()
	a.setupStatus(status, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/setup/status", nil))
	if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"required":true`)) {
		t.Fatalf("auth reset did not restore first-run setup: %d %s", status.Code, status.Body.String())
	}
}

func migrateErr(a *app) error { return a.migrateLegacyState() }
