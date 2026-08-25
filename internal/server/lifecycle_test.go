package server

import (
	"os"
	"path/filepath"
	"testing"
)

func newLifecycleTestApp(t *testing.T) *app {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{Listen: "127.0.0.1:8080", FileRoot: "/", HomeDir: "/tmp", StaticDir: "public", ConfigDir: dir}
	store, err := loadConfigStore(dir, instanceFromConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := loadAccountStore(dir)
	if err != nil {
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
	a := &app{cfg: cfg, config: store, accounts: accounts, secrets: secrets, aiUsage: usage}
	a.auth = newAuth(accounts, false, dir)
	return a
}

func TestReloadAllConfigurationDoesNotPartiallyApplyInvalidBatch(t *testing.T) {
	a := newLifecycleTestApp(t)
	before := a.config.instanceSnapshot().Listen
	inst := a.config.instanceSnapshot()
	inst.Listen = "127.0.0.1:9999"
	if err := writeJSONAtomic(filepath.Join(a.cfg.ConfigDir, "config.json"), inst, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.cfg.ConfigDir, "roles.json"), []byte(`{"version":1,"roles":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.reloadAllConfiguration(); err == nil {
		t.Fatal("expected reload failure")
	}
	if got := a.config.instanceSnapshot().Listen; got != before {
		t.Fatalf("invalid batch partially applied listen=%q want %q", got, before)
	}
}

func TestPortableImportRequiresAdministrator(t *testing.T) {
	b := portableConfigBundle{Version: 1, Instance: instanceConfigFile{Version: 1, Listen: "127.0.0.1:8080", FileRoot: "/", HomeDir: "/tmp", StaticDir: "public"}, Environment: environmentConfigFile{Version: 1, Global: map[string]string{}, Accounts: map[string]map[string]string{}}, Authentication: authenticationConfigFile{Version: 1}, AI: defaultAIConfig(), Accounts: accountsFile{Version: 1, Accounts: []account{}}, Roles: defaultRoles()}
	if err := validatePortableBundle(b); err == nil {
		t.Fatal("expected empty import to be rejected")
	}
}

func TestResetInstanceDoesNotDeleteWorkspaceFiles(t *testing.T) {
	a := newLifecycleTestApp(t)
	if _, err := a.accounts.createInitialAdmin("Admin", "admin", "very-secure-password"); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	file := filepath.Join(workspace, "project.txt")
	if err := os.WriteFile(file, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.secrets.set(aiSharedSecretName("openai"), "secret"); err != nil {
		t.Fatal(err)
	}
	if err := a.aiUsage.record("acct", "openai", 1, 2, 0.01); err != nil {
		t.Fatal(err)
	}
	if err := a.resetInstanceState(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("workspace file was touched: %v", err)
	}
	if !a.accounts.empty() {
		t.Fatal("accounts were not reset")
	}
	if _, ok := a.secrets.get(aiSharedSecretName("openai")); ok {
		t.Fatal("AI secret survived reset")
	}
	if got := a.aiUsage.summary("acct"); len(got) != 0 {
		t.Fatalf("usage survived reset: %#v", got)
	}
}
