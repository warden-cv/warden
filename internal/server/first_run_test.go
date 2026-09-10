package server

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFirstRunSetupCreatesRecoverableAdministratorAndUnlocksManagement(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Listen: "127.0.0.1:8080", FileRoot: dir, HomeDir: dir, StaticDir: "public", ConfigDir: dir}
	db, err := openDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	config, err := loadConfigStore(dir, instanceFromConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := loadAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	files, err := newFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := loadSecretStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{cfg: cfg, db: db, config: config, accounts: accounts, secrets: secrets, files: files, audit: log.New(io.Discard, "", 0)}
	a.auth = newAuth(accounts, false, dir)

	status := httptest.NewRecorder()
	statusRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/setup/status", nil)
	statusRequest.RemoteAddr = "127.0.0.1:1234"
	a.setupStatus(status, statusRequest)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"required":true`) {
		t.Fatalf("initial setup status = %d %s", status.Code, status.Body.String())
	}

	setup := httptest.NewRecorder()
	setupRequest := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/setup", strings.NewReader(`{"DisplayName":"Administrator","Username":"admin","Password":"administrator-password"}`))
	setupRequest.RemoteAddr = "127.0.0.1:1234"
	a.setup(setup, setupRequest)
	if setup.Code != http.StatusOK {
		t.Fatalf("setup status = %d %s", setup.Code, setup.Body.String())
	}
	if accounts.empty() || len(setup.Result().Cookies()) == 0 {
		t.Fatal("setup did not create an administrator session")
	}
	admin := accounts.listAccounts()[0]
	if !accounts.hasCapability(admin.ID, "accounts.manage") || !accounts.hasCapability(admin.ID, "roles.manage") || !accounts.hasCapability(admin.ID, "launcher.configure.all") {
		t.Fatal("initial administrator lacks management capabilities")
	}

	manage := httptest.NewRecorder()
	manageRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/manage/", nil)
	manageRequest.AddCookie(setup.Result().Cookies()[0])
	a.manageRoot(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(manage, manageRequest)
	if manage.Code != http.StatusNoContent {
		t.Fatalf("management remained locked after setup: %d", manage.Code)
	}
}
