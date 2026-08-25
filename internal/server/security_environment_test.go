package server

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountCanManageOwnPersistentEnvironment(t *testing.T) {
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
	if _, err := accounts.createInitialAdmin("Admin", "admin", "administrator-password"); err != nil {
		t.Fatal(err)
	}
	user, err := accounts.createAccount("User", "user", "ordinary-user-password", nil)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := loadSecretStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{cfg: cfg, config: store, accounts: accounts, secrets: secrets, audit: log.New(io.Discard, "", 0), totpPending: map[string]totpEnrollment{}}
	a.auth = newAuth(accounts, false, dir)
	loginReq := httptest.NewRequest("POST", "http://warden/api/login", nil)
	loginReq.RemoteAddr = "127.0.0.1:1"
	loginW := httptest.NewRecorder()
	sess, err := a.auth.login(loginW, loginReq, "user", "ordinary-user-password")
	if err != nil {
		t.Fatal(err)
	}
	cookie := loginW.Result().Cookies()[0]
	r := httptest.NewRequest("POST", "http://warden/api/security", strings.NewReader(`{"Action":"set-environment","Variables":[{"name":"EDITOR","value":"vim"}]}`))
	r.AddCookie(cookie)
	r.Header.Set("X-Warden-CSRF", sess.CSRF)
	w := httptest.NewRecorder()
	a.protect(a.security)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := a.config.environmentFor(user.ID)["EDITOR"]; got != "vim" {
		t.Fatalf("EDITOR=%q", got)
	}
}
