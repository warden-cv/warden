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

func TestPasswordChangeKeepsCurrentSessionAndRevokesOtherIdentitySessions(t *testing.T) {
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
	acct, err := accounts.createInitialAdmin("Admin", "admin", "administrator-password")
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := loadSecretStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{cfg: cfg, config: store, accounts: accounts, secrets: secrets, audit: log.New(io.Discard, "", 0), totpPending: map[string]totpEnrollment{}}
	a.auth = newAuth(accounts, false, dir)

	login := func(port string) (*http.Cookie, session) {
		req := httptest.NewRequest("POST", "http://warden/api/login", nil)
		req.RemoteAddr = "127.0.0.1:" + port
		w := httptest.NewRecorder()
		sess, err := a.auth.login(w, req, "admin", "administrator-password")
		if err != nil {
			t.Fatal(err)
		}
		return w.Result().Cookies()[0], sess
	}
	currentCookie, current := login("1")
	otherCookie, _ := login("2")
	if got := a.auth.countSessions(acct.ID); got != 2 {
		t.Fatalf("sessions=%d want 2", got)
	}

	r := httptest.NewRequest("POST", "http://warden/api/security", strings.NewReader(`{"Action":"change-password","Password":"administrator-password","NewPassword":"replacement-password"}`))
	r.RemoteAddr = "127.0.0.1:1"
	r.AddCookie(currentCookie)
	r.Header.Set("X-Warden-CSRF", current.CSRF)
	w := httptest.NewRecorder()
	a.protect(a.security)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !accounts.verifyIdentityPassword(acct.ID, current.IdentityID, "replacement-password") {
		t.Fatal("new password was not stored")
	}
	if accounts.verifyIdentityPassword(acct.ID, current.IdentityID, "administrator-password") {
		t.Fatal("old password still verifies")
	}
	if got := a.auth.countSessions(acct.ID); got != 1 {
		t.Fatalf("sessions=%d want 1", got)
	}

	checkCurrent := httptest.NewRequest("GET", "http://warden/api/session", nil)
	checkCurrent.AddCookie(currentCookie)
	if _, ok := a.auth.get(checkCurrent); !ok {
		t.Fatal("current session was revoked")
	}
	checkOther := httptest.NewRequest("GET", "http://warden/api/session", nil)
	checkOther.AddCookie(otherCookie)
	if _, ok := a.auth.get(checkOther); ok {
		t.Fatal("other session using changed identity was not revoked")
	}
}
