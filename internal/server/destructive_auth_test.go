package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDestructiveAccountDeletionRequiresActingAdministratorPassword(t *testing.T) {
	a, user, sess, cookie := permissionTestApp(t)
	// Restore administrator authority for this test helper's acting account.
	if err := a.accounts.setRole("user", "User", defaultUserCapabilities()); err != nil {
		t.Fatal(err)
	}
	_, _, ok := a.accounts.findPassword("admin")
	if !ok {
		t.Fatal("admin missing")
	}
	adminSessReq := httptest.NewRequest(http.MethodPost, "http://warden/api/login", nil)
	adminSessReq.RemoteAddr = "127.0.0.1:1"
	adminRec := httptest.NewRecorder()
	adminSess, err := a.auth.login(adminRec, adminSessReq, "admin", "administrator-password")
	if err != nil {
		t.Fatal(err)
	}
	adminCookie := adminRec.Result().Cookies()[0]

	call := func(password string) int {
		body := []byte(`{"Action":"delete-account","ID":"` + user.ID + `","Password":"` + password + `"}`)
		req := httptest.NewRequest(http.MethodPost, "http://warden/api/admin/access/action", bytes.NewReader(body))
		req.AddCookie(adminCookie)
		req.Header.Set("X-Warden-CSRF", adminSess.CSRF)
		rec := httptest.NewRecorder()
		a.require("accounts.manage", a.admin).ServeHTTP(rec, req)
		return rec.Code
	}
	_ = sess
	_ = cookie
	if got := call("wrong-password"); got != http.StatusBadRequest {
		t.Fatalf("wrong password status=%d", got)
	}
	if _, ok := a.accounts.accountByID(user.ID); !ok {
		t.Fatal("account deleted despite wrong acting password")
	}
	if got := call("administrator-password"); got != http.StatusOK {
		t.Fatalf("correct password status=%d", got)
	}
	if _, ok := a.accounts.accountByID(user.ID); ok {
		t.Fatal("account still exists after authorized deletion")
	}
}

func TestAuthenticationResetRequiresActingAdministratorPassword(t *testing.T) {
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
	a := &app{cfg: cfg, config: store, accounts: accounts}
	a.auth = newAuth(accounts, false, dir)
	reqLogin := httptest.NewRequest(http.MethodPost, "http://warden/api/login", nil)
	reqLogin.RemoteAddr = "127.0.0.1:1"
	recLogin := httptest.NewRecorder()
	sess, err := a.auth.login(recLogin, reqLogin, "admin", "administrator-password")
	if err != nil {
		t.Fatal(err)
	}
	cookie := recLogin.Result().Cookies()[0]
	call := func(password string) int {
		body := []byte(`{"action":"reset-authentication","confirmation":"RESET","password":"` + password + `"}`)
		req := httptest.NewRequest(http.MethodPost, "http://warden/api/admin/warden/action", bytes.NewReader(body))
		req.AddCookie(cookie)
		req.Header.Set("X-Warden-CSRF", sess.CSRF)
		rec := httptest.NewRecorder()
		a.wardenConfigAction(rec, req)
		return rec.Code
	}
	if got := call("wrong-password"); got != http.StatusForbidden {
		t.Fatalf("wrong password status=%d", got)
	}
	if accounts.empty() {
		t.Fatal("accounts reset despite wrong password")
	}
}
