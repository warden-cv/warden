package server

import (
	"net/http/httptest"
	"testing"
)

func TestInitialAdminAndPersistentSession(t *testing.T) {
	dir := t.TempDir()
	accounts, err := loadAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !accounts.empty() {
		t.Fatal("new account store should be empty")
	}
	acct, err := accounts.createInitialAdmin("Primary user", "nick", "a-long-enough-password")
	if err != nil {
		t.Fatal(err)
	}
	if acct.ID == "" || len(acct.Roles) != 1 || acct.Roles[0] != "administrator" {
		t.Fatalf("unexpected account: %#v", acct)
	}
	if _, err := accounts.createInitialAdmin("Other", "other", "another-long-password"); err == nil {
		t.Fatal("second initial admin unexpectedly succeeded")
	}

	auth := newAuth(accounts, false, dir)
	req := httptest.NewRequest("POST", "http://warden/api/login", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rw := httptest.NewRecorder()
	sess, err := auth.login(rw, req, "nick", "a-long-enough-password")
	if err != nil {
		t.Fatal(err)
	}
	if sess.AccountID != acct.ID {
		t.Fatalf("session account=%q want %q", sess.AccountID, acct.ID)
	}
	cookies := rw.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not set session cookie")
	}

	reloaded := newAuth(accounts, false, dir)
	check := httptest.NewRequest("GET", "http://warden/api/session", nil)
	check.AddCookie(cookies[0])
	got, ok := reloaded.get(check)
	if !ok || got.AccountID != acct.ID {
		t.Fatalf("persistent session missing: %#v %v", got, ok)
	}
}

func TestAccountStoreRejectsDuplicateUsername(t *testing.T) {
	roles := rolesFile{Version: 1, Roles: []role{{ID: "administrator", Name: "Administrator", Capabilities: []string{"*"}}}}
	users := accountsFile{Version: 1, Accounts: []account{
		{ID: "a", DisplayName: "A", Enabled: true, Roles: []string{"administrator"}, Identities: []loginIdentity{{ID: "i1", Type: "password", Username: "Same", PasswordHash: "x", Enabled: true}}},
		{ID: "b", DisplayName: "B", Enabled: true, Roles: []string{"administrator"}, Identities: []loginIdentity{{ID: "i2", Type: "password", Username: "same", PasswordHash: "x", Enabled: true}}},
	}}
	if err := validateAccounts(users, roles); err == nil {
		t.Fatal("duplicate username accepted")
	}
}
