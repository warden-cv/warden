package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSessionsAreBoundedAndIdentityStateIsRechecked(t *testing.T) {
	dir := t.TempDir()
	accounts, err := loadAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	acct, err := accounts.createInitialAdmin("Admin", "admin", "administrator-password")
	if err != nil {
		t.Fatal(err)
	}
	auth := newAuth(accounts, false, dir)
	var lastCookie *http.Cookie
	for i := 0; i < maxSessionsPerAccount+5; i++ {
		req := httptest.NewRequest(http.MethodPost, "http://warden/api/login", nil)
		req.RemoteAddr = "127.0.0.1:1"
		rec := httptest.NewRecorder()
		if _, err := auth.createSession(rec, req, acct.ID, acct.Identities[0].ID); err != nil {
			t.Fatal(err)
		}
		lastCookie = rec.Result().Cookies()[0]
	}
	if got := auth.countSessions(acct.ID); got != maxSessionsPerAccount {
		t.Fatalf("sessions=%d", got)
	}

	accounts.mu.Lock()
	accounts.accounts.Accounts[0].Identities[0].Enabled = false
	accounts.mu.Unlock()
	req := httptest.NewRequest(http.MethodGet, "http://warden/api/session", nil)
	req.AddCookie(lastCookie)
	if _, ok := auth.get(req); ok {
		t.Fatal("disabled identity retained an active session")
	}
}
