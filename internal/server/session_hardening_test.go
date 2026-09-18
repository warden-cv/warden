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
	acct, err := accounts.createInitialAdmin("Admin", "admin", "admin@example.com", "administrator-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.createAccount("Backup Admin", "backup-admin", "backup-admin@example.com", "administrator-password", []string{"administrator"}); err != nil {
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

	if err := accounts.model.SetIdentityEnabled(acct.ID, acct.Identities[0].ID, false); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://warden/api/session", nil)
	req.AddCookie(lastCookie)
	if _, ok := auth.get(req); ok {
		t.Fatal("disabled identity retained an active session")
	}
}
