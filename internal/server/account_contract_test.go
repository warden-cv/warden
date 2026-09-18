package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAccountCreationContract enforces the standardized account-creation
// contract: username and email are both required, duplicate emails and
// duplicate usernames are rejected, and a created account can sign in by either
// username or email.
func TestAccountCreationContract(t *testing.T) {
	dir := t.TempDir()
	accounts, err := loadAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.createInitialAdmin("Admin", "admin", "admin@example.com", "administrator-password"); err != nil {
		t.Fatal(err)
	}
	auth := newAuth(accounts, false, dir)

	// A new account with a distinct username but a duplicate (case-insensitive)
	// email must be rejected.
	if _, err := accounts.createAccount("Other", "other", "ADMIN@example.com", "ordinary-user-password", []string{"user"}); err == nil {
		t.Fatal("duplicate normalized email accepted")
	}
	// A duplicate (case-insensitive) username must be rejected.
	if _, err := accounts.createAccount("Third", "ADMIN", "third@example.com", "ordinary-user-password", []string{"user"}); err == nil {
		t.Fatal("duplicate normalized username accepted")
	}
	// A distinct account is accepted.
	if _, err := accounts.createAccount("Other", "other", "other@example.com", "ordinary-user-password", []string{"user"}); err != nil {
		t.Fatalf("distinct account rejected: %v", err)
	}

	// The initial administrator can sign in by username or by email.
	login := func(identifier string) bool {
		req := httptest.NewRequest(http.MethodPost, "http://warden/api/login", nil)
		req.RemoteAddr = "127.0.0.1:1"
		_, _, err := auth.authenticatePassword(req, identifier, "administrator-password")
		return err == nil
	}
	if !login("admin") {
		t.Fatal("sign-in by username failed")
	}
	if !login("admin@example.com") {
		t.Fatal("sign-in by email failed")
	}
}