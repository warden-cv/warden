package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLegacyStateMigratesIntoSQLite(t *testing.T) {
	dir := t.TempDir()
	db, err := openDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	accounts, err := loadAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	accounts.mu.Lock()
	accounts.accounts.Accounts = []account{{ID: "account-a", DisplayName: "Admin", Enabled: true, Roles: []string{"administrator"}, CreatedAt: time.Unix(100, 0), Identities: []loginIdentity{{ID: "identity-a", Type: "password", Username: "admin", PasswordHash: "hash", Enabled: true}}}}
	accounts.mu.Unlock()
	auth := newAuth(accounts, false, dir)
	auth.mu.Lock()
	auth.sessions["session-a"] = session{AccountID: "account-a", IdentityID: "identity-a", CSRF: "csrf", Created: time.Unix(200, 0), Expires: time.Now().Add(time.Hour)}
	auth.mu.Unlock()
	usage, err := loadAIUsageStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	usage.mu.Lock()
	usage.data.Accounts["account-a"] = aiAccountUsage{Providers: map[string]aiUsageCounter{"openai": {Requests: 2, InputTokens: 10, OutputTokens: 5, UpdatedAt: time.Now()}}}
	usage.mu.Unlock()
	if err := os.WriteFile(filepath.Join(dir, "audit.log"), []byte("2026/01/01 event=login account=account-a\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a := &app{db: db, accounts: accounts, auth: auth, aiUsage: usage, cfg: Config{ConfigDir: dir}}
	if err := a.migrateLegacyState(); err != nil {
		t.Fatal(err)
	}
	checks := map[string]int{"accounts": 1, "login_identities": 1, "account_roles": 1, "browser_sessions": 1, "ai_usage_totals": 1, "audit_events": 1}
	for table, want := range checks {
		var got int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&got); err != nil || got != want {
			t.Fatalf("%s count=%d want=%d err=%v", table, got, want, err)
		}
	}
	if err := a.migrateLegacyState(); err != nil {
		t.Fatal(err)
	}
	var auditCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("audit import was not idempotent: %d %v", auditCount, err)
	}
}
