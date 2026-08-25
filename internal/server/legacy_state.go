package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func (a *app) migrateLegacyState() error {
	if err := a.syncLegacyState(); err != nil {
		return err
	}
	var done int
	if err := a.db.QueryRow("SELECT COUNT(*) FROM legacy_imports WHERE name='audit.log'").Scan(&done); err != nil {
		return err
	}
	if done == 0 {
		path := filepath.Join(a.cfg.ConfigDir, "audit.log")
		if file, err := os.Open(path); err == nil {
			scanner := bufio.NewScanner(file)
			line := 0
			for scanner.Scan() {
				line++
				raw := scanner.Text()
				sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s", line, raw)))
				key := hex.EncodeToString(sum[:])
				_, _ = a.db.Exec("INSERT OR IGNORE INTO audit_events(source_key,event,detail,created_at) VALUES(?, 'legacy', ?, ?)", key, raw, time.Now().UnixMilli())
			}
			file.Close()
			if err := scanner.Err(); err != nil {
				return err
			}
		}
		_, err := a.db.Exec("INSERT INTO legacy_imports(name,imported_at,detail) VALUES('audit.log',?,'Imported pre-SQLite audit lines')", time.Now().UnixMilli())
		if err != nil {
			return err
		}
	}
	_, err := a.db.Exec(`INSERT INTO legacy_imports(name,imported_at,detail) VALUES('json-state',?,'SQLite mirror active; JSON retained for backup compatibility')
		ON CONFLICT(name) DO UPDATE SET imported_at=excluded.imported_at`, time.Now().UnixMilli())
	return err
}

func (a *app) runLegacyStateMirror(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = a.syncLegacyState()
		}
	}
}

func (a *app) syncLegacyState() error {
	a.accounts.mu.RLock()
	accounts := append([]account(nil), a.accounts.accounts.Accounts...)
	roles := append([]role(nil), a.accounts.roles.Roles...)
	a.accounts.mu.RUnlock()
	a.auth.mu.Lock()
	sessions := make(map[string]session, len(a.auth.sessions))
	for id, s := range a.auth.sessions {
		sessions[id] = s
	}
	a.auth.mu.Unlock()
	a.aiUsage.mu.RLock()
	usageBytes, err := json.Marshal(a.aiUsage.data)
	a.aiUsage.mu.RUnlock()
	if err != nil {
		return err
	}
	var usage aiUsageFile
	if err = json.Unmarshal(usageBytes, &usage); err != nil {
		return err
	}
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"browser_sessions", "account_roles", "role_capabilities", "login_identities", "roles", "accounts", "ai_usage_totals"} {
		if _, err = tx.Exec("DELETE FROM " + table); err != nil {
			return err
		}
	}
	for _, acct := range accounts {
		created := acct.CreatedAt.UnixMilli()
		if acct.CreatedAt.IsZero() {
			created = 0
		}
		if _, err = tx.Exec("INSERT INTO accounts(id,display_name,enabled,created_at) VALUES(?,?,?,?)", acct.ID, acct.DisplayName, acct.Enabled, created); err != nil {
			return err
		}
		for _, identity := range acct.Identities {
			recovery, _ := json.Marshal(identity.RecoveryCodeHashes)
			if _, err = tx.Exec(`INSERT INTO login_identities(id,account_id,type,username,email,provider_subject,password_hash,totp_enabled,recovery_code_hashes_json,enabled) VALUES(?,?,?,?,?,?,?,?,?,?)`, identity.ID, acct.ID, identity.Type, identity.Username, identity.Email, identity.ProviderSubject, identity.PasswordHash, identity.TOTPEnabled, string(recovery), identity.Enabled); err != nil {
				return err
			}
		}
	}
	for _, r := range roles {
		if _, err = tx.Exec("INSERT INTO roles(id,name,built_in) VALUES(?,?,?)", r.ID, r.Name, r.BuiltIn); err != nil {
			return err
		}
		for _, capability := range r.Capabilities {
			if _, err = tx.Exec("INSERT INTO role_capabilities(role_id,capability) VALUES(?,?)", r.ID, capability); err != nil {
				return err
			}
		}
	}
	for _, acct := range accounts {
		for _, roleID := range acct.Roles {
			if _, err = tx.Exec("INSERT INTO account_roles(account_id,role_id) VALUES(?,?)", acct.ID, roleID); err != nil {
				return err
			}
		}
	}
	for id, s := range sessions {
		if _, err = tx.Exec(`INSERT INTO browser_sessions(id,account_id,identity_id,csrf,created_at,expires_at,remote_ip,user_agent) VALUES(?,?,?,?,?,?,?,?)`, id, s.AccountID, s.IdentityID, s.CSRF, s.Created.UnixMilli(), s.Expires.UnixMilli(), s.RemoteIP, s.UserAgent); err != nil {
			return err
		}
	}
	for accountID, accountUsage := range usage.Accounts {
		for provider, c := range accountUsage.Providers {
			if _, err = tx.Exec(`INSERT INTO ai_usage_totals(account_id,provider,requests,input_tokens,output_tokens,estimated_cost_usd,updated_at) VALUES(?,?,?,?,?,?,?)`, accountID, provider, c.Requests, c.InputTokens, c.OutputTokens, c.EstimatedCostUSD, c.UpdatedAt.UnixMilli()); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
