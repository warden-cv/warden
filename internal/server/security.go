package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type totpEnrollment struct {
	AccountID  string
	IdentityID string
	Secret     string
	Expires    time.Time
}

func totpSecretKey(identityID string) string { return "totp:" + identityID }

func (a *app) loginTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	var q struct{ Challenge, Code string }
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	if a.auth.limited(clientIP(r)) {
		http.Error(w, "too many attempts", 429)
		return
	}
	c, ok := a.auth.getChallenge(r, q.Challenge)
	if !ok {
		http.Error(w, "invalid or expired two-factor challenge", 401)
		return
	}
	acct, identity, ok := a.accounts.identityByID(c.IdentityID)
	if !ok || acct.ID != c.AccountID || !identity.TOTPEnabled {
		http.Error(w, "invalid challenge", 401)
		return
	}
	valid := false
	if secret, ok := a.secrets.get(totpSecretKey(identity.ID)); ok {
		valid = verifyTOTP(secret, q.Code, time.Now())
	}
	if !valid && a.accounts.consumeRecoveryCode(acct.ID, identity.ID, recoveryCodeHash(q.Code)) {
		valid = true
	}
	if !valid {
		a.auth.fail(clientIP(r))
		http.Error(w, "invalid two-factor code", 401)
		return
	}
	sess, err := a.auth.createSession(w, r, acct.ID, identity.ID)
	if err != nil {
		http.Error(w, "session unavailable", 500)
		return
	}
	a.audit.Printf("auth_login_2fa account=%s identity=%s ip=%s", sess.AccountID, sess.IdentityID, clientIP(r))
	jsonOut(w, a.sessionPayload(sess))
}

func (a *app) security(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	acct, ok := a.accounts.accountByID(sess.AccountID)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method == http.MethodGet {
		_, identity, _ := a.accounts.identityByID(sess.IdentityID)
		env := a.config.environmentSnapshot().Accounts[sess.AccountID]
		jsonOut(w, map[string]any{"account": publicAccount(acct), "currentIdentity": identityView{ID: identity.ID, Type: identity.Type, Username: identity.Username, Email: identity.Email, Enabled: identity.Enabled, TOTPEnabled: identity.TOTPEnabled, RecoveryCodes: len(identity.RecoveryCodeHashes)}, "googleEnabled": a.googleReady(), "sessions": a.auth.listSessions(sess.AccountID), "currentSession": a.auth.currentSessionID(r), "environment": sortedEnvironment(env)})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	var q struct {
		Action, Password, Code, Enrollment, SessionID string
		Variables                                     []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"variables"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&q) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	_, identity, ok := a.accounts.identityByID(sess.IdentityID)
	if !ok {
		http.Error(w, "identity unavailable", 400)
		return
	}
	if strings.HasPrefix(q.Action, "totp-") && identity.Type != "password" {
		http.Error(w, "TOTP is currently available for password logins", 400)
		return
	}
	switch q.Action {
	case "set-environment":
		vars := map[string]string{}
		for _, item := range q.Variables {
			name := strings.TrimSpace(item.Name)
			if name == "" {
				continue
			}
			if _, exists := vars[name]; exists {
				http.Error(w, "duplicate environment variable "+name, 400)
				return
			}
			vars[name] = item.Value
		}
		if err := a.config.replaceAccountEnvironment(sess.AccountID, vars); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		a.auditEvent(r, "account_environment_update", fmt.Sprintf("count=%d", len(vars)))
		jsonOut(w, map[string]any{"ok": true, "message": "Environment saved. New terminal and agent sessions will use it."})
	case "totp-start":
		if !a.accounts.verifyIdentityPassword(sess.AccountID, sess.IdentityID, q.Password) {
			http.Error(w, "current password is incorrect", 403)
			return
		}
		secret, err := newTOTPSecret()
		if err != nil {
			http.Error(w, "could not create TOTP secret", 500)
			return
		}
		id := token(24)
		a.totpMu.Lock()
		a.totpPending[id] = totpEnrollment{AccountID: sess.AccountID, IdentityID: sess.IdentityID, Secret: secret, Expires: time.Now().Add(10 * time.Minute)}
		a.totpMu.Unlock()
		label := identity.Username
		if label == "" {
			label = acct.DisplayName
		}
		jsonOut(w, map[string]any{"enrollment": id, "secret": secret, "uri": totpURI("Warden", label, secret), "message": "Add this secret to your authenticator, then verify a code."})
	case "totp-enable":
		a.totpMu.Lock()
		pending, found := a.totpPending[q.Enrollment]
		if found {
			delete(a.totpPending, q.Enrollment)
		}
		a.totpMu.Unlock()
		if !found || pending.AccountID != sess.AccountID || pending.IdentityID != sess.IdentityID || time.Now().After(pending.Expires) {
			http.Error(w, "TOTP enrollment expired", 400)
			return
		}
		if !verifyTOTP(pending.Secret, q.Code, time.Now()) {
			http.Error(w, "invalid authenticator code", 400)
			return
		}
		codes, hashes, err := newRecoveryCodes(8)
		if err != nil {
			http.Error(w, "could not create recovery codes", 500)
			return
		}
		if err := a.secrets.set(totpSecretKey(sess.IdentityID), pending.Secret); err != nil {
			http.Error(w, "could not store TOTP secret", 500)
			return
		}
		if err := a.accounts.setIdentityTOTP(sess.AccountID, sess.IdentityID, true, hashes); err != nil {
			_ = a.secrets.delete(totpSecretKey(sess.IdentityID))
			http.Error(w, err.Error(), 400)
			return
		}
		a.audit.Printf("totp_enabled account=%s identity=%s ip=%s", sess.AccountID, sess.IdentityID, clientIP(r))
		jsonOut(w, map[string]any{"ok": true, "recoveryCodes": codes, "message": "Two-factor authentication enabled. Save these recovery codes now."})
	case "totp-disable":
		if !a.accounts.verifyIdentityPassword(sess.AccountID, sess.IdentityID, q.Password) {
			http.Error(w, "current password is incorrect", 403)
			return
		}
		if err := a.accounts.setIdentityTOTP(sess.AccountID, sess.IdentityID, false, nil); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		_ = a.secrets.delete(totpSecretKey(sess.IdentityID))
		a.audit.Printf("totp_disabled account=%s identity=%s ip=%s", sess.AccountID, sess.IdentityID, clientIP(r))
		jsonOut(w, map[string]any{"ok": true, "message": "Two-factor authentication disabled."})
	case "totp-recovery":
		if !a.accounts.verifyIdentityPassword(sess.AccountID, sess.IdentityID, q.Password) {
			http.Error(w, "current password is incorrect", 403)
			return
		}
		if !identity.TOTPEnabled {
			http.Error(w, "TOTP is not enabled", 400)
			return
		}
		codes, hashes, err := newRecoveryCodes(8)
		if err != nil {
			http.Error(w, "could not create recovery codes", 500)
			return
		}
		if err := a.accounts.setIdentityTOTP(sess.AccountID, sess.IdentityID, true, hashes); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		jsonOut(w, map[string]any{"ok": true, "recoveryCodes": codes, "message": "Recovery codes regenerated. Previous codes no longer work."})
	case "revoke-session":
		if strings.TrimSpace(q.SessionID) == "" {
			http.Error(w, "session id is required", 400)
			return
		}
		if !a.auth.revokeSession(sess.AccountID, q.SessionID) {
			http.Error(w, "session not found", 404)
			return
		}
		a.auditEvent(r, "session_revoked", fmt.Sprintf("session=%s", q.SessionID))
		jsonOut(w, map[string]any{"ok": true, "message": "Session revoked."})
	default:
		http.Error(w, errors.New(fmt.Sprintf("unsupported security action %q", strings.TrimSpace(q.Action))).Error(), 400)
	}
}
