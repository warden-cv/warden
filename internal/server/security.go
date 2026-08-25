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
		jsonOut(w, map[string]any{"account": publicAccount(acct), "currentIdentity": identityView{ID: identity.ID, Type: identity.Type, Username: identity.Username, Email: identity.Email, Enabled: identity.Enabled, TOTPEnabled: identity.TOTPEnabled, RecoveryCodes: len(identity.RecoveryCodeHashes)}, "googleEnabled": a.googleReady()})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	var q struct{ Action, Password, Code, Enrollment string }
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&q) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	_, identity, ok := a.accounts.identityByID(sess.IdentityID)
	if !ok || identity.Type != "password" {
		http.Error(w, "TOTP is currently available for password logins", 400)
		return
	}
	switch q.Action {
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
	default:
		http.Error(w, errors.New(fmt.Sprintf("unsupported security action %q", strings.TrimSpace(q.Action))).Error(), 400)
	}
}
