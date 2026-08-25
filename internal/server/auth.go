package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type session struct {
	AccountID  string    `json:"account_id"`
	IdentityID string    `json:"identity_id"`
	CSRF       string    `json:"csrf"`
	Expires    time.Time `json:"expires"`
}
type sessionsFile struct {
	Version  int                `json:"version"`
	Sessions map[string]session `json:"sessions"`
}
type authStore struct {
	mu           sync.Mutex
	sessions     map[string]session
	failures     map[string][]time.Time
	accounts     *accountStore
	sessionsPath string
	secure       bool
}

func newAuth(accounts *accountStore, secure bool, configDir string) *authStore {
	a := &authStore{sessions: map[string]session{}, failures: map[string][]time.Time{}, accounts: accounts, sessionsPath: filepath.Join(configDir, "sessions.json"), secure: secure}
	_ = a.loadSessions()
	return a
}
func token(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func (a *authStore) limited(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	cut := now.Add(-10 * time.Minute)
	xs := a.failures[ip][:0]
	for _, t := range a.failures[ip] {
		if t.After(cut) {
			xs = append(xs, t)
		}
	}
	a.failures[ip] = xs
	return len(xs) >= 8
}
func (a *authStore) fail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failures[ip] = append(a.failures[ip], time.Now())
}
func (a *authStore) login(w http.ResponseWriter, r *http.Request, username, password string) (session, error) {
	ip := clientIP(r)
	if a.limited(ip) {
		return session{}, errors.New("too many attempts")
	}
	acct, identity, ok := a.accounts.findPassword(username)
	if !ok || !verifyPassword(identity.PasswordHash, password) {
		a.fail(ip)
		return session{}, errors.New("invalid credentials")
	}
	sid, csrf := token(32), token(24)
	s := session{AccountID: acct.ID, IdentityID: identity.ID, CSRF: csrf, Expires: time.Now().Add(12 * time.Hour)}
	a.mu.Lock()
	a.sessions[sid] = s
	delete(a.failures, ip)
	_ = a.persistSessionsLocked()
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "warden_session", Value: sid, Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	return s, nil
}
func (a *authStore) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("warden_session"); e == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		_ = a.persistSessionsLocked()
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "warden_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode})
}
func (a *authStore) get(r *http.Request) (session, bool) {
	c, e := r.Cookie("warden_session")
	if e != nil {
		return session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	if !ok || time.Now().After(s.Expires) {
		delete(a.sessions, c.Value)
		_ = a.persistSessionsLocked()
		return session{}, false
	}
	acct, ok := a.accounts.accountByID(s.AccountID)
	if !ok || !acct.Enabled {
		delete(a.sessions, c.Value)
		_ = a.persistSessionsLocked()
		return session{}, false
	}
	return s, true
}
func (a *authStore) revokeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions = map[string]session{}
	_ = a.persistSessionsLocked()
}
func (a *authStore) revokeAccount(accountID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, s := range a.sessions {
		if s.AccountID == accountID {
			delete(a.sessions, id)
		}
	}
	_ = a.persistSessionsLocked()
}
func (a *authStore) loadSessions() error {
	var f sessionsFile
	if _, err := os.Stat(a.sessionsPath); errors.Is(err, os.ErrNotExist) {
		return writeJSONAtomic(a.sessionsPath, sessionsFile{Version: configSchemaVersion, Sessions: map[string]session{}}, false)
	} else if err != nil {
		return err
	}
	if err := readJSONStrict(a.sessionsPath, &f); err != nil {
		return err
	}
	if f.Version != configSchemaVersion {
		return errors.New("unsupported sessions schema version")
	}
	now := time.Now()
	for id, s := range f.Sessions {
		if s.Expires.After(now) {
			a.sessions[id] = s
		}
	}
	return nil
}
func (a *authStore) persistSessionsLocked() error {
	return writeJSONAtomic(a.sessionsPath, sessionsFile{Version: configSchemaVersion, Sessions: a.sessions}, true)
}
func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, e := strconv.Atoi(parts[1])
	if e != nil || iter < 100000 {
		return false
	}
	salt, e := hex.DecodeString(parts[2])
	if e != nil {
		return false
	}
	want, e := base64.RawStdEncoding.DecodeString(parts[3])
	if e != nil {
		return false
	}
	got := pbkdf2([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}
func pbkdf2(p, s []byte, iter, n int) []byte {
	out := make([]byte, 0, n)
	for block := 1; len(out) < n; block++ {
		ctr := []byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)}
		u := hmac256(p, append(append([]byte{}, s...), ctr...))
		t := append([]byte{}, u...)
		for i := 1; i < iter; i++ {
			u = hmac256(p, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:n]
}
func hmac256(k, m []byte) []byte {
	if len(k) > 64 {
		x := sha256.Sum256(k)
		k = x[:]
	}
	kb := make([]byte, 64)
	copy(kb, k)
	ipad := make([]byte, 64)
	opad := make([]byte, 64)
	for i := range kb {
		ipad[i] = kb[i] ^ 0x36
		opad[i] = kb[i] ^ 0x5c
	}
	a := sha256.Sum256(append(ipad, m...))
	b := sha256.Sum256(append(opad, a[:]...))
	return b[:]
}
