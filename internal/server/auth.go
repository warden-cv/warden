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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type session struct {
	AccountID  string    `json:"account_id"`
	IdentityID string    `json:"identity_id"`
	CSRF       string    `json:"csrf"`
	Created    time.Time `json:"created,omitempty"`
	Expires    time.Time `json:"expires"`
	RemoteIP   string    `json:"remote_ip,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
}
type sessionsFile struct {
	Version  int                `json:"version"`
	Sessions map[string]session `json:"sessions"`
}
type loginChallenge struct {
	AccountID  string
	IdentityID string
	IP         string
	Expires    time.Time
}

type authStore struct {
	mu           sync.Mutex
	sessions     map[string]session
	failures     map[string][]time.Time
	challenges   map[string]loginChallenge
	accounts     *accountStore
	sessionsPath string
	secure       bool
}

func newAuth(accounts *accountStore, secure bool, configDir string) *authStore {
	a := &authStore{sessions: map[string]session{}, failures: map[string][]time.Time{}, challenges: map[string]loginChallenge{}, accounts: accounts, sessionsPath: filepath.Join(configDir, "sessions.json"), secure: secure}
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
func (a *authStore) authenticatePassword(r *http.Request, username, password string) (account, loginIdentity, error) {
	ip := clientIP(r)
	if a.limited(ip) {
		return account{}, loginIdentity{}, errors.New("too many attempts")
	}
	acct, identity, ok := a.accounts.findPassword(username)
	if !ok || !verifyPassword(identity.PasswordHash, password) {
		a.fail(ip)
		return account{}, loginIdentity{}, errors.New("invalid credentials")
	}
	return acct, identity, nil
}

func (a *authStore) createSession(w http.ResponseWriter, r *http.Request, accountID, identityID string) (session, error) {
	sid, csrf := token(32), token(24)
	now := time.Now().UTC()
	s := session{AccountID: accountID, IdentityID: identityID, CSRF: csrf, Created: now, Expires: now.Add(12 * time.Hour), RemoteIP: clientIP(r), UserAgent: strings.TrimSpace(r.UserAgent())}
	a.mu.Lock()
	a.sessions[sid] = s
	delete(a.failures, clientIP(r))
	err := a.persistSessionsLocked()
	a.mu.Unlock()
	if err != nil {
		return session{}, err
	}
	http.SetCookie(w, &http.Cookie{Name: "warden_session", Value: sid, Path: "/", HttpOnly: true, Secure: a.secure || requestScheme(r) == "https", SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	return s, nil
}

func (a *authStore) login(w http.ResponseWriter, r *http.Request, username, password string) (session, error) {
	acct, identity, err := a.authenticatePassword(r, username, password)
	if err != nil {
		return session{}, err
	}
	return a.createSession(w, r, acct.ID, identity.ID)
}

func (a *authStore) beginChallenge(r *http.Request, accountID, identityID string) string {
	id := token(32)
	a.mu.Lock()
	now := time.Now()
	for key, c := range a.challenges {
		if c.Expires.Before(now) {
			delete(a.challenges, key)
		}
	}
	a.challenges[id] = loginChallenge{AccountID: accountID, IdentityID: identityID, IP: clientIP(r), Expires: now.Add(5 * time.Minute)}
	a.mu.Unlock()
	return id
}

func (a *authStore) getChallenge(r *http.Request, id string) (loginChallenge, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.challenges[id]
	if !ok || time.Now().After(c.Expires) || c.IP != clientIP(r) {
		delete(a.challenges, id)
		return loginChallenge{}, false
	}
	return c, true
}
func (a *authStore) consumeChallenge(id string) { a.mu.Lock(); delete(a.challenges, id); a.mu.Unlock() }

func (a *authStore) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("warden_session"); e == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		_ = a.persistSessionsLocked()
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "warden_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secure || requestScheme(r) == "https", SameSite: http.SameSiteStrictMode})
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

type sessionView struct {
	ID        string    `json:"id"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
	RemoteIP  string    `json:"remoteIp,omitempty"`
	UserAgent string    `json:"userAgent,omitempty"`
}

func (a *authStore) listSessions(accountID string) []sessionView {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	out := []sessionView{}
	for id, s := range a.sessions {
		if s.Expires.Before(now) {
			delete(a.sessions, id)
			continue
		}
		if s.AccountID == accountID {
			out = append(out, sessionView{ID: id, Created: s.Created, Expires: s.Expires, RemoteIP: s.RemoteIP, UserAgent: s.UserAgent})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}
func (a *authStore) countSessions(accountID string) int { return len(a.listSessions(accountID)) }
func (a *authStore) revokeSession(accountID, sessionID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[sessionID]
	if !ok || s.AccountID != accountID {
		return false
	}
	delete(a.sessions, sessionID)
	_ = a.persistSessionsLocked()
	return true
}
func (a *authStore) revokeIdentity(identityID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, s := range a.sessions {
		if s.IdentityID == identityID {
			delete(a.sessions, id)
		}
	}
	_ = a.persistSessionsLocked()
}

func (a *authStore) revokeIdentityExcept(identityID, keepSessionID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, s := range a.sessions {
		if s.IdentityID == identityID && id != keepSessionID {
			delete(a.sessions, id)
		}
	}
	_ = a.persistSessionsLocked()
}
func (a *authStore) currentSessionID(r *http.Request) string {
	c, err := r.Cookie("warden_session")
	if err != nil {
		return ""
	}
	return c.Value
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
	return writeJSONAtomic(a.sessionsPath, sessionsFile{Version: configSchemaVersion, Sessions: a.sessions}, false)
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
