package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type session struct {
	CSRF    string
	Expires time.Time
}
type authStore struct {
	mu       sync.Mutex
	sessions map[string]session
	failures map[string][]time.Time
	hash     string
	secure   bool
}

func newAuth(hash string, secure bool) *authStore {
	return &authStore{sessions: map[string]session{}, failures: map[string][]time.Time{}, hash: hash, secure: secure}
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
func (a *authStore) login(w http.ResponseWriter, r *http.Request, password string) (string, error) {
	ip := clientIP(r)
	if a.limited(ip) {
		return "", errors.New("too many attempts")
	}
	if !verifyPassword(a.hash, password) {
		a.fail(ip)
		return "", errors.New("invalid credentials")
	}
	sid, csrf := token(32), token(24)
	a.mu.Lock()
	a.sessions[sid] = session{CSRF: csrf, Expires: time.Now().Add(12 * time.Hour)}
	delete(a.failures, ip)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "warden_session", Value: sid, Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	return csrf, nil
}
func (a *authStore) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("warden_session"); e == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
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
		return session{}, false
	}
	return s, true
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
