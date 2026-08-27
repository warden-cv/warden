package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestForwardedHeadersFailClosedOnAmbiguity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://warden.example/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req = req.WithContext(context.WithValue(req.Context(), proxyTrustKey{}, true))
	req.Header.Set("X-Forwarded-Proto", "https, http")
	if requestScheme(req) != "http" {
		t.Fatal("ambiguous forwarded protocol was trusted")
	}
	req.Header.Set("X-Forwarded-For", "invalid, 203.0.113.9")
	req.Header.Set("X-Real-IP", "198.51.100.8")
	if got := clientIP(req); got != "198.51.100.8" {
		t.Fatalf("client IP=%q", got)
	}
}

func TestSameOriginRequiresSchemeHostAndOriginShape(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://warden.example/api/terminal", nil)
	req.Host = "warden.example"
	for origin, want := range map[string]bool{
		"https://warden.example": true, "http://warden.example": false,
		"https://other.example": false, "https://warden.example/path": false,
	} {
		req.Header.Set("Origin", origin)
		if got := sameOrigin(req); got != want {
			t.Fatalf("origin %q=%v", origin, got)
		}
	}
}

func TestCSRFAndTerminalOriginFailBeforeHandlers(t *testing.T) {
	a, _, sess, cookie := permissionTestApp(t)
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/files/mutate", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	a.require("files.read", func(http.ResponseWriter, *http.Request) { t.Fatal("handler reached") }).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("csrf status=%d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "http://warden/api/terminal?csrf="+sess.CSRF+"&session=test-session", nil)
	req.Host = "warden"
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("Origin", "https://warden")
	req.AddCookie(cookie)
	if err := a.accounts.setRole("user", "User", []string{"files.read", "terminal.open"}); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	a.terminal(rec, req)
	if rec.Code != http.StatusForbidden || rec.Body.String() != "origin\n" {
		t.Fatalf("origin status=%d body=%q", rec.Code, rec.Body.String())
	}
}
