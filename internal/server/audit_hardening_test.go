package server

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuditRedactionRemovesSecretCanaries(t *testing.T) {
	input := `password=canary-one token="canary-two" secret=canary-three credential=canary-four authorization=canary-five recovery=canary-six totp=canary-seven api_key=canary-eight session=canary-nine safe=value`
	got := redactAuditDetail(input)
	for _, canary := range []string{"canary-one", "canary-two", "canary-three", "canary-four", "canary-five", "canary-six", "canary-seven", "canary-eight", "canary-nine"} {
		if strings.Contains(got, canary) {
			t.Fatalf("redacted detail retained %q: %q", canary, got)
		}
	}
	if !strings.Contains(got, "safe=value") {
		t.Fatalf("redaction removed non-sensitive context: %q", got)
	}
	if got := redactAuditDetail(strings.Repeat("x", 5000)); len(got) > 4110 || !strings.HasSuffix(got, "[truncated]") {
		t.Fatalf("audit detail was not bounded: len=%d", len(got))
	}
}

func TestHTTPBoundaryAssignsRequestID(t *testing.T) {
	var seen string
	h := httpBoundary(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = requestIDFrom(r)
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://warden/health", nil))
	if seen == "" || rec.Header().Get("X-Warden-Request-ID") != seen {
		t.Fatalf("request ID header=%q context=%q", rec.Header().Get("X-Warden-Request-ID"), seen)
	}
}

func TestStructuredAuditPersistsRedactedEvidence(t *testing.T) {
	db, err := openDatabase(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var logOutput bytes.Buffer
	a := &app{db: db, audit: log.New(&logOutput, "", 0)}
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/admin?token=query-canary", nil)
	req = req.WithContext(context.WithValue(req.Context(), requestIDKey{}, "request-123"))
	a.auditEvent(req, "admin_action", "password=body-canary safe=value")

	var schema int
	var requestID, action, target, outcome, detail string
	if err := db.QueryRow("SELECT schema_version,request_id,action,target,outcome,detail FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&schema, &requestID, &action, &target, &outcome, &detail); err != nil {
		t.Fatal(err)
	}
	if schema != 1 || requestID != "request-123" || action != "admin_action" || target != "/api/admin" || outcome != "success" {
		t.Fatalf("unexpected envelope: schema=%d request=%q action=%q target=%q outcome=%q", schema, requestID, action, target, outcome)
	}
	if strings.Contains(detail, "body-canary") || strings.Contains(logOutput.String(), "body-canary") || strings.Contains(logOutput.String(), "query-canary") {
		t.Fatalf("secret canary escaped redaction: detail=%q log=%q", detail, logOutput.String())
	}
}

func TestDeniedPrivilegedRequestIsAudited(t *testing.T) {
	a, _, sess, cookie := permissionTestApp(t)
	db, err := openDatabase(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a.db = db
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/admin", strings.NewReader(`{}`))
	req.AddCookie(cookie)
	req.Header.Set("X-Warden-CSRF", sess.CSRF)
	rec := httptest.NewRecorder()
	a.require("administration.manage", func(http.ResponseWriter, *http.Request) {
		t.Fatal("denied handler was called")
	}).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
	var action, outcome string
	if err := db.QueryRow("SELECT action,outcome FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&action, &outcome); err != nil {
		t.Fatal(err)
	}
	if action != "authorization_denied" || outcome != "denied" {
		t.Fatalf("action=%q outcome=%q", action, outcome)
	}
}
