package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllCapabilityRoutesDenyMissingCapability(t *testing.T) {
	a, _, sess, cookie := permissionTestApp(t)
	for _, route := range a.apiRoutes() {
		if route.Policy.Boundary != "capability" || route.Policy.Capability == "files.read" {
			continue
		}
		t.Run(route.Policy.Path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://warden"+route.Policy.Path, nil)
			req.AddCookie(cookie)
			req.Header.Set("X-Warden-CSRF", sess.CSRF)
			rec := httptest.NewRecorder()
			a.require(route.Policy.Capability, func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler reached") }).ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status=%d", rec.Code)
			}
		})
	}
}

func TestCapabilityChangesApplyToExistingSession(t *testing.T) {
	a, _, _, cookie := permissionTestApp(t)
	if err := a.accounts.setRole("user", "User", nil); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://warden/api/files", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	a.require("files.read", func(http.ResponseWriter, *http.Request) { t.Fatal("stale authority used") }).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestSessionRevocationIsAccountOwned(t *testing.T) {
	a, user, _, _ := permissionTestApp(t)
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/login", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	other, err := a.auth.createSession(rec, req, user.ID, user.Identities[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	id := a.auth.currentSessionID(func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://warden/", nil)
		r.AddCookie(rec.Result().Cookies()[0])
		return r
	}())
	if a.auth.revokeSession("different-account", id) {
		t.Fatal("cross-account revocation succeeded")
	}
	if _, ok := a.auth.sessions[id]; !ok || other.AccountID != user.ID {
		t.Fatal("target session was altered")
	}
}

func TestAdminCapabilityDerivation(t *testing.T) {
	cases := map[string]string{"access": "accounts.manage", "audit": "audit.read", "warden": "settings.manage"}
	for kind, want := range cases {
		if got := requiredAdminCapability(kind, http.MethodGet); got != want {
			t.Fatalf("%s=%s", kind, got)
		}
	}
	if requiredAdminCapability("services", http.MethodGet) != "system.read" || requiredAdminCapability("services", http.MethodPost) != "system.manage" {
		t.Fatal("system capability derivation failed")
	}
}
