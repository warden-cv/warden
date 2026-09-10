package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManageRootRequiresManagementCapability(t *testing.T) {
	a := launcherTestApp(t)
	if _, err := a.accounts.createInitialAdmin("Admin", "admin", "administrator-password"); err != nil {
		t.Fatal(err)
	}
	static := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/manage.html" {
			t.Fatalf("static path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte("management"))
	})
	handler := a.manageRoot(static)
	unauthenticated := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "http://warden/manage/", nil))
	if unauthenticated.Code != http.StatusFound || unauthenticated.Header().Get("Location") != "/app/?return=%2Fmanage%2F" {
		t.Fatalf("unauthenticated response = %d %q", unauthenticated.Code, unauthenticated.Header().Get("Location"))
	}
	loginRequest := httptest.NewRequest(http.MethodPost, "http://warden/api/login", nil)
	loginResponse := httptest.NewRecorder()
	if _, err := a.auth.login(loginResponse, loginRequest, "admin", "administrator-password"); err != nil {
		t.Fatal(err)
	}
	authorized := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://warden/manage/", nil)
	request.AddCookie(loginResponse.Result().Cookies()[0])
	handler.ServeHTTP(authorized, request)
	if authorized.Code != http.StatusOK || authorized.Body.String() != "management" {
		t.Fatalf("authorized response = %d %q", authorized.Code, authorized.Body.String())
	}
}

func TestManagementActionAllowlistCannotCrossSectionBoundary(t *testing.T) {
	called := false
	handler := userManagementActions(func(http.ResponseWriter, *http.Request) { called = true })
	request := httptest.NewRequest(http.MethodPost, "http://warden/api/manage/users/action", strings.NewReader(`{"Action":"set-role"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || called {
		t.Fatalf("cross-section action response = %d called=%t", response.Code, called)
	}

	request = httptest.NewRequest(http.MethodPost, "http://warden/api/manage/users/action", strings.NewReader(`{"Action":"create-account"}`))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !called {
		t.Fatal("allowed user action did not reach handler")
	}
}

func TestManageRoutesUseSeparateCapabilities(t *testing.T) {
	a := &app{}
	policies := map[string]string{}
	for _, route := range a.apiRoutes() {
		policies[route.Policy.Path] = route.Policy.Capability
	}
	if policies["/api/manage/users"] != "accounts.manage" || policies["/api/manage/users/action"] != "accounts.manage" {
		t.Fatalf("user policies = %#v", policies)
	}
	if policies["/api/manage/roles"] != "roles.manage" || policies["/api/manage/roles/action"] != "roles.manage" {
		t.Fatalf("role policies = %#v", policies)
	}
	if policies["/api/launcher/config"] != "launcher.configure.all" {
		t.Fatalf("launcher policy = %q", policies["/api/launcher/config"])
	}
}
