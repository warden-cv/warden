package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func launcherTestApp(t *testing.T) *app {
	t.Helper()
	dir := t.TempDir()
	db, err := openDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	accounts, err := loadAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &app{cfg: Config{ConfigDir: dir}, db: db, accounts: accounts, auth: newAuth(accounts, false, dir)}
}

func intPointer(value int) *int { return &value }

func TestLauncherPortableConfigurationAndDirectURLs(t *testing.T) {
	document := launcherConfigDocument{Version: 1, Product: "warden", Instances: []launcherInstance{
		{Name: "Local", Domain: "localhost", Port: intPointer(7332)},
		{Name: "Production", Domain: "https://warden.example.com/"},
	}}
	instances, err := normalizeLauncherDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	if instances[0].ID == "" || instances[1].ID == "" || instances[0].ID == instances[1].ID {
		t.Fatalf("fresh IDs were not assigned: %#v", instances)
	}
	local, err := launcherAppURL(instances[0])
	if err != nil || local != "http://localhost:7332/app/" {
		t.Fatalf("local app URL = %q, %v", local, err)
	}
	production, err := launcherAppURL(instances[1])
	if err != nil || production != "https://warden.example.com/app/" {
		t.Fatalf("production app URL = %q, %v", production, err)
	}
	encoded, err := json.Marshal(launcherConfigDocument{Version: 1, Product: "warden", Instances: instances})
	if err != nil || !strings.Contains(string(encoded), `"domain":"localhost"`) {
		t.Fatalf("portable JSON unavailable: %s %v", encoded, err)
	}
}

func TestLauncherRejectsWrongProductAndInvalidEntries(t *testing.T) {
	cases := []launcherConfigDocument{
		{Version: 2, Product: "warden", Instances: []launcherInstance{}},
		{Version: 1, Product: "cortex", Instances: []launcherInstance{}},
		{Version: 1, Product: "warden", Instances: []launcherInstance{{Name: "Bad", Domain: "javascript://example.com"}}},
		{Version: 1, Product: "warden", Instances: []launcherInstance{{Name: "Bad", Domain: "example.com/path"}}},
		{Version: 1, Product: "warden", Instances: []launcherInstance{{Name: "Bad", Domain: "example.com", Port: intPointer(70000)}}},
	}
	for _, document := range cases {
		if _, err := normalizeLauncherDocument(document); err == nil {
			t.Fatalf("accepted invalid launcher document: %#v", document)
		}
	}
}

func TestAdaptiveLauncherRoot(t *testing.T) {
	a := launcherTestApp(t)
	static := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/launcher.html" {
			t.Fatalf("static path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte("launcher"))
	})
	handler := a.launcherRoot(static)

	request := func(target string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		return recorder
	}
	if response := request("http://warden.example/"); response.Code != http.StatusFound || response.Header().Get("Location") != "/app/" {
		t.Fatalf("zero-instance response = %d %q", response.Code, response.Header().Get("Location"))
	}
	one, _ := normalizeLauncherDocument(launcherConfigDocument{Version: 1, Product: "warden", Instances: []launcherInstance{{Name: "Local", Domain: "localhost", Port: intPointer(7332)}}})
	if err := a.replaceLauncherInstances(t.Context(), one); err != nil {
		t.Fatal(err)
	}
	if response := request("http://warden.example/"); response.Code != http.StatusFound || response.Header().Get("Location") != "http://localhost:7332/app/" {
		t.Fatalf("one-instance response = %d %q", response.Code, response.Header().Get("Location"))
	}
	two, _ := normalizeLauncherDocument(launcherConfigDocument{Version: 1, Product: "warden", Instances: []launcherInstance{{Name: "One", Domain: "one.example"}, {Name: "Two", Domain: "two.example"}}})
	if err := a.replaceLauncherInstances(t.Context(), two); err != nil {
		t.Fatal(err)
	}
	if response := request("http://warden.example/"); response.Code != http.StatusOK || response.Body.String() != "launcher" {
		t.Fatalf("multi-instance response = %d %q", response.Code, response.Body.String())
	}
	if response := request("http://warden.example/?config"); response.Code != http.StatusFound || response.Header().Get("Location") != "/app/?return=%2F%3Fconfig" {
		t.Fatalf("unauthenticated config response = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestApplicationIsMountedAtAppAndAssetsRemainStable(t *testing.T) {
	a := launcherTestApp(t)
	static := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Path))
	})
	handler := a.routes(static)

	app := httptest.NewRecorder()
	handler.ServeHTTP(app, httptest.NewRequest(http.MethodGet, "http://warden/app/", nil))
	if app.Code != http.StatusOK || app.Body.String() != "/" {
		t.Fatalf("/app/ served %d %q", app.Code, app.Body.String())
	}
	asset := httptest.NewRecorder()
	handler.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "http://warden/assets/js/script.js", nil))
	if asset.Code != http.StatusOK || asset.Body.String() != "/assets/js/script.js" {
		t.Fatalf("asset served %d %q", asset.Code, asset.Body.String())
	}
	canonical := httptest.NewRecorder()
	handler.ServeHTTP(canonical, httptest.NewRequest(http.MethodGet, "http://warden/app", nil))
	if canonical.Code != http.StatusFound || canonical.Header().Get("Location") != "/app/" {
		t.Fatalf("/app redirect = %d %q", canonical.Code, canonical.Header().Get("Location"))
	}
	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "http://warden/not-an-app-route", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d", missing.Code)
	}
}

func TestLauncherConfigRequiresAdminCSRFAndReplacesAtomically(t *testing.T) {
	a := launcherTestApp(t)
	account, err := a.accounts.createInitialAdmin("Admin", "admin", "administrator-password")
	if err != nil {
		t.Fatal(err)
	}
	loginRequest := httptest.NewRequest(http.MethodPost, "http://warden/api/login", nil)
	loginResponse := httptest.NewRecorder()
	sess, err := a.auth.login(loginResponse, loginRequest, "admin", "administrator-password")
	if err != nil || sess.AccountID != account.ID {
		t.Fatalf("login = %#v, %v", sess, err)
	}
	cookie := loginResponse.Result().Cookies()[0]
	handler := a.require("settings.manage", a.launcherConfig)
	body := `{"version":1,"product":"warden","instances":[{"name":"Production","domain":"warden.example.com"}]}`

	withoutCSRF := httptest.NewRequest(http.MethodPut, "http://warden/api/launcher/config", strings.NewReader(body))
	withoutCSRF.AddCookie(cookie)
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, withoutCSRF)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d", denied.Code)
	}

	valid := httptest.NewRequest(http.MethodPut, "http://warden/api/launcher/config", strings.NewReader(body))
	valid.AddCookie(cookie)
	valid.Header.Set("X-Warden-CSRF", sess.CSRF)
	saved := httptest.NewRecorder()
	handler.ServeHTTP(saved, valid)
	if saved.Code != http.StatusOK {
		t.Fatalf("save status = %d: %s", saved.Code, saved.Body.String())
	}
	before, err := a.loadLauncherInstances(t.Context())
	if err != nil || len(before) != 1 || before[0].Name != "Production" {
		t.Fatalf("saved instances = %#v, %v", before, err)
	}

	invalid := httptest.NewRequest(http.MethodPut, "http://warden/api/launcher/config", strings.NewReader(`{"version":1,"product":"warden","instances":[{"name":"Broken","domain":"bad host"}]}`))
	invalid.AddCookie(cookie)
	invalid.Header.Set("X-Warden-CSRF", sess.CSRF)
	rejected := httptest.NewRecorder()
	handler.ServeHTTP(rejected, invalid)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("invalid save status = %d", rejected.Code)
	}
	after, err := a.loadLauncherInstances(t.Context())
	if err != nil || len(after) != 1 || after[0].Name != "Production" {
		t.Fatalf("invalid replacement changed stored catalogue: %#v, %v", after, err)
	}
}
