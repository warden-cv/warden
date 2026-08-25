package server

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAICredentialResolutionPrefersAccountOverride(t *testing.T) {
	dir := t.TempDir()
	secrets, err := loadSecretStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{secrets: secrets}
	if err := secrets.set(aiSharedSecretName("openai"), "shared-key"); err != nil {
		t.Fatal(err)
	}
	if got, source, ok := a.resolveAICredential("acct_one", "openai"); !ok || got != "shared-key" || source != "shared" {
		t.Fatalf("shared resolution = %q %q %v", got, source, ok)
	}
	if err := secrets.set(aiAccountSecretName("acct_one", "openai"), "account-key"); err != nil {
		t.Fatal(err)
	}
	if got, source, ok := a.resolveAICredential("acct_one", "openai"); !ok || got != "account-key" || source != "account" {
		t.Fatalf("account resolution = %q %q %v", got, source, ok)
	}
	if got, source, ok := a.resolveAICredential("acct_two", "openai"); !ok || got != "shared-key" || source != "shared" {
		t.Fatalf("other account resolution = %q %q %v", got, source, ok)
	}
}

func TestAIUsageIsAttributedByWardenAccount(t *testing.T) {
	dir := t.TempDir()
	usage, err := loadAIUsageStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := usage.record("acct_one", "openai", 100, 25, 0.0125); err != nil {
		t.Fatal(err)
	}
	if err := usage.record("acct_one", "openai", 20, 5, 0.0025); err != nil {
		t.Fatal(err)
	}
	if err := usage.record("acct_two", "openai", 999, 999, 9.99); err != nil {
		t.Fatal(err)
	}
	one := usage.summary("acct_one")
	if len(one) != 1 || one[0].Requests != 2 || one[0].InputTokens != 120 || one[0].OutputTokens != 30 || one[0].EstimatedCostUSD < 0.014999 || one[0].EstimatedCostUSD > 0.015001 {
		t.Fatalf("acct_one usage = %#v", one)
	}
	two := usage.summary("acct_two")
	if len(two) != 1 || two[0].Requests != 1 {
		t.Fatalf("acct_two usage = %#v", two)
	}
}

func TestAIProviderRejectsInsecureRemoteHTTP(t *testing.T) {
	cfg := defaultAIConfig()
	p := cfg.Providers["openai"]
	p.BaseURL = "http://example.com/v1"
	cfg.Providers["openai"] = p
	if err := validateAIConfig(cfg); err == nil {
		t.Fatal("expected insecure remote AI base URL to be rejected")
	}
	p.BaseURL = "http://127.0.0.1:8080/v1"
	cfg.Providers["openai"] = p
	if err := validateAIConfig(cfg); err != nil {
		t.Fatalf("loopback HTTP should be allowed: %v", err)
	}
}

func TestAIEndpointSeparatesPersonalAndSharedCredentialAuthority(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Listen: "127.0.0.1:8080", FileRoot: "/", HomeDir: "/tmp", StaticDir: "public", ConfigDir: dir}
	store, err := loadConfigStore(dir, instanceFromConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := loadAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.createInitialAdmin("Admin", "admin", "administrator-password"); err != nil {
		t.Fatal(err)
	}
	user, err := accounts.createAccount("User", "user", "ordinary-user-password", nil)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := loadSecretStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := loadAIUsageStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{cfg: cfg, config: store, accounts: accounts, secrets: secrets, aiUsage: usage, audit: log.New(io.Discard, "", 0)}
	a.auth = newAuth(accounts, false, dir)
	loginReq := httptest.NewRequest("POST", "http://warden/api/login", nil)
	loginReq.RemoteAddr = "127.0.0.1:1"
	loginW := httptest.NewRecorder()
	sess, err := a.auth.login(loginW, loginReq, "user", "ordinary-user-password")
	if err != nil {
		t.Fatal(err)
	}
	cookie := loginW.Result().Cookies()[0]

	call := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://warden/api/ai", strings.NewReader(body))
		r.AddCookie(cookie)
		r.Header.Set("X-Warden-CSRF", sess.CSRF)
		w := httptest.NewRecorder()
		a.protect(a.aiSettings)(w, r)
		return w
	}
	if w := call(`{"action":"set-shared-credential","provider":"openai","credential":"shared"}`); w.Code != http.StatusForbidden {
		t.Fatalf("ordinary user set shared credential: status=%d body=%s", w.Code, w.Body.String())
	}
	if w := call(`{"action":"set-account-credential","provider":"openai","credential":"personal-secret"}`); w.Code != http.StatusOK {
		t.Fatalf("ordinary user could not set own credential: status=%d body=%s", w.Code, w.Body.String())
	}
	if got, source, ok := a.resolveAICredential(user.ID, "openai"); !ok || got != "personal-secret" || source != "account" {
		t.Fatalf("personal credential resolution = %q %q %v", got, source, ok)
	}
	get := httptest.NewRequest("GET", "http://warden/api/ai", nil)
	get.AddCookie(cookie)
	gw := httptest.NewRecorder()
	a.protect(a.aiSettings)(gw, get)
	if strings.Contains(gw.Body.String(), "personal-secret") {
		t.Fatal("AI credential leaked in GET response")
	}
}

func TestAIUsageAllSummariesRemainSeparatedByAccount(t *testing.T) {
	dir := t.TempDir()
	usage, err := loadAIUsageStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := usage.record("acct_one", "openai", 10, 2, 0.01); err != nil {
		t.Fatal(err)
	}
	if err := usage.record("acct_two", "anthropic", 20, 4, 0.02); err != nil {
		t.Fatal(err)
	}
	all := usage.allSummaries()
	if len(all) != 2 {
		t.Fatalf("accounts=%d want 2", len(all))
	}
	if got := all["acct_one"]; len(got) != 1 || got[0].Provider != "openai" || got[0].Requests != 1 {
		t.Fatalf("acct_one=%#v", got)
	}
	if got := all["acct_two"]; len(got) != 1 || got[0].Provider != "anthropic" || got[0].Requests != 1 {
		t.Fatalf("acct_two=%#v", got)
	}
}
