package server

import "testing"

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
