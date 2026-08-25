package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigStoreCreatesReloadsAndBacksUpEnvironment(t *testing.T) {
	dir := t.TempDir()
	defaults := Config{Listen: "127.0.0.1:8080", FileRoot: "/", HomeDir: "/tmp", StaticDir: "public", ConfigDir: dir}
	cfg, err := LoadConfig(dir, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != defaults.Listen {
		t.Fatalf("listen=%q", cfg.Listen)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "environment.json")); err != nil {
		t.Fatal(err)
	}

	store, err := loadConfigStore(dir, instanceFromConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.replaceGlobalEnvironment(map[string]string{"EDITOR": "nano", "WARDEN_TEST": "1"}); err != nil {
		t.Fatal(err)
	}
	if got := store.environmentFor("")["EDITOR"]; got != "nano" {
		t.Fatalf("EDITOR=%q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "environment.json.bak")); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "environment.json"), []byte(`{"version":1,"global":{"BAD-NAME":"x"},"accounts":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.reload(); err == nil {
		t.Fatal("expected invalid environment reload to fail")
	}
	if got := store.environmentFor("")["EDITOR"]; got != "nano" {
		t.Fatalf("invalid reload replaced active environment: %q", got)
	}
}

func TestMergedEnvironmentOverrides(t *testing.T) {
	got := mergedEnvironment([]string{"A=base", "B=base"}, map[string]string{"B": "global", "C": "global"}, map[string]string{"C": "forced"})
	want := map[string]string{"A": "base", "B": "global", "C": "forced"}
	for _, item := range got {
		for k := range want {
			if len(item) > len(k) && item[:len(k)+1] == k+"=" {
				want[k] = item[len(k)+1:]
			}
		}
	}
	if want["A"] != "base" || want["B"] != "global" || want["C"] != "forced" {
		t.Fatalf("merged=%v", got)
	}
}

func TestLoadConfigStoreAddsNewDefaultAIProvidersToExistingConfig(t *testing.T) {
	dir := t.TempDir()
	defaults := instanceConfigFile{Version: configSchemaVersion, Listen: "127.0.0.1:8080", FileRoot: dir, HomeDir: dir, StaticDir: "public"}
	if _, err := loadConfigStore(dir, defaults); err != nil {
		t.Fatal(err)
	}

	legacy := defaultAIConfig()
	delete(legacy.Providers, "opencode")
	legacy.Providers["custom"] = aiProviderConfig{Label: "Custom", BaseURL: "https://example.com/v1"}
	if err := writeJSONAtomic(filepath.Join(dir, "ai.json"), legacy, true); err != nil {
		t.Fatal(err)
	}

	store, err := loadConfigStore(dir, defaults)
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.aiSnapshot()
	if _, ok := cfg.Providers["opencode"]; !ok {
		t.Fatal("OpenCode Zen provider was not added to existing AI config")
	}
	if _, ok := cfg.Providers["custom"]; !ok {
		t.Fatal("existing custom provider was lost during default-provider migration")
	}
}
