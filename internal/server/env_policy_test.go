package server

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestAgentSubprocessEnvGHPolicy verifies Warden's multi-user credential
// boundary: host GitHub CLI authentication is not inherited by default, is
// only shared for accounts whose environment explicitly sets GH_CONFIG_DIR,
// and other accounts remain isolated.
func TestAgentSubprocessEnvGHPolicy(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "config")
	dataDir := filepath.Join(t.TempDir(), "data")
	base := []string{"HOME=/home/warden", "XDG_CONFIG_HOME=/home/warden/.config", "PATH=/usr/bin:/bin"}

	t.Run("default deny", func(t *testing.T) {
		env := agentSubprocessEnv(base, configDir, dataDir, "", false, nil)
		if v := agentEnvValue(env, "GH_CONFIG_DIR"); v != "" {
			t.Fatalf("GH_CONFIG_DIR=%q inherited by default", v)
		}
		if v := agentEnvValue(env, "XDG_CONFIG_HOME"); v != configDir {
			t.Fatalf("XDG_CONFIG_HOME=%q want isolated %q", v, configDir)
		}
	})

	t.Run("inherited host GitHub variables are scrubbed", func(t *testing.T) {
		baseWith := append([]string{}, base...)
		baseWith = append(baseWith, "GH_CONFIG_DIR=/host/.config/gh", "GH_TOKEN=TEST_VALUE_NOT_A_SECRET", "GITHUB_TOKEN=TEST_VALUE_NOT_A_SECRET", "GH_HOST=github.example.com")
		env := agentSubprocessEnv(baseWith, configDir, dataDir, "", false, nil)
		for _, v := range []string{"GH_CONFIG_DIR", "GH_TOKEN", "GITHUB_TOKEN", "GH_HOST"} {
			if got := agentEnvValue(env, v); got != "" {
				t.Fatalf("%s=%q survived scrubbing", v, got)
			}
		}
	})

	t.Run("per-account enablement overrides scrub", func(t *testing.T) {
		baseWith := append([]string{}, base...)
		baseWith = append(baseWith, "GH_CONFIG_DIR=/host/.config/gh", "GITHUB_TOKEN=TEST_VALUE_NOT_A_SECRET")
		overrides := map[string]string{"GH_CONFIG_DIR": "/account/gh", "GH_TOKEN": "TEST_VALUE_NOT_A_SECRET"}
		env := agentSubprocessEnv(baseWith, configDir, dataDir, "", false, overrides)
		if v := agentEnvValue(env, "GH_CONFIG_DIR"); v != "/account/gh" {
			t.Fatalf("GH_CONFIG_DIR=%q want account value", v)
		}
		if v := agentEnvValue(env, "GH_TOKEN"); v != "TEST_VALUE_NOT_A_SECRET" {
			t.Fatalf("GH_TOKEN=%q want account value", v)
		}
		// Scrub first, so a value not configured for the account is absent.
		if v := agentEnvValue(env, "GITHUB_TOKEN"); v != "" {
			t.Fatalf("GITHUB_TOKEN=%q leaked from host into account", v)
		}
	})

	t.Run("account isolation", func(t *testing.T) {
		baseWith := append([]string{}, base...)
		baseWith = append(baseWith, "GH_CONFIG_DIR=/host/gh", "GH_TOKEN=TEST_VALUE_NOT_A_SECRET")
		envA := agentSubprocessEnv(baseWith, configDir, dataDir, "", false, map[string]string{"GH_CONFIG_DIR": "/host/gh-a"})
		envB := agentSubprocessEnv(baseWith, configDir, dataDir, "", false, map[string]string{})
		if agentEnvValue(envA, "GH_CONFIG_DIR") != "/host/gh-a" {
			t.Fatalf("account A lost its GH_CONFIG_DIR")
		}
		if agentEnvValue(envA, "GH_TOKEN") != "" {
			t.Fatalf("account A inherited host GH_TOKEN")
		}
		for _, v := range []string{"GH_CONFIG_DIR", "GH_TOKEN", "GITHUB_TOKEN"} {
			if agentEnvValue(envB, v) != "" {
				t.Fatalf("account B received host %s", v)
			}
		}
	})

	t.Run("explicit value precedence", func(t *testing.T) {
		baseWith := []string{"GH_CONFIG_DIR=/inherited/gh"}
		overrides := map[string]string{"GH_CONFIG_DIR": "/account/gh"}
		env := agentSubprocessEnv(baseWith, configDir, dataDir, "", false, overrides)
		if v := agentEnvValue(env, "GH_CONFIG_DIR"); v != "/account/gh" {
			t.Fatalf("GH_CONFIG_DIR=%q want account override", v)
		}
	})

	t.Run("does not duplicate XDG entries", func(t *testing.T) {
		env := agentSubprocessEnv(base, configDir, dataDir, "", false, nil)
		count := 0
		for _, e := range env {
			if strings.HasPrefix(e, "XDG_CONFIG_HOME=") {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("XDG_CONFIG_HOME appears %d times", count)
		}
	})
}

func TestAgentEnvValue(t *testing.T) {
	env := []string{"A=1", "B=x=2", "C="}
	if v := agentEnvValue(env, "B"); v != "x=2" {
		t.Fatalf("agentEnvValue(B)=%q want x=2", v)
	}
	if v := agentEnvValue(env, "D"); v != "" {
		t.Fatalf("agentEnvValue(D)=%q want empty", v)
	}
}