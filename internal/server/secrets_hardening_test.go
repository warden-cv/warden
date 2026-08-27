package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSecretStoreRejectsSymlinkedKeyAndCiphertext(t *testing.T) {
	for _, target := range []string{"master.key", "secrets.json"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			outside := filepath.Join(t.TempDir(), "outside")
			body := []byte("outside")
			if target == "master.key" {
				body = make([]byte, 32)
				if err := os.WriteFile(filepath.Join(dir, "secrets.json"), []byte(`{"version":1,"values":{}}`), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(filepath.Join(dir, "master.key"), make([]byte, 32), 0600); err != nil {
					t.Fatal(err)
				}
				body = []byte(`{"version":1,"values":{}}`)
			}
			if err := os.WriteFile(outside, body, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(dir, target)); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if _, err := loadSecretStore(dir); err == nil {
				t.Fatalf("accepted symlinked %s", target)
			}
		})
	}
}

func TestSecretNoncesAreUniqueAndCorruptionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s, err := loadSecretStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 128; i++ {
		enc, err := s.encrypt("same plaintext")
		if err != nil {
			t.Fatal(err)
		}
		if seen[enc.Nonce] {
			t.Fatal("AES-GCM nonce was reused")
		}
		seen[enc.Nonce] = true
	}
	if err := s.set("canary", "secret-value"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file secretsFile
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	v := file.Values["canary"]
	i := len(v.Ciphertext) / 2
	replacement := "A"
	if v.Ciphertext[i:i+1] == replacement {
		replacement = "B"
	}
	v.Ciphertext = v.Ciphertext[:i] + replacement + v.Ciphertext[i+1:]
	file.Values["canary"] = v
	if err := writeJSONAtomic(filepath.Join(dir, "secrets.json"), file, false); err != nil {
		t.Fatal(err)
	}
	if err := s.reload(); err == nil {
		t.Fatal("accepted corrupt ciphertext")
	}
	if got, ok := s.get("canary"); !ok || got != "secret-value" {
		t.Fatal("failed reload replaced last known-good secret snapshot")
	}
}
