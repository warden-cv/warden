package server

import (
    "bytes"
    "os"
    "path/filepath"
    "testing"
)

func TestSecretStoreEncryptsAndReloads(t *testing.T) {
    dir := t.TempDir()
    s, err := loadSecretStore(dir)
    if err != nil { t.Fatal(err) }
    if err := s.set("example", "super-secret-value"); err != nil { t.Fatal(err) }
    raw, err := os.ReadFile(filepath.Join(dir, "secrets.json")); if err != nil { t.Fatal(err) }
    if bytes.Contains(raw, []byte("super-secret-value")) { t.Fatal("plaintext secret leaked into secrets.json") }
    s2, err := loadSecretStore(dir); if err != nil { t.Fatal(err) }
    got, ok := s2.get("example"); if !ok || got != "super-secret-value" { t.Fatalf("reload got %q, %v", got, ok) }
    keyInfo, err := os.Stat(filepath.Join(dir, "master.key")); if err != nil { t.Fatal(err) }
    if keyInfo.Mode().Perm() != 0600 { t.Fatalf("master key mode = %o", keyInfo.Mode().Perm()) }
}
