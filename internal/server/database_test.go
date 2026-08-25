package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDatabaseFoundation(t *testing.T) {
	dir := t.TempDir()
	db, err := openDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err := db.QueryRowContext(context.Background(), "SELECT MAX(version) FROM schema_migrations").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(databaseMigrations) {
		t.Fatalf("schema version = %d, want %d", version, len(databaseMigrations))
	}
	info, err := os.Stat(filepath.Join(dir, "warden.db"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("database mode = %o, want 600", info.Mode().Perm())
	}
}

func TestDatabaseRejectsFutureSchema(t *testing.T) {
	dir := t.TempDir()
	db, err := openDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO schema_migrations(version,name,applied_at) VALUES(999,'future',0)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := openDatabase(dir); err == nil {
		t.Fatal("newer schema was accepted")
	}
}
