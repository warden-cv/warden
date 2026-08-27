package server

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
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

func TestEveryHistoricalMigrationPrefixUpgradesWithoutDataLoss(t *testing.T) {
	for prefix := 0; prefix < len(databaseMigrations); prefix++ {
		t.Run(string(rune('A'+prefix)), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "warden.db")
			db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < prefix; i++ {
				m := databaseMigrations[i]
				tx, err := db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				if _, err = tx.Exec(m.sql); err == nil {
					_, err = tx.Exec("INSERT INTO schema_migrations(version,name,applied_at) VALUES(?,?,?)", m.version, m.name, time.Now().UnixMilli())
				}
				if err != nil {
					_ = tx.Rollback()
					t.Fatal(err)
				}
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			seeded := prefix > 0
			if seeded {
				if _, err := db.Exec("INSERT INTO application_metadata(key,value,updated_at) VALUES('migration-canary','preserve-me',?)", time.Now().UnixMilli()); err != nil {
					t.Fatal(err)
				}
			}
			_ = db.Close()

			upgraded, err := openDatabase(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer upgraded.Close()
			var version int
			if err := upgraded.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version); err != nil || version != len(databaseMigrations) {
				t.Fatalf("version=%d err=%v", version, err)
			}
			if seeded {
				var value string
				if err := upgraded.QueryRow("SELECT value FROM application_metadata WHERE key='migration-canary'").Scan(&value); err != nil || value != "preserve-me" {
					t.Fatalf("migration lost data: value=%q err=%v", value, err)
				}
			}
		})
	}
}

func TestConcurrentDatabaseStartupConverges(t *testing.T) {
	dir := t.TempDir()
	const workers = 4
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db, err := openDatabase(dir)
			if err == nil {
				err = db.Close()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	db, err := openDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil || count != len(databaseMigrations) {
		t.Fatalf("migration rows=%d err=%v", count, err)
	}
}

func TestDatabaseRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "warden.db"), []byte("not a sqlite database"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openDatabase(dir); err == nil {
		t.Fatal("corrupt database was accepted")
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
