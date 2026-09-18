package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResetWardenAuthRollsBackOnPartialFailure verifies the multi-file auth
// reset is transactional: if one file cannot be moved, already-moved files are
// restored so a partial failure can never leave the half-reset state that
// would abort startup on stale sessions.
func TestResetWardenAuthRollsBackOnPartialFailure(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"users.json", "sessions.json", "roles.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	oldRename := renameFile
	renameFile = func(oldpath, newpath string) error {
		if strings.HasSuffix(newpath, "sessions.json") {
			return errors.New("injected failure")
		}
		return os.Rename(oldpath, newpath)
	}
	t.Cleanup(func() { renameFile = oldRename })

	if err := resetWarden(dir, false); err == nil {
		t.Fatal("partial reset must fail")
	}
	for _, name := range []string{"users.json", "sessions.json", "roles.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("after rollback %s is missing: %v", name, err)
		}
	}
}

func TestResetWardenAuthPreservesRolesAndClearsSessions(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"users.json", "sessions.json", "roles.json", "config.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	if err := resetWarden(dir, false); err != nil {
		t.Fatalf("auth reset: %v", err)
	}

	// Configuration (roles, instance config) must survive an auth-only reset.
	for _, name := range []string{"roles.json", "config.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("auth reset removed non-auth state %s: %v", name, err)
		}
	}
	// Account and session state must be removed so restart yields first-run
	// setup rather than failing to migrate stale sessions.
	for _, name := range []string{"users.json", "sessions.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("auth reset left auth state %s: %v", name, err)
		}
	}
	backups, err := filepath.Glob(filepath.Join(dir, "reset-backups", "*"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v, err = %v; want one", backups, err)
	}
	for _, name := range []string{"users.json", "sessions.json"} {
		if _, err := os.Stat(filepath.Join(backups[0], name)); err != nil {
			t.Fatalf("auth state %s not in backup: %v", name, err)
		}
	}
}

func TestResetWardenAllMovesWholeDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte("state"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := resetWarden(dir, true); err != nil {
		t.Fatalf("all reset: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "marker")); !os.IsNotExist(err) {
		t.Fatalf("recreated directory retained old marker: %v", err)
	}
	backups, err := filepath.Glob(dir + ".reset-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v, err = %v; want one", backups, err)
	}
	if got, err := os.ReadFile(filepath.Join(backups[0], "marker")); err != nil || string(got) != "state" {
		t.Fatalf("backup marker = %q, err = %v", got, err)
	}
}
