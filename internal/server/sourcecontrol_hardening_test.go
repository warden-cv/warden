package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func initTestRepository(t *testing.T, root string) {
	t.Helper()
	for _, args := range [][]string{
		{"init"}, {"config", "user.email", "warden@example.invalid"}, {"config", "user.name", "Warden Test"},
	} {
		if _, err := runGit(root, args...); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSourceControlTreatsDashFilenameAsPath(t *testing.T) {
	root := t.TempDir()
	initTestRepository(t, root)
	if err := os.WriteFile(filepath.Join(root, "-nasty"), []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := newFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/source-control/mutate", strings.NewReader(`{"Root":"/","Action":"stage","Path":"-nasty"}`))
	rec := httptest.NewRecorder()
	f.sourceControlMutate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	out, err := runGit(root, "diff", "--cached", "--name-only", "--")
	if err != nil || strings.TrimSpace(out) != "-nasty" {
		t.Fatalf("staged=%q err=%v", out, err)
	}
}

func TestSourceControlCommitDoesNotRunRepositoryHooks(t *testing.T) {
	root := t.TempDir()
	initTestRepository(t, root)
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runGit(root, "add", "--", "file.txt"); err != nil {
		t.Fatal(err)
	}
	hooks := filepath.Join(root, ".git", "hooks")
	marker := filepath.Join(root, "hook-ran")
	hook := "#!/bin/sh\nprintf ran > '" + marker + "'\n"
	if err := os.WriteFile(filepath.Join(hooks, "pre-commit"), []byte(hook), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := runGit(root, "commit", "-m", "safe commit"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("repository hook executed: %v", err)
	}
}

func TestGitOutputIsBounded(t *testing.T) {
	w := &boundedCommandOutput{limit: 4}
	if n, err := w.Write([]byte("123456")); err != nil || n != 6 {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	if w.String() != "1234" || !w.truncated {
		t.Fatalf("output=%q truncated=%v", w.String(), w.truncated)
	}
}
