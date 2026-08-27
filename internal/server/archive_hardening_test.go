package server

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractionPreflightLeavesNoPartialTarget(t *testing.T) {
	root := t.TempDir()
	f, err := newFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	writeTestZip(t, filepath.Join(root, "hostile.zip"), map[string]string{
		"valid.txt": "would otherwise be written",
		"../escape": "outside",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/files/extract", strings.NewReader(`{"Path":"/hostile.zip","Target":"/out"}`))
	rec := httptest.NewRecorder()
	f.extract(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if _, err := os.Lstat(filepath.Join(root, "out")); !os.IsNotExist(err) {
		t.Fatalf("partial extraction target exists: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(root), "escape")); !os.IsNotExist(err) {
		t.Fatalf("archive escaped root: %v", err)
	}
}

func TestArchiveExpansionRatioIsBounded(t *testing.T) {
	root := t.TempDir()
	f, err := newFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	writeTestZip(t, filepath.Join(root, "bomb.zip"), map[string]string{"zeros.bin": string(bytes.Repeat([]byte{0}, 2<<20))})
	req := httptest.NewRequest(http.MethodPost, "/api/files/extract", strings.NewReader(`{"Path":"/bomb.zip","Target":"/out"}`))
	rec := httptest.NewRecorder()
	f.extract(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "expansion-ratio") {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestCopyRefusesSymlinksAndSpecialFiles(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	if err := os.Mkdir(src, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(src, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := copyPath(src, filepath.Join(root, "copy")); err == nil {
		t.Fatal("copied directory containing symlink")
	}
	if _, err := os.Stat(filepath.Join(root, "copy", "escape")); !os.IsNotExist(err) {
		t.Fatalf("symlink target was copied: %v", err)
	}
}
