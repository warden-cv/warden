package server

import (
	"encoding/base64"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testHash(password string) string {
	salt := []byte("0123456789abcdef")
	return "pbkdf2-sha256$100000$" + hex.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(pbkdf2([]byte(password), salt, 100000, 32))
}

func TestPasswordVerification(t *testing.T) {
	h := testHash("correct horse battery staple")
	if !verifyPassword(h, "correct horse battery staple") {
		t.Fatal("expected password to verify")
	}
	if verifyPassword(h, "wrong") {
		t.Fatal("wrong password verified")
	}
}

func TestFileRootConfinement(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("nope"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	f, err := newFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.resolve("/escape/secret", false); err == nil {
		t.Fatal("symlink escape was accepted")
	}
	if got, err := f.resolve("/", false); err != nil || got != f.root {
		t.Fatalf("root resolve = %q, %v", got, err)
	}
}

func TestFileWriteAtomicAndPreservesMode(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "config.txt")
	if err := os.WriteFile(p, []byte("old"), 0640); err != nil {
		t.Fatal(err)
	}
	f, err := newFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("PUT", "/api/file?path=/config.txt", strings.NewReader("new contents"))
	w := httptest.NewRecorder()
	f.write(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	b, _ := os.ReadFile(p)
	if string(b) != "new contents" {
		t.Fatalf("content = %q", b)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0640 {
		t.Fatalf("mode = %o", st.Mode().Perm())
	}
}
