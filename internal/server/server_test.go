package server

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

func TestWorkspaceSearchAndReplaceConfined(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello world\nHELLO again\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "b.txt"), []byte("hello there\n"), 0640); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("hello secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	f, err := newFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	m, err := f.searchWorkspace(workspaceQuery{Root: "/", Query: "hello", CaseSensitive: false}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 {
		t.Fatalf("matches=%d want 3: %#v", len(m), m)
	}

	body := `{"Root":"/","Query":"hello","Replacement":"bye","Regex":false,"CaseSensitive":false}`
	r := httptest.NewRequest("POST", "/api/workspace/replace", strings.NewReader(body))
	w := httptest.NewRecorder()
	f.workspaceReplace(w, r)
	if w.Code != 200 {
		t.Fatalf("replace status %d: %s", w.Code, w.Body.String())
	}
	var replaced struct {
		UndoToken string   `json:"undoToken"`
		Paths     []string `json:"paths"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &replaced); err != nil || replaced.UndoToken == "" || len(replaced.Paths) != 2 {
		t.Fatalf("replace response=%s err=%v", w.Body.String(), err)
	}
	b, _ := os.ReadFile(filepath.Join(root, "a.txt"))
	if string(b) != "bye world\nbye again\n" {
		t.Fatalf("a.txt=%q", b)
	}
	secret, _ := os.ReadFile(filepath.Join(outside, "secret.txt"))
	if string(secret) != "hello secret\n" {
		t.Fatalf("symlink target was modified: %q", secret)
	}

	undoBody := `{"token":"` + replaced.UndoToken + `"}`
	ur := httptest.NewRequest("POST", "/api/workspace/replace/undo", strings.NewReader(undoBody))
	uw := httptest.NewRecorder()
	f.workspaceUndoReplace(uw, ur)
	if uw.Code != 200 {
		t.Fatalf("undo status %d: %s", uw.Code, uw.Body.String())
	}
	b, _ = os.ReadFile(filepath.Join(root, "a.txt"))
	if string(b) != "hello world\nHELLO again\n" {
		t.Fatalf("undo a.txt=%q", b)
	}
}

func TestZipCompressAndSafeExtract(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "folder"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "folder", "a.txt"), []byte("alpha"), 0640); err != nil {
		t.Fatal(err)
	}
	f, err := newFiles(root)
	if err != nil {
		t.Fatal(err)
	}

	cr := httptest.NewRequest("POST", "/api/files/compress", strings.NewReader(`{"paths":["/folder"],"target":"/bundle.zip"}`))
	cw := httptest.NewRecorder()
	f.compress(cw, cr)
	if cw.Code != 200 {
		t.Fatalf("compress status %d: %s", cw.Code, cw.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "bundle.zip")); err != nil {
		t.Fatal(err)
	}

	er := httptest.NewRequest("POST", "/api/files/extract", strings.NewReader(`{"Path":"/bundle.zip","Target":"/out"}`))
	ew := httptest.NewRecorder()
	f.extract(ew, er)
	if ew.Code != 200 {
		t.Fatalf("extract status %d: %s", ew.Code, ew.Body.String())
	}
	b, err := os.ReadFile(filepath.Join(root, "out", "folder", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "alpha" {
		t.Fatalf("extracted=%q", b)
	}
}

func TestFileStartPrefersHomeWithinRoot(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	if err := os.MkdirAll(home, 0750); err != nil {
		t.Fatal(err)
	}
	f, err := newFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.startPath(home); got != "/home/alice" {
		t.Fatalf("startPath=%q want /home/alice", got)
	}
	if got := f.shellStart(home); got != home {
		t.Fatalf("shellStart=%q want %q", got, home)
	}
}

func TestFileStartFallsBackToConfiguredRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	f, err := newFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.startPath(outside); got != "/" {
		t.Fatalf("startPath=%q want /", got)
	}
	if got := f.shellStart(outside); got != root {
		t.Fatalf("shellStart=%q want %q", got, root)
	}
}

func TestServiceActionUsesStructuredArguments(t *testing.T) {
	bin := t.TempDir()
	logPath := filepath.Join(bin, "args.log")
	script := filepath.Join(bin, "systemctl")
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$WARDEN_TEST_ARGS\"\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WARDEN_TEST_ARGS", logPath)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err := actionService(adminActionRequest{Action: "restart", Name: "nginx.service"}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "restart\nnginx.service\n" {
		t.Fatalf("args=%q", got)
	}
	if _, err := actionService(adminActionRequest{Action: "restart", Name: "pipewire.service", Scope: "user"}); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "--user\nrestart\npipewire.service\n" {
		t.Fatalf("user args=%q", got)
	}
	if _, err := actionService(adminActionRequest{Action: "restart", Name: "nginx.service;touch-pwned"}); err == nil {
		t.Fatal("unsafe service name accepted")
	}
}

func TestAdminInputValidation(t *testing.T) {
	if validCronSchedule("* * * * *; rm -rf /") {
		t.Fatal("invalid cron schedule accepted")
	}
	if _, err := actionFail2ban(adminActionRequest{Action: "ban", Name: "sshd", Target: "not-an-ip"}); err == nil {
		t.Fatal("invalid fail2ban IP accepted")
	}
	if _, err := actionFirewall(adminActionRequest{Action: "allow", Target: "22/tcp\nmalicious"}); err == nil {
		t.Fatal("newline firewall target accepted")
	}
	if _, err := actionUser(adminActionRequest{Action: "lock", Name: "bad;user"}); err == nil {
		t.Fatal("unsafe username accepted")
	}
}
