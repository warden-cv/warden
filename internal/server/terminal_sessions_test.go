package server

import "testing"

func TestTerminalSessionsAreAccountOwnedAndBounded(t *testing.T) {
	db, err := openDatabase(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	files, err := newFiles(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := &app{db: db, files: files}
	s := terminalSession{ID: "terminal-1", Title: "Build", CWD: "/"}
	if err := a.saveTerminalSession("account-a", &s); err != nil {
		t.Fatal(err)
	}
	a.appendTerminalScrollback("account-a", s.ID, []byte("hello"))
	items, err := a.loadTerminalSessions("account-a")
	if err != nil || len(items) != 1 || items[0].Scrollback != "hello" {
		t.Fatalf("unexpected terminal sessions: %#v, %v", items, err)
	}
	other, err := a.loadTerminalSessions("account-b")
	if err != nil || len(other) != 0 {
		t.Fatalf("other account saw terminal sessions: %#v, %v", other, err)
	}
	a.appendTerminalScrollback("account-a", s.ID, make([]byte, 300000))
	items, err = a.loadTerminalSessions("account-a")
	if err != nil || len(items[0].Scrollback) > 262144 {
		t.Fatalf("scrollback was not bounded: %d, %v", len(items[0].Scrollback), err)
	}
}
