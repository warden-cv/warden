package server

import "testing"

func TestAccountOwnedDurableConversation(t *testing.T) {
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
	c := durableConversation{ID: "conversation-1", Workspace: "/", Provider: "openai", Events: []durableAgentEvent{{Kind: "user", Text: "hello"}, {Kind: "assistant", Text: "hi"}}}
	if err := a.saveConversation("account-a", &c); err != nil {
		t.Fatal(err)
	}
	items, err := a.loadConversations("account-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || len(items[0].Events) != 2 {
		t.Fatalf("unexpected conversations: %#v", items)
	}
	other, err := a.loadConversations("account-b")
	if err != nil || len(other) != 0 {
		t.Fatalf("other account saw conversations: %#v, %v", other, err)
	}
}
