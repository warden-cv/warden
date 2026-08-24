//go:build linux

package server

import "testing"

func TestProcStatProcessGroups(t *testing.T) {
	pgid, tpgid, ok := procStatProcessGroups("123 (bash with spaces) S 1 123 123 34817 123 0 0 0")
	if !ok || pgid != 123 || tpgid != 123 {
		t.Fatalf("got pgid=%d tpgid=%d ok=%v", pgid, tpgid, ok)
	}
	if _, _, ok := procStatProcessGroups("malformed"); ok {
		t.Fatal("malformed stat unexpectedly parsed")
	}
}
