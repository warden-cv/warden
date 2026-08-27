package server

import (
	"strings"
	"testing"
	"time"
)

func TestSystemExecutableRejectsPaths(t *testing.T) {
	for _, name := range []string{"/tmp/systemctl", "../bin/systemctl", "subdir/systemctl"} {
		if _, err := systemExecutable(name); err == nil {
			t.Fatalf("accepted executable path %q", name)
		}
	}
}

func TestFixedCommandInputIsBounded(t *testing.T) {
	_, err := fixedCommandInput(time.Second, make([]byte, (1<<20)+1), "true")
	if err == nil || !strings.Contains(err.Error(), "input exceeded") {
		t.Fatalf("oversized input err=%v", err)
	}
}
