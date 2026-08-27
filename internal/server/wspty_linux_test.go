//go:build linux

package server

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestProcStatProcessGroups(t *testing.T) {
	pgid, tpgid, ok := procStatProcessGroups("123 (bash with spaces) S 1 123 123 34817 123 0 0 0")
	if !ok || pgid != 123 || tpgid != 123 {
		t.Fatalf("got pgid=%d tpgid=%d ok=%v", pgid, tpgid, ok)
	}
	if _, _, ok := procStatProcessGroups("malformed"); ok {
		t.Fatal("malformed stat unexpectedly parsed")
	}
}

func TestTerminalEnvironmentFiltersLoaderInjection(t *testing.T) {
	env := mergedEnvironment([]string{"PATH=/bin", "LD_PRELOAD=/tmp/evil", "BASH_ENV=/tmp/evil"}, map[string]string{
		"LD_LIBRARY_PATH": "/tmp/evil",
		"SAFE":            "value",
		"BROKEN":          "line\nvalue",
	})
	joined := strings.Join(env, "\n")
	for _, forbidden := range []string{"LD_PRELOAD=", "LD_LIBRARY_PATH=", "BASH_ENV=", "BROKEN="} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("unsafe environment retained %q in %q", forbidden, joined)
		}
	}
	if !strings.Contains(joined, "SAFE=value") {
		t.Fatalf("safe environment lost: %q", joined)
	}
}

func TestWebSocketFramesRequireMaskAndBoundSize(t *testing.T) {
	if _, _, err := readWS(bufio.NewReader(bytes.NewReader([]byte{0x81, 0x01, 'x'}))); err == nil {
		t.Fatal("accepted unmasked client frame")
	}
	var frame bytes.Buffer
	frame.Write([]byte{0x82, 0xff})
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], maxTerminalFrameBytes+1)
	frame.Write(size[:])
	if _, _, err := readWS(bufio.NewReader(&frame)); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized frame err=%v", err)
	}
}
