package server

import (
	"strings"
	"testing"
)

func TestParseNetworkIOSumsPhysicalInterfacesAndSkipsLoopback(t *testing.T) {
	fixture := `Inter-| Receive | Transmit
 lo: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0
eth0: 1024 1 0 0 0 0 0 0 2048 1 0 0 0 0 0 0
wlan0: 4096 2 0 0 0 0 0 0 8192 2 0 0 0 0 0 0
`
	got := parseNetworkIO(strings.NewReader(fixture))
	if got.Received != 5120 || got.Transmitted != 10240 {
		t.Fatalf("parseNetworkIO() = %#v, want received 5120 and transmitted 10240", got)
	}
}
