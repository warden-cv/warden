package server

import (
	"strings"
	"sync"
	"testing"
)

func FuzzValidDomain(f *testing.F) {
	for _, seed := range []string{"example.com", "sub.example.test", "-bad.test", "localhost", "a\n.invalid"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_ = validDomain(value)
	})
}

func FuzzValidLoopbackUpstream(f *testing.F) {
	for _, seed := range []string{"http://127.0.0.1:8080", "http://[::1]:3000", "https://example.com", "file:///etc/passwd", "http://127.0.0.1:1\nheader:x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_ = validLoopbackUpstream(value)
	})
}

func FuzzAgentSessionID(f *testing.F) {
	for _, seed := range []string{"session-123", "../escape", strings.Repeat("a", 129), "abc_DEF.123"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_ = validAgentSessionID(value)
	})
}

func FuzzAuditRedaction(f *testing.F) {
	for _, seed := range []string{"safe=value", "password=canary", "token=\"quoted canary\"", string([]byte{0xff, 0xfe})} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		got := redactAuditDetail(value)
		if len(got) > 4110 {
			t.Fatalf("redacted audit detail exceeded bound: %d", len(got))
		}
	})
}

func FuzzGitStatusParser(f *testing.F) {
	for _, seed := range [][]byte{[]byte(" M file.txt\x00"), []byte("R  old\x00new\x00"), {0xff, 0, '\n'}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		entries := parseGitStatus(value)
		if len(entries) > len(value)+1 {
			t.Fatalf("parser amplified %d input bytes into %d entries", len(value), len(entries))
		}
	})
}

func FuzzCronSchedule(f *testing.F) {
	for _, seed := range []string{"* * * * *", "0 2 * * 1", "@reboot", strings.Repeat("* ", 1000)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_ = validCronSchedule(value)
	})
}

func TestConcurrentAuditRedactionIsBounded(t *testing.T) {
	const workers = 32
	const rounds = 100
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if got := redactAuditDetail(strings.Repeat("x", 5000) + " password=canary"); len(got) > 4110 || strings.Contains(got, "canary") {
					t.Errorf("unbounded or unredacted result")
					return
				}
			}
		}()
	}
	wg.Wait()
}
