package main

import "testing"

func TestIsLoopbackListen(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"[::1]:8080", true},
		{"0.0.0.0:8080", false},
		{"192.0.2.10:8080", false},
		{"bad-address", false},
	} {
		if got := isLoopbackListen(tc.addr); got != tc.want {
			t.Fatalf("isLoopbackListen(%q)=%v want %v", tc.addr, got, tc.want)
		}
	}
}
