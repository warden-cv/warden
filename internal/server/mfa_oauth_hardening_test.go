package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTOTPChallengeIsSingleUseAndIPBound(t *testing.T) {
	auth := &authStore{sessions: map[string]session{}, failures: map[string][]time.Time{}, challenges: map[string]loginChallenge{}}
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/login/totp", nil)
	req.RemoteAddr = "127.0.0.1:1"
	id := auth.beginChallenge(req, "acct", "identity")
	if _, ok := auth.takeChallenge(req, id); !ok {
		t.Fatal("first challenge use failed")
	}
	if _, ok := auth.takeChallenge(req, id); ok {
		t.Fatal("challenge replay succeeded")
	}
	id = auth.beginChallenge(req, "acct", "identity")
	other := httptest.NewRequest(http.MethodPost, "http://warden/api/login/totp", nil)
	other.RemoteAddr = "127.0.0.2:1"
	if _, ok := auth.takeChallenge(other, id); ok {
		t.Fatal("cross-IP challenge succeeded")
	}
	if _, ok := auth.takeChallenge(req, id); ok {
		t.Fatal("failed cross-IP attempt did not consume challenge")
	}
}

func TestOAuthStateIsSingleUseAndBounded(t *testing.T) {
	s := newOAuthStateStore()
	first := s.put(oauthState{Expires: time.Now().Add(time.Minute)})
	if _, ok := s.take(first); !ok {
		t.Fatal("first state use failed")
	}
	if _, ok := s.take(first); ok {
		t.Fatal("OAuth state replay succeeded")
	}
	for i := 0; i < maxOAuthStates+20; i++ {
		s.put(oauthState{Expires: time.Now().Add(time.Minute)})
	}
	if len(s.states) != maxOAuthStates {
		t.Fatalf("states=%d", len(s.states))
	}
}
