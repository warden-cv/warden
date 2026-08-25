package server

import (
	"testing"
	"time"
)

func TestOAuthStateIsSingleUseAndExpires(t *testing.T) {
	s := newOAuthStateStore()
	id := s.put(oauthState{Mode: "login", Expires: time.Now().Add(time.Minute)})
	got, ok := s.take(id)
	if !ok || got.Mode != "login" {
		t.Fatal("state not returned")
	}
	if _, ok := s.take(id); ok {
		t.Fatal("OAuth state reused")
	}
	expired := s.put(oauthState{Mode: "login", Expires: time.Now().Add(-time.Second)})
	if _, ok := s.take(expired); ok {
		t.Fatal("expired OAuth state accepted")
	}
}

func TestGoogleAuthenticationConfigRequiresSafeCallback(t *testing.T) {
	good := authenticationConfigFile{Version: configSchemaVersion, Google: googleAuthConfig{Enabled: true, ClientID: "client", RedirectURL: "https://warden.example/api/oauth/google/callback"}}
	if err := validateAuthenticationConfig(good); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.Google.RedirectURL = "http://warden.example/api/oauth/google/callback"
	if err := validateAuthenticationConfig(bad); err == nil {
		t.Fatal("accepted insecure non-loopback redirect")
	}
	loopback := good
	loopback.Google.RedirectURL = "http://localhost:8080/api/oauth/google/callback"
	if err := validateAuthenticationConfig(loopback); err != nil {
		t.Fatal(err)
	}
}
