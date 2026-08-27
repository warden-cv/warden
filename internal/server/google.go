package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type oauthState struct {
	Mode         string
	AccountID    string
	CodeVerifier string
	Expires      time.Time
}

type oauthStateStore struct {
	mu     sync.Mutex
	states map[string]oauthState
}

const maxOAuthStates = 128

func newOAuthStateStore() *oauthStateStore { return &oauthStateStore{states: map[string]oauthState{}} }
func (s *oauthStateStore) put(v oauthState) string {
	id := token(32)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, st := range s.states {
		if st.Expires.Before(now) {
			delete(s.states, k)
		}
	}
	for len(s.states) >= maxOAuthStates {
		for k := range s.states {
			delete(s.states, k)
			break
		}
	}
	s.states[id] = v
	return id
}
func (s *oauthStateStore) take(id string) (oauthState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[id]
	delete(s.states, id)
	if !ok || time.Now().After(st.Expires) {
		return oauthState{}, false
	}
	return st, true
}

func (a *app) googleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", 405)
		return
	}
	cfg := a.config.authenticationSnapshot().Google
	clientSecret, hasSecret := a.secrets.get("google.client_secret")
	if !cfg.Enabled || strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(clientSecret) == "" || !hasSecret {
		http.Error(w, "Google login is not configured", http.StatusServiceUnavailable)
		return
	}
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "login"
	}
	verifier := token(48)
	state := oauthState{Mode: mode, CodeVerifier: verifier, Expires: time.Now().Add(10 * time.Minute)}
	if mode == "link" {
		sess, ok := a.auth.get(r)
		if !ok {
			http.Error(w, "sign in before linking Google", 401)
			return
		}
		state.AccountID = sess.AccountID
	} else if mode != "login" {
		http.Error(w, "invalid OAuth mode", 400)
		return
	}
	stateID := a.oauth.put(state)
	q := url.Values{}
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("state", stateID)
	q.Set("prompt", "select_account")
	sum := sha256.Sum256([]byte(verifier))
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	http.Redirect(w, r, "https://accounts.google.com/o/oauth2/v2/auth?"+q.Encode(), http.StatusFound)
}

func (a *app) googleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", 405)
		return
	}
	st, ok := a.oauth.take(r.URL.Query().Get("state"))
	if !ok {
		a.oauthRedirectError(w, r, "Invalid or expired Google sign-in state")
		return
	}
	if msg := r.URL.Query().Get("error"); msg != "" {
		a.oauthRedirectError(w, r, "Google sign-in was cancelled or denied")
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		a.oauthRedirectError(w, r, "Google did not return an authorization code")
		return
	}
	cfg := a.config.authenticationSnapshot().Google
	secret, ok := a.secrets.get("google.client_secret")
	if !cfg.Enabled || !ok {
		a.oauthRedirectError(w, r, "Google login is not configured")
		return
	}
	profile, err := exchangeGoogleCode(r.Context(), cfg, secret, code, st.CodeVerifier)
	if err != nil {
		a.audit.Printf("google_oauth_failed ip=%s error=%q", clientIP(r), err.Error())
		a.oauthRedirectError(w, r, "Google sign-in failed")
		return
	}
	if st.Mode == "link" {
		if _, _, exists := a.accounts.findGoogle(profile.Sub); exists {
			a.oauthRedirectError(w, r, "That Google account is already linked to Warden")
			return
		}
		if err := a.accounts.addGoogleIdentity(st.AccountID, profile.Sub, profile.Email); err != nil {
			a.oauthRedirectError(w, r, err.Error())
			return
		}
		a.audit.Printf("google_identity_linked account=%s subject=%s ip=%s", st.AccountID, profile.Sub, clientIP(r))
		http.Redirect(w, r, "/?oauth=linked", http.StatusFound)
		return
	}
	acct, identity, found := a.accounts.findGoogle(profile.Sub)
	if !found {
		a.oauthRedirectError(w, r, "This Google account is not linked to a Warden account")
		return
	}
	sess, err := a.auth.createSession(w, r, acct.ID, identity.ID)
	if err != nil {
		a.oauthRedirectError(w, r, "Could not create Warden session")
		return
	}
	a.audit.Printf("auth_login_google account=%s identity=%s ip=%s", sess.AccountID, sess.IdentityID, clientIP(r))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *app) oauthRedirectError(w http.ResponseWriter, r *http.Request, message string) {
	http.Redirect(w, r, "/?oauth_error="+url.QueryEscape(message), http.StatusFound)
}

type googleProfile struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

func exchangeGoogleCode(ctx context.Context, cfg googleAuthConfig, secret, code, verifier string) (googleProfile, error) {
	form := url.Values{"code": {code}, "client_id": {cfg.ClientID}, "client_secret": {secret}, "redirect_uri": {cfg.RedirectURL}, "grant_type": {"authorization_code"}, "code_verifier": {verifier}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return googleProfile{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return googleProfile{}, fmt.Errorf("token endpoint: %s", strings.TrimSpace(string(body)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return googleProfile{}, errors.New("Google token response had no access token")
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, "https://openidconnect.googleapis.com/v1/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err = client.Do(req)
	if err != nil {
		return googleProfile{}, err
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return googleProfile{}, fmt.Errorf("userinfo endpoint: %s", strings.TrimSpace(string(body)))
	}
	var profile googleProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return googleProfile{}, err
	}
	if strings.TrimSpace(profile.Sub) == "" {
		return googleProfile{}, errors.New("Google profile has no subject")
	}
	if strings.TrimSpace(profile.Email) == "" || !profile.EmailVerified {
		return googleProfile{}, errors.New("Google profile email is not verified")
	}
	return profile, nil
}

func (a *app) googleReady() bool {
	cfg := a.config.authenticationSnapshot().Google
	_, ok := a.secrets.get("google.client_secret")
	return cfg.Enabled && strings.TrimSpace(cfg.ClientID) != "" && strings.TrimSpace(cfg.RedirectURL) != "" && ok
}
