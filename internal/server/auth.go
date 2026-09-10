package server

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"

	coreauth "github.com/gantry-tools/gantry-core/auth"
)

type session = coreauth.Session
type sessionView = coreauth.SessionView
type loginChallenge = coreauth.Challenge

type sessionsFile struct {
	Version  int                `json:"version"`
	Sessions map[string]session `json:"sessions"`
}

type sessionFilePersistence struct{ path string }

func (p sessionFilePersistence) LoadSessions() (map[string]session, error) {
	var document sessionsFile
	if _, err := os.Stat(p.path); errors.Is(err, os.ErrNotExist) {
		if err := writeJSONAtomic(p.path, sessionsFile{Version: configSchemaVersion, Sessions: map[string]session{}}, false); err != nil {
			return nil, err
		}
		return map[string]session{}, nil
	} else if err != nil {
		return nil, err
	}
	if err := readJSONStrict(p.path, &document); err != nil {
		return nil, err
	}
	if document.Version != configSchemaVersion {
		return nil, errors.New("unsupported sessions schema version")
	}
	return document.Sessions, nil
}

func (p sessionFilePersistence) SaveSessions(sessions map[string]session) error {
	return writeJSONAtomic(p.path, sessionsFile{Version: configSchemaVersion, Sessions: sessions}, false)
}

func (s *accountStore) AuthenticatePassword(username, password string) (account, loginIdentity, bool) {
	acct, identity, ok := s.findPassword(username)
	return acct, identity, ok && coreauth.VerifyPassword(identity.PasswordHash, password)
}

func (s *accountStore) SessionPrincipalActive(accountID, identityID string) bool {
	acct, ok := s.accountByID(accountID)
	if !ok || !acct.Enabled {
		return false
	}
	for _, identity := range acct.Identities {
		if identity.ID == identityID && identity.Enabled {
			return true
		}
	}
	return false
}

type authStore struct{ core *coreauth.SessionStore }

func newAuth(accounts *accountStore, secure bool, configDir string) *authStore {
	options := coreauth.SessionOptions{
		CookieName: "warden_session", CSRFHeader: "X-Warden-CSRF", SecureCookies: secure,
		ClientIP: clientIP, RequestScheme: requestScheme,
	}
	store, err := coreauth.NewSessionStore(accounts, sessionFilePersistence{path: filepath.Join(configDir, "sessions.json")}, options)
	if err != nil {
		// An unreadable session file must not prevent administrator recovery.
		store, _ = coreauth.NewSessionStore(accounts, nil, options)
	}
	return &authStore{core: store}
}

func token(size int) string { return coreauth.Token(size) }

func (a *authStore) limited(ip string) bool { return a.core.Limited(ip) }
func (a *authStore) fail(ip string) { a.core.Fail(ip) }
func (a *authStore) authenticatePassword(r *http.Request, username, password string) (account, loginIdentity, error) {
	return a.core.AuthenticatePassword(r, username, password)
}
func (a *authStore) createSession(w http.ResponseWriter, r *http.Request, accountID, identityID string) (session, error) {
	return a.core.CreateSession(w, r, accountID, identityID)
}
func (a *authStore) login(w http.ResponseWriter, r *http.Request, username, password string) (session, error) {
	return a.core.Login(w, r, username, password)
}
func (a *authStore) beginChallenge(r *http.Request, accountID, identityID string) string {
	return a.core.BeginChallenge(r, accountID, identityID)
}
func (a *authStore) takeChallenge(r *http.Request, id string) (loginChallenge, bool) {
	return a.core.TakeChallenge(r, id)
}
func (a *authStore) logout(w http.ResponseWriter, r *http.Request) { a.core.Logout(w, r) }
func (a *authStore) get(r *http.Request) (session, bool) { return a.core.Get(r) }
func (a *authStore) revokeAll() { a.core.RevokeAll() }
func (a *authStore) revokeAccount(accountID string) { a.core.RevokeAccount(accountID) }
func (a *authStore) listSessions(accountID string) []sessionView { return a.core.ListSessions(accountID) }
func (a *authStore) countSessions(accountID string) int { return a.core.CountSessions(accountID) }
func (a *authStore) revokeSession(accountID, sessionID string) bool {
	return a.core.RevokeSession(accountID, sessionID)
}
func (a *authStore) revokeIdentity(identityID string) { a.core.RevokeIdentity(identityID) }
func (a *authStore) revokeIdentityExcept(identityID, keepSessionID string) {
	a.core.RevokeIdentityExcept(identityID, keepSessionID)
}
func (a *authStore) currentSessionID(r *http.Request) string { return a.core.CurrentSessionID(r) }
func (a *authStore) validCSRF(r *http.Request, sess session) bool { return a.core.ValidCSRF(r, sess) }

func verifyPassword(encoded, password string) bool { return coreauth.VerifyPassword(encoded, password) }
