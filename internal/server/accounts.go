package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type loginIdentity struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	Username        string `json:"username,omitempty"`
	Email           string `json:"email,omitempty"`
	ProviderSubject string `json:"provider_subject,omitempty"`
	PasswordHash    string `json:"password_hash,omitempty"`
	Enabled         bool   `json:"enabled"`
}

type account struct {
	ID          string          `json:"id"`
	DisplayName string          `json:"display_name"`
	Enabled     bool            `json:"enabled"`
	Roles       []string        `json:"roles"`
	Identities  []loginIdentity `json:"identities"`
	CreatedAt   time.Time       `json:"created_at"`
}

type accountsFile struct {
	Version  int       `json:"version"`
	Accounts []account `json:"accounts"`
}

type role struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
	BuiltIn      bool     `json:"built_in,omitempty"`
}

type rolesFile struct {
	Version int    `json:"version"`
	Roles   []role `json:"roles"`
}

type accountStore struct {
	mu       sync.RWMutex
	dir      string
	accounts accountsFile
	roles    rolesFile
}

func loadAccountStore(dir string) (*accountStore, error) {
	s := &accountStore{dir: dir}
	usersPath := filepath.Join(dir, "users.json")
	if _, err := os.Stat(usersPath); errors.Is(err, os.ErrNotExist) {
		if err := writeJSONAtomic(usersPath, accountsFile{Version: configSchemaVersion, Accounts: []account{}}, false); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	rolesPath := filepath.Join(dir, "roles.json")
	if _, err := os.Stat(rolesPath); errors.Is(err, os.ErrNotExist) {
		defaults := rolesFile{Version: configSchemaVersion, Roles: []role{
			{ID: "administrator", Name: "Administrator", Capabilities: []string{"*"}, BuiltIn: true},
			{ID: "user", Name: "User", Capabilities: []string{}, BuiltIn: true},
		}}
		if err := writeJSONAtomic(rolesPath, defaults, false); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *accountStore) reload() error {
	var users accountsFile
	if err := readJSONStrict(filepath.Join(s.dir, "users.json"), &users); err != nil {
		return fmt.Errorf("users.json: %w", err)
	}
	var roles rolesFile
	if err := readJSONStrict(filepath.Join(s.dir, "roles.json"), &roles); err != nil {
		return fmt.Errorf("roles.json: %w", err)
	}
	if err := validateAccounts(users, roles); err != nil {
		return err
	}
	s.mu.Lock()
	s.accounts = users
	s.roles = roles
	s.mu.Unlock()
	return nil
}

func validateAccounts(users accountsFile, roles rolesFile) error {
	if users.Version != configSchemaVersion || roles.Version != configSchemaVersion {
		return errors.New("unsupported users/roles schema version")
	}
	roleIDs := map[string]bool{}
	for _, r := range roles.Roles {
		if r.ID == "" || roleIDs[r.ID] {
			return fmt.Errorf("duplicate/empty role id %q", r.ID)
		}
		roleIDs[r.ID] = true
	}
	accountIDs := map[string]bool{}
	identityIDs := map[string]bool{}
	usernames := map[string]bool{}
	googleSubjects := map[string]bool{}
	for _, a := range users.Accounts {
		if a.ID == "" || accountIDs[a.ID] {
			return fmt.Errorf("duplicate/empty account id %q", a.ID)
		}
		accountIDs[a.ID] = true
		if strings.TrimSpace(a.DisplayName) == "" {
			return fmt.Errorf("account %s has no display_name", a.ID)
		}
		for _, rid := range a.Roles {
			if !roleIDs[rid] {
				return fmt.Errorf("account %s references unknown role %s", a.ID, rid)
			}
		}
		for _, id := range a.Identities {
			if id.ID == "" || identityIDs[id.ID] {
				return fmt.Errorf("duplicate/empty identity id %q", id.ID)
			}
			identityIDs[id.ID] = true
			switch id.Type {
			case "password":
				u := strings.ToLower(strings.TrimSpace(id.Username))
				if u == "" || id.PasswordHash == "" {
					return fmt.Errorf("password identity %s is incomplete", id.ID)
				}
				if usernames[u] {
					return fmt.Errorf("duplicate username %q", id.Username)
				}
				usernames[u] = true
			case "email":
				if strings.TrimSpace(id.Email) == "" {
					return fmt.Errorf("email identity %s has no email", id.ID)
				}
			case "google":
				if id.ProviderSubject == "" {
					return fmt.Errorf("google identity %s has no provider_subject", id.ID)
				}
				if googleSubjects[id.ProviderSubject] {
					return fmt.Errorf("duplicate Google subject")
				}
				googleSubjects[id.ProviderSubject] = true
			default:
				return fmt.Errorf("identity %s has unsupported type %q", id.ID, id.Type)
			}
		}
	}
	return nil
}

func (s *accountStore) empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.accounts.Accounts) == 0
}

func (s *accountStore) findPassword(username string) (account, loginIdentity, bool) {
	u := strings.ToLower(strings.TrimSpace(username))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.accounts.Accounts {
		if !a.Enabled {
			continue
		}
		for _, id := range a.Identities {
			if id.Enabled && id.Type == "password" && strings.ToLower(id.Username) == u {
				return a, id, true
			}
		}
	}
	return account{}, loginIdentity{}, false
}

func (s *accountStore) accountByID(id string) (account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.accounts.Accounts {
		if a.ID == id {
			return a, true
		}
	}
	return account{}, false
}
func (s *accountStore) listAccounts() []account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]account(nil), s.accounts.Accounts...)
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].DisplayName) < strings.ToLower(out[j].DisplayName) })
	return out
}
func (s *accountStore) listRoles() []role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]role(nil), s.roles.Roles...)
}

func (s *accountStore) createInitialAdmin(display, username, password string) (account, error) {
	display = strings.TrimSpace(display)
	username = strings.TrimSpace(username)
	if display == "" || username == "" || len(password) < 10 {
		return account{}, errors.New("display name, username and a password of at least 10 characters are required")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return account{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.accounts.Accounts) != 0 {
		return account{}, errors.New("setup is already complete")
	}
	now := time.Now().UTC()
	a := account{ID: newID("acct"), DisplayName: display, Enabled: true, Roles: []string{"administrator"}, CreatedAt: now, Identities: []loginIdentity{{ID: newID("id"), Type: "password", Username: username, PasswordHash: hash, Enabled: true}}}
	next := s.accounts
	next.Accounts = append([]account(nil), a)
	if err := validateAccounts(next, s.roles); err != nil {
		return account{}, err
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, "users.json"), next, true); err != nil {
		return account{}, err
	}
	s.accounts = next
	return a, nil
}

func newID(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b)
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	iter := 310000
	dk := pbkdf2([]byte(password), salt, iter, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", iter, hex.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}
