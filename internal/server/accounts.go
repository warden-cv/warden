package server

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type loginIdentity struct {
	ID                 string   `json:"id"`
	Type               string   `json:"type"`
	Username           string   `json:"username,omitempty"`
	Email              string   `json:"email,omitempty"`
	ProviderSubject    string   `json:"provider_subject,omitempty"`
	PasswordHash       string   `json:"password_hash,omitempty"`
	TOTPEnabled        bool     `json:"totp_enabled,omitempty"`
	RecoveryCodeHashes []string `json:"recovery_code_hashes,omitempty"`
	Enabled            bool     `json:"enabled"`
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
		defaults := defaultRoles()
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

func (s *accountStore) readCandidate() (accountsFile, rolesFile, error) {
	var users accountsFile
	if err := readJSONStrict(filepath.Join(s.dir, "users.json"), &users); err != nil {
		return users, rolesFile{}, fmt.Errorf("users.json: %w", err)
	}
	var roles rolesFile
	if err := readJSONStrict(filepath.Join(s.dir, "roles.json"), &roles); err != nil {
		return users, roles, fmt.Errorf("roles.json: %w", err)
	}
	if err := validateAccounts(users, roles); err != nil {
		return users, roles, err
	}
	return users, roles, nil
}

func (s *accountStore) applyCandidate(users accountsFile, roles rolesFile) {
	s.mu.Lock()
	s.accounts = users
	s.roles = roles
	s.mu.Unlock()
}

func (s *accountStore) reload() error {
	users, roles, err := s.readCandidate()
	if err != nil {
		return err
	}
	s.applyCandidate(users, roles)
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
		if r.ID == "administrator" && (len(r.Capabilities) != 1 || r.Capabilities[0] != "*") {
			return errors.New("administrator role must retain all capabilities")
		}
		for _, c := range r.Capabilities {
			if c != "*" && !knownCapability(c) {
				return fmt.Errorf("role %s has unknown capability %q", r.ID, c)
			}
		}
	}
	if !roleIDs["administrator"] {
		return errors.New("administrator role is required")
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

type capabilityInfo struct{ Key, Group, Label string }

var capabilityCatalog = []capabilityInfo{
	{"monitor.read", "Workspace", "View monitoring"},
	{"files.read", "Workspace", "Browse/read files"},
	{"files.write", "Workspace", "Create/edit/upload files"},
	{"files.manage", "Workspace", "Move/copy/delete/archive files"},
	{"workspace.search", "Editor", "Search workspaces"},
	{"workspace.replace", "Editor", "Replace across workspaces"},
	{"source.read", "Source control", "View Git status"},
	{"source.write", "Source control", "Stage/unstage/commit"},
	{"terminal.open", "Terminal", "Open interactive terminal"},
	{"system.read", "System", "View system administration pages"},
	{"system.manage", "System", "Change system services/settings"},
	{"accounts.manage", "Warden", "Manage Warden accounts and roles"},
	{"settings.manage", "Warden", "Manage instance configuration"},
	{"audit.read", "Warden", "View Warden audit history"},
	{"ai.use", "AI", "Use AI providers and manage own credentials"},
	{"ai.manage", "AI", "Manage shared AI provider configuration"},
}

func knownCapability(key string) bool {
	for _, c := range capabilityCatalog {
		if c.Key == key {
			return true
		}
	}
	return false
}
func defaultUserCapabilities() []string {
	return []string{"monitor.read", "files.read", "files.write", "files.manage", "workspace.search", "workspace.replace", "source.read", "source.write", "terminal.open", "ai.use"}
}

func (s *accountStore) capabilities(accountID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var acct *account
	for i := range s.accounts.Accounts {
		if s.accounts.Accounts[i].ID == accountID {
			acct = &s.accounts.Accounts[i]
			break
		}
	}
	if acct == nil || !acct.Enabled {
		return nil
	}
	set := map[string]bool{}
	for _, rid := range acct.Roles {
		for _, r := range s.roles.Roles {
			if r.ID == rid {
				for _, c := range r.Capabilities {
					if c == "*" {
						return []string{"*"}
					}
					set[c] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
func (s *accountStore) hasCapability(accountID, key string) bool {
	for _, c := range s.capabilities(accountID) {
		if c == "*" || c == key {
			return true
		}
	}
	return false
}

func (s *accountStore) createAccount(display, username, password string, roles []string) (account, error) {
	display = strings.TrimSpace(display)
	username = strings.TrimSpace(username)
	if display == "" || username == "" || len(password) < 10 {
		return account{}, errors.New("display name, username and a password of at least 10 characters are required")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return account{}, err
	}
	if len(roles) == 0 {
		roles = []string{"user"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := account{ID: newID("acct"), DisplayName: display, Enabled: true, Roles: dedupeStrings(roles), CreatedAt: time.Now().UTC(), Identities: []loginIdentity{{ID: newID("id"), Type: "password", Username: username, PasswordHash: hash, Enabled: true}}}
	next := s.accounts
	next.Accounts = append(append([]account(nil), s.accounts.Accounts...), a)
	if err := validateAccounts(next, s.roles); err != nil {
		return account{}, err
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, "users.json"), next, true); err != nil {
		return account{}, err
	}
	s.accounts = next
	return a, nil
}
func (s *accountStore) updateAccount(id, display string, enabled bool, roles []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.accounts
	next.Accounts = append([]account(nil), s.accounts.Accounts...)
	found := false
	for i := range next.Accounts {
		if next.Accounts[i].ID == id {
			found = true
			if strings.TrimSpace(display) != "" {
				next.Accounts[i].DisplayName = strings.TrimSpace(display)
			}
			next.Accounts[i].Enabled = enabled
			next.Accounts[i].Roles = dedupeStrings(roles)
		}
	}
	if !found {
		return errors.New("account not found")
	}
	if countEnabledAdmins(next.Accounts) == 0 {
		return errors.New("Warden must retain at least one enabled administrator")
	}
	if err := validateAccounts(next, s.roles); err != nil {
		return err
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, "users.json"), next, true); err != nil {
		return err
	}
	s.accounts = next
	return nil
}
func (s *accountStore) addEmailIdentity(accountID, email string) error {
	return s.addIdentity(accountID, loginIdentity{ID: newID("id"), Type: "email", Email: strings.TrimSpace(email), Enabled: true})
}
func (s *accountStore) addGoogleIdentity(accountID, subject, email string) error {
	subject = strings.TrimSpace(subject)
	email = strings.TrimSpace(email)
	if subject == "" {
		return errors.New("Google subject is required")
	}
	return s.addIdentity(accountID, loginIdentity{ID: newID("id"), Type: "google", ProviderSubject: subject, Email: email, Enabled: true})
}

func (s *accountStore) findGoogle(subject string) (account, loginIdentity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.accounts.Accounts {
		if !a.Enabled {
			continue
		}
		for _, id := range a.Identities {
			if id.Enabled && id.Type == "google" && id.ProviderSubject == subject {
				return a, id, true
			}
		}
	}
	return account{}, loginIdentity{}, false
}

func (s *accountStore) addPasswordIdentity(accountID, username, password string) error {
	if len(password) < 10 {
		return errors.New("password must be at least 10 characters")
	}
	h, e := hashPassword(password)
	if e != nil {
		return e
	}
	return s.addIdentity(accountID, loginIdentity{ID: newID("id"), Type: "password", Username: strings.TrimSpace(username), PasswordHash: h, Enabled: true})
}
func (s *accountStore) addIdentity(accountID string, id loginIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.accounts
	next.Accounts = append([]account(nil), s.accounts.Accounts...)
	found := false
	for i := range next.Accounts {
		if next.Accounts[i].ID == accountID {
			found = true
			next.Accounts[i].Identities = append(append([]loginIdentity(nil), next.Accounts[i].Identities...), id)
		}
	}
	if !found {
		return errors.New("account not found")
	}
	if err := validateAccounts(next, s.roles); err != nil {
		return err
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, "users.json"), next, true); err != nil {
		return err
	}
	s.accounts = next
	return nil
}
func (s *accountStore) identityByID(identityID string) (account, loginIdentity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.accounts.Accounts {
		for _, id := range a.Identities {
			if id.ID == identityID {
				return a, id, true
			}
		}
	}
	return account{}, loginIdentity{}, false
}

func (s *accountStore) verifyIdentityPassword(accountID, identityID, password string) bool {
	a, id, ok := s.identityByID(identityID)
	return ok && a.ID == accountID && a.Enabled && id.Enabled && id.Type == "password" && verifyPassword(id.PasswordHash, password)
}

func (s *accountStore) setIdentityPassword(accountID, identityID, password string) error {
	if len(password) < 10 {
		return errors.New("password must be at least 10 characters")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.accounts
	next.Accounts = append([]account(nil), s.accounts.Accounts...)
	found := false
	for i := range next.Accounts {
		if next.Accounts[i].ID != accountID {
			continue
		}
		next.Accounts[i].Identities = append([]loginIdentity(nil), next.Accounts[i].Identities...)
		for j := range next.Accounts[i].Identities {
			id := &next.Accounts[i].Identities[j]
			if id.ID == identityID {
				if id.Type != "password" {
					return errors.New("identity is not a password login")
				}
				id.PasswordHash = hash
				found = true
			}
		}
	}
	if !found {
		return errors.New("identity not found")
	}
	if err := validateAccounts(next, s.roles); err != nil {
		return err
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, "users.json"), next, true); err != nil {
		return err
	}
	s.accounts = next
	return nil
}

func (s *accountStore) setIdentityTOTP(accountID, identityID string, enabled bool, recoveryHashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.accounts
	next.Accounts = append([]account(nil), s.accounts.Accounts...)
	found := false
	for i := range next.Accounts {
		if next.Accounts[i].ID != accountID {
			continue
		}
		next.Accounts[i].Identities = append([]loginIdentity(nil), next.Accounts[i].Identities...)
		for j := range next.Accounts[i].Identities {
			id := &next.Accounts[i].Identities[j]
			if id.ID == identityID {
				if id.Type != "password" {
					return errors.New("TOTP is currently supported for password identities")
				}
				id.TOTPEnabled = enabled
				id.RecoveryCodeHashes = append([]string(nil), recoveryHashes...)
				found = true
			}
		}
	}
	if !found {
		return errors.New("identity not found")
	}
	if err := validateAccounts(next, s.roles); err != nil {
		return err
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, "users.json"), next, true); err != nil {
		return err
	}
	s.accounts = next
	return nil
}

func (s *accountStore) consumeRecoveryCode(accountID, identityID, hash string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.accounts
	next.Accounts = append([]account(nil), s.accounts.Accounts...)
	for i := range next.Accounts {
		if next.Accounts[i].ID != accountID {
			continue
		}
		next.Accounts[i].Identities = append([]loginIdentity(nil), next.Accounts[i].Identities...)
		for j := range next.Accounts[i].Identities {
			id := &next.Accounts[i].Identities[j]
			if id.ID != identityID {
				continue
			}
			for k, saved := range id.RecoveryCodeHashes {
				if hmac.Equal([]byte(saved), []byte(hash)) {
					id.RecoveryCodeHashes = append(append([]string(nil), id.RecoveryCodeHashes[:k]...), id.RecoveryCodeHashes[k+1:]...)
					if writeJSONAtomic(filepath.Join(s.dir, "users.json"), next, true) != nil {
						return false
					}
					s.accounts = next
					return true
				}
			}
		}
	}
	return false
}

func (s *accountStore) removeIdentity(accountID, identityID string) (loginIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.accounts
	next.Accounts = append([]account(nil), s.accounts.Accounts...)
	for i := range next.Accounts {
		if next.Accounts[i].ID != accountID {
			continue
		}
		ids := append([]loginIdentity(nil), next.Accounts[i].Identities...)
		idx := -1
		var removed loginIdentity
		loginCapable := 0
		for j, id := range ids {
			if id.Type == "password" || id.Type == "google" {
				loginCapable++
			}
			if id.ID == identityID {
				idx = j
				removed = id
			}
		}
		if idx < 0 {
			return loginIdentity{}, errors.New("identity not found")
		}
		if (removed.Type == "password" || removed.Type == "google") && loginCapable <= 1 {
			return loginIdentity{}, errors.New("account must retain at least one login identity")
		}
		next.Accounts[i].Identities = append(ids[:idx], ids[idx+1:]...)
		if err := validateAccounts(next, s.roles); err != nil {
			return loginIdentity{}, err
		}
		if err := writeJSONAtomic(filepath.Join(s.dir, "users.json"), next, true); err != nil {
			return loginIdentity{}, err
		}
		s.accounts = next
		return removed, nil
	}
	return loginIdentity{}, errors.New("account not found")
}

func (s *accountStore) deleteAccount(accountID string) ([]loginIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.accounts
	next.Accounts = append([]account(nil), s.accounts.Accounts...)
	idx := -1
	var identities []loginIdentity
	for i, a := range next.Accounts {
		if a.ID == accountID {
			idx = i
			identities = append([]loginIdentity(nil), a.Identities...)
			break
		}
	}
	if idx < 0 {
		return nil, errors.New("account not found")
	}
	next.Accounts = append(next.Accounts[:idx], next.Accounts[idx+1:]...)
	if len(next.Accounts) == 0 || countEnabledAdmins(next.Accounts) == 0 {
		return nil, errors.New("Warden must retain at least one enabled administrator")
	}
	if err := validateAccounts(next, s.roles); err != nil {
		return nil, err
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, "users.json"), next, true); err != nil {
		return nil, err
	}
	s.accounts = next
	return identities, nil
}

func (s *accountStore) setRole(id, name string, caps []string) error {
	id = strings.TrimSpace(id)
	name = strings.TrimSpace(name)
	if id == "" || name == "" {
		return errors.New("role id and name are required")
	}
	caps = dedupeStrings(caps)
	for _, c := range caps {
		if c != "*" && !knownCapability(c) {
			return fmt.Errorf("unknown capability %q", c)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.roles
	next.Roles = append([]role(nil), s.roles.Roles...)
	found := false
	for i := range next.Roles {
		if next.Roles[i].ID == id {
			found = true
			if next.Roles[i].BuiltIn && id == "administrator" {
				if len(caps) != 1 || caps[0] != "*" {
					return errors.New("administrator role must retain all capabilities")
				}
			}
			next.Roles[i].Name = name
			next.Roles[i].Capabilities = caps
		}
	}
	if !found {
		next.Roles = append(next.Roles, role{ID: id, Name: name, Capabilities: caps})
	}
	if err := validateAccounts(s.accounts, next); err != nil {
		return err
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, "roles.json"), next, true); err != nil {
		return err
	}
	s.roles = next
	return nil
}
func countEnabledAdmins(accounts []account) int {
	n := 0
	for _, a := range accounts {
		if !a.Enabled {
			continue
		}
		for _, r := range a.Roles {
			if r == "administrator" {
				n++
				break
			}
		}
	}
	return n
}
func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

type identityView struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	Username      string `json:"username,omitempty"`
	Email         string `json:"email,omitempty"`
	Enabled       bool   `json:"enabled"`
	TOTPEnabled   bool   `json:"totpEnabled,omitempty"`
	RecoveryCodes int    `json:"recoveryCodes,omitempty"`
}
type accountView struct {
	ID          string              `json:"id"`
	DisplayName string              `json:"displayName"`
	Enabled     bool                `json:"enabled"`
	Roles       []string            `json:"roles"`
	Identities  []identityView      `json:"identities"`
	CreatedAt   time.Time           `json:"createdAt"`
	Environment []map[string]string `json:"environment,omitempty"`
	Sessions    int                 `json:"sessions"`
}

func publicAccount(a account) accountView {
	v := accountView{ID: a.ID, DisplayName: a.DisplayName, Enabled: a.Enabled, Roles: append([]string(nil), a.Roles...), CreatedAt: a.CreatedAt}
	for _, id := range a.Identities {
		v.Identities = append(v.Identities, identityView{ID: id.ID, Type: id.Type, Username: id.Username, Email: id.Email, Enabled: id.Enabled, TOTPEnabled: id.TOTPEnabled, RecoveryCodes: len(id.RecoveryCodeHashes)})
	}
	return v
}

func (a *app) collectAccessConfiguration() adminEnvelope {
	accounts := a.accounts.listAccounts()
	views := make([]accountView, 0, len(accounts))
	for _, acct := range accounts {
		v := publicAccount(acct)
		v.Environment = sortedEnvironment(a.config.environmentSnapshot().Accounts[acct.ID])
		v.Sessions = a.auth.countSessions(acct.ID)
		views = append(views, v)
	}
	return adminEnvelope{Kind: "access", Available: true, Data: map[string]any{"accounts": views, "roles": a.accounts.listRoles(), "capabilities": capabilityCatalog}}
}
func (a *app) accessAction(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Action, ID, IdentityID, DisplayName, Username, Password, Email, RoleID, RoleName string
		Enabled                                                                          *bool
		Roles, Capabilities                                                              []string
		Variables                                                                        []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"variables"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&q) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	var err error
	msg := "Access settings updated."
	switch q.Action {
	case "create-account":
		_, err = a.accounts.createAccount(q.DisplayName, q.Username, q.Password, q.Roles)
		msg = "Account created."
	case "update-account":
		if q.Enabled == nil {
			err = errors.New("enabled is required")
		} else {
			err = a.accounts.updateAccount(q.ID, q.DisplayName, *q.Enabled, q.Roles)
			if err == nil && !*q.Enabled {
				a.auth.revokeAccount(q.ID)
			}
		}
	case "add-email":
		err = a.accounts.addEmailIdentity(q.ID, q.Email)
		msg = "Email identity added."
	case "add-password":
		err = a.accounts.addPasswordIdentity(q.ID, q.Username, q.Password)
		msg = "Password identity added."
	case "reset-password":
		err = a.accounts.setIdentityPassword(q.ID, q.IdentityID, q.Password)
		if err == nil {
			a.auth.revokeIdentity(q.IdentityID)
			msg = "Password reset and sessions for that login revoked."
		}
	case "revoke-sessions":
		a.auth.revokeAccount(q.ID)
		msg = "Account sessions revoked."
	case "remove-identity":
		removed, removeErr := a.accounts.removeIdentity(q.ID, q.IdentityID)
		err = removeErr
		if err == nil {
			a.auth.revokeIdentity(q.IdentityID)
			if removed.TOTPEnabled {
				_ = a.secrets.delete(totpSecretKey(q.IdentityID))
			}
			msg = "Identity removed."
		}
	case "delete-account":
		var identities []loginIdentity
		identities, err = a.accounts.deleteAccount(q.ID)
		if err == nil {
			a.auth.revokeAccount(q.ID)
			_ = a.config.replaceAccountEnvironment(q.ID, nil)
			for _, identity := range identities {
				_ = a.secrets.delete(totpSecretKey(identity.ID))
			}
			_ = a.secrets.deletePrefix(aiAccountSecretPrefix + q.ID + ".")
			msg = "Account deleted."
		}
	case "set-role":
		err = a.accounts.setRole(q.RoleID, q.RoleName, q.Capabilities)
		msg = "Role saved."
	case "set-environment":
		vars := map[string]string{}
		for _, item := range q.Variables {
			name := strings.TrimSpace(item.Name)
			if name != "" {
				vars[name] = item.Value
			}
		}
		err = a.config.replaceAccountEnvironment(q.ID, vars)
		msg = "Account environment saved."
	default:
		err = errors.New("unsupported action")
	}
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	a.auditEvent(r, "warden_access", fmt.Sprintf("action=%s target=%s", q.Action, q.ID))
	jsonOut(w, map[string]any{"ok": true, "message": msg})
}

func (s *accountStore) resetAccounts() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := accountsFile{Version: configSchemaVersion, Accounts: []account{}}
	if err := writeJSONAtomic(filepath.Join(s.dir, "users.json"), next, true); err != nil {
		return err
	}
	s.accounts = next
	return nil
}
