package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const configSchemaVersion = 1

type instanceConfigFile struct {
	Version       int    `json:"version"`
	Listen        string `json:"listen"`
	FileRoot      string `json:"file_root"`
	HomeDir       string `json:"home_dir"`
	StaticDir     string `json:"static_dir"`
	SecureCookies bool   `json:"secure_cookies"`
	TrustProxy    bool   `json:"trust_proxy"`
}

type environmentConfigFile struct {
	Version  int                          `json:"version"`
	Global   map[string]string            `json:"global"`
	Accounts map[string]map[string]string `json:"accounts"`
}

type googleAuthConfig struct {
	Enabled     bool   `json:"enabled"`
	ClientID    string `json:"client_id"`
	RedirectURL string `json:"redirect_url"`
}

type authenticationConfigFile struct {
	Version int              `json:"version"`
	Google  googleAuthConfig `json:"google"`
}

type aiProviderConfig struct {
	Label        string `json:"label"`
	Enabled      bool   `json:"enabled"`
	BaseURL      string `json:"base_url,omitempty"`
	DefaultModel string `json:"default_model,omitempty"`
}

type aiConfigFile struct {
	Version   int                         `json:"version"`
	Providers map[string]aiProviderConfig `json:"providers"`
}

type configStore struct {
	mu             sync.RWMutex
	dir            string
	instance       instanceConfigFile
	environment    environmentConfigFile
	authentication authenticationConfigFile
	ai             aiConfigFile
}

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func DefaultConfigDir() string {
	if v := strings.TrimSpace(os.Getenv("WARDEN_CONFIG_DIR")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); v != "" {
		return filepath.Join(v, "warden")
	}
	h, err := os.UserHomeDir()
	if err == nil && h != "" {
		return filepath.Join(h, ".config", "warden")
	}
	return ".warden"
}

// LoadConfig creates Warden's JSON configuration on first run and loads it on
// subsequent runs. The supplied defaults are used only to bootstrap a missing
// config file, keeping config.json as the durable source of truth afterwards.
func LoadConfig(configDir string, defaults Config) (Config, error) {
	if strings.TrimSpace(configDir) == "" {
		configDir = DefaultConfigDir()
	}
	defaults.ConfigDir = configDir
	store, err := loadConfigStore(configDir, instanceFromConfig(defaults))
	if err != nil {
		return Config{}, err
	}
	inst := store.instanceSnapshot()
	defaults.Listen = inst.Listen
	defaults.FileRoot = inst.FileRoot
	defaults.HomeDir = inst.HomeDir
	defaults.StaticDir = inst.StaticDir
	defaults.SecureCookies = inst.SecureCookies
	defaults.TrustProxy = inst.TrustProxy
	return defaults, nil
}

func instanceFromConfig(cfg Config) instanceConfigFile {
	return instanceConfigFile{
		Version: configSchemaVersion, Listen: cfg.Listen, FileRoot: cfg.FileRoot,
		HomeDir: cfg.HomeDir, StaticDir: cfg.StaticDir, SecureCookies: cfg.SecureCookies,
		TrustProxy: cfg.TrustProxy,
	}
}

func defaultAIConfig() aiConfigFile {
	return aiConfigFile{Version: configSchemaVersion, Providers: map[string]aiProviderConfig{
		"openai":     {Label: "OpenAI", BaseURL: "https://api.openai.com/v1"},
		"anthropic":  {Label: "Anthropic", BaseURL: "https://api.anthropic.com"},
		"gemini":     {Label: "Google Gemini", BaseURL: "https://generativelanguage.googleapis.com"},
		"openrouter": {Label: "OpenRouter", BaseURL: "https://openrouter.ai/api/v1"},
		"opencode":   {Label: "OpenCode Zen", BaseURL: "https://opencode.ai/zen/v1"},
		"ollama":     {Label: "Ollama", BaseURL: "http://127.0.0.1:11434"},
	}}
}

func loadConfigStore(dir string, defaults instanceConfigFile) (*configStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create config directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("secure config directory: %w", err)
	}
	s := &configStore{dir: dir}
	instancePath := filepath.Join(dir, "config.json")
	if _, err := os.Stat(instancePath); errors.Is(err, os.ErrNotExist) {
		defaults.Version = configSchemaVersion
		if err := validateInstanceConfig(defaults); err != nil {
			return nil, err
		}
		if err := writeJSONAtomic(instancePath, defaults, false); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	envPath := filepath.Join(dir, "environment.json")
	if _, err := os.Stat(envPath); errors.Is(err, os.ErrNotExist) {
		env := environmentConfigFile{Version: configSchemaVersion, Global: map[string]string{}, Accounts: map[string]map[string]string{}}
		if err := writeJSONAtomic(envPath, env, false); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	authPath := filepath.Join(dir, "authentication.json")
	if _, err := os.Stat(authPath); errors.Is(err, os.ErrNotExist) {
		auth := authenticationConfigFile{Version: configSchemaVersion}
		if err := writeJSONAtomic(authPath, auth, false); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	aiPath := filepath.Join(dir, "ai.json")
	if _, err := os.Stat(aiPath); errors.Is(err, os.ErrNotExist) {
		if err := writeJSONAtomic(aiPath, defaultAIConfig(), false); err != nil {
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

type configCandidate struct {
	instance       instanceConfigFile
	environment    environmentConfigFile
	authentication authenticationConfigFile
	ai             aiConfigFile
}

func (s *configStore) readCandidate() (configCandidate, error) {
	var c configCandidate
	if err := readJSONStrict(filepath.Join(s.dir, "config.json"), &c.instance); err != nil {
		return c, fmt.Errorf("config.json: %w", err)
	}
	if err := validateInstanceConfig(c.instance); err != nil {
		return c, fmt.Errorf("config.json: %w", err)
	}
	if err := readJSONStrict(filepath.Join(s.dir, "environment.json"), &c.environment); err != nil {
		return c, fmt.Errorf("environment.json: %w", err)
	}
	if err := validateEnvironmentConfig(c.environment); err != nil {
		return c, fmt.Errorf("environment.json: %w", err)
	}
	if c.environment.Global == nil {
		c.environment.Global = map[string]string{}
	}
	if c.environment.Accounts == nil {
		c.environment.Accounts = map[string]map[string]string{}
	}
	if err := readJSONStrict(filepath.Join(s.dir, "authentication.json"), &c.authentication); err != nil {
		return c, fmt.Errorf("authentication.json: %w", err)
	}
	if err := validateAuthenticationConfig(c.authentication); err != nil {
		return c, fmt.Errorf("authentication.json: %w", err)
	}
	if err := readJSONStrict(filepath.Join(s.dir, "ai.json"), &c.ai); err != nil {
		return c, fmt.Errorf("ai.json: %w", err)
	}
	if err := validateAIConfig(c.ai); err != nil {
		return c, fmt.Errorf("ai.json: %w", err)
	}
	return c, nil
}

func (s *configStore) applyCandidate(c configCandidate) {
	s.mu.Lock()
	s.instance = c.instance
	s.environment = c.environment
	s.authentication = c.authentication
	s.ai = c.ai
	s.mu.Unlock()
}

func (s *configStore) reload() error {
	c, err := s.readCandidate()
	if err != nil {
		return err
	}
	s.applyCandidate(c)
	return nil
}

func sortedAIProviderIDs(c aiConfigFile) []string {
	ids := make([]string, 0, len(c.Providers))
	for id := range c.Providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *configStore) aiSnapshot() aiConfigFile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := aiConfigFile{Version: s.ai.Version, Providers: map[string]aiProviderConfig{}}
	for id, p := range s.ai.Providers {
		out.Providers[id] = p
	}
	return out
}
func validateAIConfig(c aiConfigFile) error {
	if c.Version != configSchemaVersion {
		return fmt.Errorf("unsupported schema version %d", c.Version)
	}
	if c.Providers == nil {
		return errors.New("providers is required")
	}
	idRE := regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	for id, p := range c.Providers {
		if !idRE.MatchString(id) {
			return fmt.Errorf("invalid AI provider id %q", id)
		}
		if strings.TrimSpace(p.Label) == "" {
			return fmt.Errorf("AI provider %s has no label", id)
		}
		if strings.TrimSpace(p.BaseURL) != "" {
			u, err := url.Parse(p.BaseURL)
			if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"))) {
				return fmt.Errorf("AI provider %s has an invalid or insecure base_url", id)
			}
		}
	}
	return nil
}
func (s *configStore) setAIProvider(id string, p aiProviderConfig) error {
	next := s.aiSnapshot()
	next.Providers[id] = p
	if err := validateAIConfig(next); err != nil {
		return err
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, "ai.json"), next, true); err != nil {
		return err
	}
	return s.reload()
}

func (s *configStore) authenticationSnapshot() authenticationConfigFile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authentication
}

func validateAuthenticationConfig(c authenticationConfigFile) error {
	if c.Version != configSchemaVersion {
		return fmt.Errorf("unsupported schema version %d", c.Version)
	}
	if !c.Google.Enabled {
		return nil
	}
	if strings.TrimSpace(c.Google.ClientID) == "" {
		return errors.New("google.client_id is required when Google login is enabled")
	}
	u, err := url.Parse(strings.TrimSpace(c.Google.RedirectURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("google.redirect_url must be an absolute URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return errors.New("google.redirect_url must use HTTPS except on loopback")
	}
	if !strings.HasSuffix(u.Path, "/api/oauth/google/callback") {
		return errors.New("google.redirect_url must end with /api/oauth/google/callback")
	}
	return nil
}

func (s *configStore) replaceGoogleAuthentication(g googleAuthConfig) error {
	next := authenticationConfigFile{Version: configSchemaVersion, Google: g}
	if err := validateAuthenticationConfig(next); err != nil {
		return err
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, "authentication.json"), next, true); err != nil {
		return err
	}
	return s.reload()
}

func (s *configStore) instanceSnapshot() instanceConfigFile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.instance
}

func (s *configStore) environmentSnapshot() environmentConfigFile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := environmentConfigFile{Version: s.environment.Version, Global: cloneStringMap(s.environment.Global), Accounts: map[string]map[string]string{}}
	for id, vars := range s.environment.Accounts {
		out.Accounts[id] = cloneStringMap(vars)
	}
	return out
}

func (s *configStore) environmentFor(accountID string) map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := cloneStringMap(s.environment.Global)
	if vars := s.environment.Accounts[accountID]; vars != nil {
		for k, v := range vars {
			out[k] = v
		}
	}
	return out
}

func (s *configStore) replaceGlobalEnvironment(vars map[string]string) error {
	s.mu.RLock()
	next := environmentConfigFile{Version: configSchemaVersion, Global: cloneStringMap(vars), Accounts: map[string]map[string]string{}}
	for id, accountVars := range s.environment.Accounts {
		next.Accounts[id] = cloneStringMap(accountVars)
	}
	s.mu.RUnlock()
	if err := validateEnvironmentConfig(next); err != nil {
		return err
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, "environment.json"), next, true); err != nil {
		return err
	}
	return s.reload()
}

func validateInstanceConfig(c instanceConfigFile) error {
	if c.Version != configSchemaVersion {
		return fmt.Errorf("unsupported schema version %d", c.Version)
	}
	if strings.TrimSpace(c.Listen) == "" {
		return errors.New("listen is required")
	}
	if strings.TrimSpace(c.FileRoot) == "" || !filepath.IsAbs(c.FileRoot) {
		return errors.New("file_root must be an absolute path")
	}
	if strings.TrimSpace(c.HomeDir) == "" || !filepath.IsAbs(c.HomeDir) {
		return errors.New("home_dir must be an absolute path")
	}
	if strings.TrimSpace(c.StaticDir) == "" {
		return errors.New("static_dir is required")
	}
	return nil
}

func validateEnvironmentConfig(c environmentConfigFile) error {
	if c.Version != configSchemaVersion {
		return fmt.Errorf("unsupported schema version %d", c.Version)
	}
	check := func(scope string, vars map[string]string) error {
		for k, v := range vars {
			if !envNameRE.MatchString(k) {
				return fmt.Errorf("%s environment variable %q has an invalid name", scope, k)
			}
			if strings.ContainsRune(v, '\x00') {
				return fmt.Errorf("%s environment variable %q contains NUL", scope, k)
			}
		}
		return nil
	}
	if err := check("global", c.Global); err != nil {
		return err
	}
	for id, vars := range c.Accounts {
		if strings.TrimSpace(id) == "" {
			return errors.New("account environment has an empty account id")
		}
		if err := check("account "+id, vars); err != nil {
			return err
		}
	}
	return nil
}

func readJSONStrict(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing JSON")
		}
		return fmt.Errorf("unexpected trailing JSON: %w", err)
	}
	return nil
}

func writeJSONAtomic(path string, value any, backup bool) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if backup {
		if old, err := os.ReadFile(path); err == nil {
			if err := os.WriteFile(path+".bak", old, 0600); err != nil {
				return err
			}
		}
	}
	tmp, err := os.CreateTemp(dir, ".warden-config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sortedEnvironment(vars map[string]string) []map[string]string {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]string{"name": k, "value": vars[k]})
	}
	return out
}

func (a *app) collectWardenConfiguration() adminEnvelope {
	inst := a.config.instanceSnapshot()
	env := a.config.environmentSnapshot()
	authcfg := a.config.authenticationSnapshot()
	restart := []string{}
	if inst.Listen != a.cfg.Listen {
		restart = append(restart, "listen")
	}
	if inst.FileRoot != a.cfg.FileRoot {
		restart = append(restart, "file_root")
	}
	if inst.HomeDir != a.cfg.HomeDir {
		restart = append(restart, "home_dir")
	}
	if inst.StaticDir != a.cfg.StaticDir {
		restart = append(restart, "static_dir")
	}
	if inst.SecureCookies != a.cfg.SecureCookies {
		restart = append(restart, "secure_cookies")
	}
	if inst.TrustProxy != a.cfg.TrustProxy {
		restart = append(restart, "trust_proxy")
	}
	executable, _ := os.Executable()
	return adminEnvelope{Kind: "warden", Available: true, Data: map[string]any{
		"version":         a.cfg.Version,
		"executable":      executable,
		"installMethod":   detectInstallMethod(executable),
		"configDir":       a.config.dir,
		"instance":        inst,
		"environment":     sortedEnvironment(env.Global),
		"authentication":  authcfg,
		"googleSecretSet": func() bool { _, ok := a.secrets.get("google.client_secret"); return ok }(),
		"restartRequired": restart,
	}}
}

func (a *app) wardenConfigAction(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Action             string `json:"action"`
		Confirmation       string `json:"confirmation"`
		Password           string `json:"password"`
		GoogleEnabled      bool   `json:"googleEnabled"`
		GoogleClientID     string `json:"googleClientId"`
		GoogleClientSecret string `json:"googleClientSecret"`
		GoogleRedirectURL  string `json:"googleRedirectUrl"`
		Variables          []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"variables"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&q) != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	switch q.Action {
	case "reload":
		if err := a.reloadAllConfiguration(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.auditEvent(r, "warden_config_reload", "")
		jsonOut(w, map[string]any{"ok": true, "message": "Configuration reloaded and validated."})
	case "set-google":
		g := googleAuthConfig{Enabled: q.GoogleEnabled, ClientID: strings.TrimSpace(q.GoogleClientID), RedirectURL: strings.TrimSpace(q.GoogleRedirectURL)}
		if g.Enabled && strings.TrimSpace(q.GoogleClientSecret) == "" {
			if _, ok := a.secrets.get("google.client_secret"); !ok {
				http.Error(w, "Google client secret is required", 400)
				return
			}
		}
		if err := a.config.replaceGoogleAuthentication(g); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if strings.TrimSpace(q.GoogleClientSecret) != "" {
			if err := a.secrets.set("google.client_secret", q.GoogleClientSecret); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
		}
		a.auditEvent(r, "warden_google_auth_update", fmt.Sprintf("enabled=%t", g.Enabled))
		jsonOut(w, map[string]any{"ok": true, "message": "Google authentication settings saved."})
	case "set-environment":
		vars := map[string]string{}
		for _, item := range q.Variables {
			name := strings.TrimSpace(item.Name)
			if name == "" {
				continue
			}
			if _, exists := vars[name]; exists {
				http.Error(w, "duplicate environment variable "+name, http.StatusBadRequest)
				return
			}
			vars[name] = item.Value
		}
		if err := a.config.replaceGlobalEnvironment(vars); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.auditEvent(r, "warden_environment_update", fmt.Sprintf("count=%d", len(vars)))
		jsonOut(w, map[string]any{"ok": true, "message": "Environment saved. New terminal sessions will use it."})
	case "reset-instance":
		sess, ok := a.auth.get(r)
		if !ok || !a.accounts.verifyAccountPassword(sess.AccountID, q.Password) {
			http.Error(w, "your current Warden account password is incorrect", http.StatusForbidden)
			return
		}
		if q.Confirmation != "RESET WARDEN" {
			http.Error(w, "type RESET WARDEN to confirm", http.StatusBadRequest)
			return
		}
		a.auditEvent(r, "warden_instance_reset", "")
		if err := a.resetInstanceState(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOut(w, map[string]any{"ok": true, "message": "Warden state reset. Workspace files were not touched.", "setupRequired": true})
	case "reset-authentication":
		sess, ok := a.auth.get(r)
		if !ok || !a.accounts.verifyAccountPassword(sess.AccountID, q.Password) {
			http.Error(w, "your current Warden account password is incorrect", http.StatusForbidden)
			return
		}
		if q.Confirmation != "RESET" {
			http.Error(w, "type RESET to confirm", http.StatusBadRequest)
			return
		}
		if err := a.accounts.resetAccounts(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		a.auth.revokeAll()
		_ = a.secrets.deletePrefix("totp:")
		a.auditEvent(r, "warden_authentication_reset", "")
		jsonOut(w, map[string]any{"ok": true, "message": "Authentication reset. Reload Warden to create a new administrator.", "setupRequired": true})
	default:
		http.Error(w, "unsupported action", http.StatusBadRequest)
	}
}

func (s *configStore) replaceAccountEnvironment(accountID string, vars map[string]string) error {
	if strings.TrimSpace(accountID) == "" {
		return errors.New("account id is required")
	}
	s.mu.RLock()
	next := environmentConfigFile{Version: configSchemaVersion, Global: cloneStringMap(s.environment.Global), Accounts: map[string]map[string]string{}}
	for id, av := range s.environment.Accounts {
		next.Accounts[id] = cloneStringMap(av)
	}
	s.mu.RUnlock()
	if len(vars) == 0 {
		delete(next.Accounts, accountID)
	} else {
		next.Accounts[accountID] = cloneStringMap(vars)
	}
	if err := validateEnvironmentConfig(next); err != nil {
		return err
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, "environment.json"), next, true); err != nil {
		return err
	}
	return s.reload()
}

func detectInstallMethod(executable string) string {
	p := filepath.Clean(executable)
	switch {
	case strings.Contains(p, "/snap/"):
		return "snap"
	case strings.Contains(p, "/linuxbrew/") || strings.Contains(p, "/homebrew/"):
		return "homebrew"
	case strings.HasPrefix(p, "/usr/bin/") || strings.HasPrefix(p, "/usr/local/bin/"):
		return "system-or-standalone"
	default:
		return "standalone"
	}
}

type portableConfigBundle struct {
	Version        int                      `json:"version"`
	ExportedAt     time.Time                `json:"exported_at"`
	Instance       instanceConfigFile       `json:"instance"`
	Environment    environmentConfigFile    `json:"environment"`
	Authentication authenticationConfigFile `json:"authentication"`
	AI             aiConfigFile             `json:"ai"`
	Accounts       accountsFile             `json:"accounts"`
	Roles          rolesFile                `json:"roles"`
}

func (a *app) portableConfig() portableConfigBundle {
	a.accounts.mu.RLock()
	users := a.accounts.accounts
	users.Accounts = append([]account(nil), users.Accounts...)
	roles := a.accounts.roles
	roles.Roles = append([]role(nil), roles.Roles...)
	a.accounts.mu.RUnlock()
	return portableConfigBundle{Version: 1, ExportedAt: time.Now().UTC(), Instance: a.config.instanceSnapshot(), Environment: a.config.environmentSnapshot(), Authentication: a.config.authenticationSnapshot(), AI: a.config.aiSnapshot(), Accounts: users, Roles: roles}
}
