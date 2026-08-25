package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func defaultRoles() rolesFile {
	return rolesFile{Version: configSchemaVersion, Roles: []role{
		{ID: "administrator", Name: "Administrator", Capabilities: []string{"*"}, BuiltIn: true},
		{ID: "user", Name: "User", Capabilities: defaultUserCapabilities(), BuiltIn: true},
	}}
}

func validatePortableBundle(b portableConfigBundle) error {
	if b.Version != 1 {
		return fmt.Errorf("unsupported export version %d", b.Version)
	}
	if err := validateInstanceConfig(b.Instance); err != nil {
		return fmt.Errorf("instance: %w", err)
	}
	if err := validateEnvironmentConfig(b.Environment); err != nil {
		return fmt.Errorf("environment: %w", err)
	}
	if err := validateAuthenticationConfig(b.Authentication); err != nil {
		return fmt.Errorf("authentication: %w", err)
	}
	if err := validateAIConfig(b.AI); err != nil {
		return fmt.Errorf("ai: %w", err)
	}
	if err := validateAccounts(b.Accounts, b.Roles); err != nil {
		return fmt.Errorf("accounts/roles: %w", err)
	}
	if len(b.Accounts.Accounts) == 0 || countEnabledAdmins(b.Accounts.Accounts) == 0 {
		return errors.New("import must contain at least one enabled administrator")
	}
	return nil
}

func marshalJSONFile(value any) ([]byte, error) {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// replaceConfigFiles validates all candidate state before any file is changed,
// then writes the batch with rollback-on-error. Workspace/project files are
// deliberately outside this mechanism.
func replaceConfigFiles(dir string, values map[string]any) error {
	original := map[string][]byte{}
	created := map[string]bool{}
	encoded := map[string][]byte{}
	for name, value := range values {
		b, err := marshalJSONFile(value)
		if err != nil {
			return err
		}
		encoded[name] = b
		path := filepath.Join(dir, name)
		old, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			created[name] = true
		} else if err != nil {
			return err
		} else {
			original[name] = old
		}
	}
	written := []string{}
	rollback := func() {
		for i := len(written) - 1; i >= 0; i-- {
			name := written[i]
			path := filepath.Join(dir, name)
			if created[name] {
				_ = os.Remove(path)
			} else if old, ok := original[name]; ok {
				_ = os.WriteFile(path, old, 0600)
			}
		}
	}
	for name := range encoded {
		path := filepath.Join(dir, name)
		var decoded any
		if err := json.Unmarshal(encoded[name], &decoded); err != nil {
			rollback()
			return err
		}
		// writeJSONAtomic remarshal is intentional: permissions/fsync/backups
		// remain centralized in the existing configuration primitive.
		if err := writeRawJSONAtomic(path, encoded[name], true); err != nil {
			rollback()
			return err
		}
		written = append(written, name)
	}
	return nil
}

func writeRawJSONAtomic(path string, b []byte, backup bool) error {
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
	tmp, err := os.CreateTemp(dir, ".warden-import-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
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
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return nil
}

func (a *app) importConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var bundle portableConfigBundle
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bundle); err != nil {
		http.Error(w, "invalid configuration export: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validatePortableBundle(bundle); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	values := map[string]any{
		"config.json":         bundle.Instance,
		"environment.json":    bundle.Environment,
		"authentication.json": bundle.Authentication,
		"ai.json":             bundle.AI,
		"users.json":          bundle.Accounts,
		"roles.json":          bundle.Roles,
	}
	if err := replaceConfigFiles(a.cfg.ConfigDir, values); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.reloadAllConfiguration(); err != nil {
		http.Error(w, "configuration was written but could not be reloaded: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.auth.revokeAll()
	a.auditEvent(r, "warden_configuration_import", fmt.Sprintf("exported_at=%s", bundle.ExportedAt.UTC().Format(time.RFC3339)))
	jsonOut(w, map[string]any{"ok": true, "message": "Configuration imported. Sign in using an imported account.", "reauthenticate": true})
}

func (a *app) resetInstanceState() error {
	values := map[string]any{
		"config.json":         instanceFromConfig(a.cfg),
		"environment.json":    environmentConfigFile{Version: configSchemaVersion, Global: map[string]string{}, Accounts: map[string]map[string]string{}},
		"authentication.json": authenticationConfigFile{Version: configSchemaVersion},
		"ai.json":             defaultAIConfig(),
		"users.json":          accountsFile{Version: configSchemaVersion, Accounts: []account{}},
		"roles.json":          defaultRoles(),
	}
	if err := replaceConfigFiles(a.cfg.ConfigDir, values); err != nil {
		return err
	}
	if err := a.secrets.reset(); err != nil {
		return err
	}
	if err := a.aiUsage.reset(); err != nil {
		return err
	}
	if err := a.reloadAllConfiguration(); err != nil {
		return err
	}
	a.auth.revokeAll()
	return nil
}

func (a *app) reloadAllConfiguration() error {
	// Validate every independently editable store first. Only after every
	// candidate is known-good do we swap the in-memory snapshots.
	cfgCandidate, err := a.config.readCandidate()
	if err != nil {
		return err
	}
	accountsCandidate, rolesCandidate, err := a.accounts.readCandidate()
	if err != nil {
		return err
	}
	secretsCandidate, err := a.secrets.readCandidate()
	if err != nil {
		return err
	}

	a.config.applyCandidate(cfgCandidate)
	a.accounts.applyCandidate(accountsCandidate, rolesCandidate)
	a.secrets.applyCandidate(secretsCandidate)
	return nil
}
