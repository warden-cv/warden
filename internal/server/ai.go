package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

const (
	aiSharedSecretPrefix  = "ai.shared."
	aiAccountSecretPrefix = "ai.account."
)

type aiProviderView struct {
	ID                        string `json:"id"`
	Label                     string `json:"label"`
	Enabled                   bool   `json:"enabled"`
	BaseURL                   string `json:"baseUrl,omitempty"`
	DefaultModel              string `json:"defaultModel,omitempty"`
	AccountCredentialSet      bool   `json:"accountCredentialSet"`
	SharedCredentialSet       bool   `json:"sharedCredentialSet"`
	EffectiveCredentialSource string `json:"effectiveCredentialSource"`
}

type aiAccountUsageView struct {
	AccountID   string           `json:"accountId"`
	DisplayName string           `json:"displayName"`
	Usage       []aiUsageSummary `json:"usage"`
}

func aiSharedSecretName(provider string) string { return aiSharedSecretPrefix + provider }
func aiAccountSecretName(accountID, provider string) string {
	return aiAccountSecretPrefix + accountID + "." + provider
}

func (a *app) resolveAICredential(accountID, provider string) (string, string, bool) {
	if a.accounts == nil || a.accounts.hasCapability(accountID, "ai.credentials") {
		if key, ok := a.secrets.get(aiAccountSecretName(accountID, provider)); ok && strings.TrimSpace(key) != "" {
			return key, "account", true
		}
	}
	if key, ok := a.secrets.get(aiSharedSecretName(provider)); ok && strings.TrimSpace(key) != "" {
		return key, "shared", true
	}
	return "", "none", false
}

func (a *app) aiSettings(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !a.accounts.hasCapability(sess.AccountID, "ai.use") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg := a.config.aiSnapshot()
		ids := sortedAIProviderIDs(cfg)
		providers := make([]aiProviderView, 0, len(ids))
		for _, id := range ids {
			p := cfg.Providers[id]
			_, own := a.secrets.get(aiAccountSecretName(sess.AccountID, id))
			_, shared := a.secrets.get(aiSharedSecretName(id))
			_, source, _ := a.resolveAICredential(sess.AccountID, id)
			providers = append(providers, aiProviderView{ID: id, Label: p.Label, Enabled: p.Enabled, BaseURL: p.BaseURL, DefaultModel: p.DefaultModel, AccountCredentialSet: own, SharedCredentialSet: shared, EffectiveCredentialSource: source})
		}
		canManage := a.accounts.hasCapability(sess.AccountID, "ai.manage")
		canManageCredentials := a.accounts.hasCapability(sess.AccountID, "ai.credentials")
		response := map[string]any{
			"providers":            providers,
			"usage":                a.aiUsage.summary(sess.AccountID),
			"canManage":            canManage,
			"canManageCredentials": canManageCredentials,
		}
		if canManage {
			allUsage := a.aiUsage.allSummaries()
			accountUsage := make([]aiAccountUsageView, 0, len(allUsage))
			for _, acct := range a.accounts.listAccounts() {
				usage := allUsage[acct.ID]
				if len(usage) == 0 {
					continue
				}
				accountUsage = append(accountUsage, aiAccountUsageView{AccountID: acct.ID, DisplayName: acct.DisplayName, Usage: usage})
			}
			response["accountUsage"] = accountUsage
		}
		jsonOut(w, response)
	case http.MethodPost:
		var q struct {
			Action       string `json:"action"`
			Provider     string `json:"provider"`
			Credential   string `json:"credential"`
			Label        string `json:"label"`
			Enabled      bool   `json:"enabled"`
			BaseURL      string `json:"baseUrl"`
			DefaultModel string `json:"defaultModel"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&q) != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		provider := strings.TrimSpace(q.Provider)
		cfg := a.config.aiSnapshot()
		current, exists := cfg.Providers[provider]
		if !exists {
			http.Error(w, "unknown AI provider", http.StatusBadRequest)
			return
		}
		switch q.Action {
		case "set-account-credential":
			if !a.accounts.hasCapability(sess.AccountID, "ai.credentials") {
				http.Error(w, "personal AI credentials are disabled for this account", http.StatusForbidden)
				return
			}
			if strings.TrimSpace(q.Credential) == "" {
				http.Error(w, "credential is required", http.StatusBadRequest)
				return
			}
			if err := a.secrets.set(aiAccountSecretName(sess.AccountID, provider), q.Credential); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			a.auditEvent(r, "ai_account_credential_set", "provider="+provider)
		case "clear-account-credential":
			if !a.accounts.hasCapability(sess.AccountID, "ai.credentials") {
				http.Error(w, "personal AI credentials are disabled for this account", http.StatusForbidden)
				return
			}
			if err := a.secrets.delete(aiAccountSecretName(sess.AccountID, provider)); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			a.auditEvent(r, "ai_account_credential_clear", "provider="+provider)
		case "set-shared-credential":
			if !a.accounts.hasCapability(sess.AccountID, "ai.manage") {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if strings.TrimSpace(q.Credential) == "" {
				http.Error(w, "credential is required", http.StatusBadRequest)
				return
			}
			if err := a.secrets.set(aiSharedSecretName(provider), q.Credential); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			a.auditEvent(r, "ai_shared_credential_set", "provider="+provider)
		case "clear-shared-credential":
			if !a.accounts.hasCapability(sess.AccountID, "ai.manage") {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if err := a.secrets.delete(aiSharedSecretName(provider)); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			a.auditEvent(r, "ai_shared_credential_clear", "provider="+provider)
		case "set-provider":
			if !a.accounts.hasCapability(sess.AccountID, "ai.manage") {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next := aiProviderConfig{Label: strings.TrimSpace(q.Label), Enabled: q.Enabled, BaseURL: strings.TrimSpace(q.BaseURL), DefaultModel: strings.TrimSpace(q.DefaultModel)}
			if next.Label == "" {
				next.Label = current.Label
			}
			if err := a.config.setAIProvider(provider, next); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			a.auditEvent(r, "ai_provider_update", "provider="+provider)
		default:
			http.Error(w, "unsupported action", http.StatusBadRequest)
			return
		}
		jsonOut(w, map[string]any{"ok": true})
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func validateAIProviderID(cfg aiConfigFile, provider string) error {
	if _, ok := cfg.Providers[provider]; !ok {
		return errors.New("unknown AI provider")
	}
	return nil
}
