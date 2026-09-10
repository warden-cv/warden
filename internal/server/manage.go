package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

func (a *app) manageRoot(static http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/manage/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		sess, ok := a.auth.get(r)
		if !ok {
			http.Redirect(w, r, "/app/?return=%2Fmanage%2F", http.StatusFound)
			return
		}
		if !a.hasAnyCapability(sess.AccountID, "accounts.manage", "roles.manage", "launcher.configure.all") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		clone := r.Clone(r.Context())
		clone.URL.Path = "/manage.html"
		clone.URL.RawPath = ""
		w.Header().Set("Cache-Control", "no-store")
		static.ServeHTTP(w, clone)
	}
}

func (a *app) hasAnyCapability(accountID string, capabilities ...string) bool {
	for _, capability := range capabilities {
		if a.accounts.hasCapability(accountID, capability) {
			return true
		}
	}
	return false
}

func (a *app) manageUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	accounts := a.accounts.listAccounts()
	views := make([]accountView, 0, len(accounts))
	for _, acct := range accounts {
		view := publicAccount(acct)
		view.Sessions = a.auth.countSessions(acct.ID)
		views = append(views, view)
	}
	roles := a.accounts.listRoles()
	type roleOption struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	options := make([]roleOption, 0, len(roles))
	for _, item := range roles {
		options = append(options, roleOption{ID: item.ID, Name: item.Name})
	}
	jsonOut(w, map[string]any{"accounts": views, "roles": options})
}

func (a *app) manageRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	jsonOut(w, map[string]any{"roles": a.accounts.listRoles(), "capabilities": capabilityCatalog})
}

func allowManagementActions(allowed map[string]bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
		if err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		var envelope struct{ Action string }
		if json.Unmarshal(body, &envelope) != nil || !allowed[envelope.Action] {
			http.Error(w, "unsupported action", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next(w, r)
	}
}

func userManagementActions(next http.HandlerFunc) http.HandlerFunc {
	return allowManagementActions(map[string]bool{
		"create-account": true, "update-account": true, "add-email": true,
		"add-password": true, "reset-password": true, "revoke-sessions": true,
		"remove-identity": true, "delete-account": true,
	}, next)
}

func roleManagementActions(next http.HandlerFunc) http.HandlerFunc {
	return allowManagementActions(map[string]bool{"set-role": true}, next)
}
