package server

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Listen, FileRoot, HomeDir, StaticDir, PasswordHash, Version, ConfigDir string
	SecureCookies, TrustProxy                                              bool
	StaticFS                                                               fs.FS
}
type app struct {
	cfg         Config
	db          *sql.DB
	auth        *authStore
	accounts    *accountStore
	files       *fileAPI
	audit       *log.Logger
	config      *configStore
	secrets     *secretStore
	aiUsage     *aiUsageStore
	setupToken  string
	totpMu      sync.Mutex
	totpPending map[string]totpEnrollment
	oauth       *oauthStateStore
}

func Run(cfg Config) error {
	db, e := openDatabase(cfg.ConfigDir)
	if e != nil {
		return fmt.Errorf("database: %w", e)
	}
	defer db.Close()
	store, e := loadConfigStore(cfg.ConfigDir, instanceFromConfig(cfg))
	if e != nil {
		return fmt.Errorf("configuration: %w", e)
	}
	f, e := newFiles(cfg.FileRoot)
	if e != nil {
		return fmt.Errorf("file root: %w", e)
	}
	accounts, e := loadAccountStore(cfg.ConfigDir)
	if e != nil {
		return fmt.Errorf("accounts: %w", e)
	}
	secrets, e := loadSecretStore(cfg.ConfigDir)
	if e != nil {
		return fmt.Errorf("secrets: %w", e)
	}
	aiUsage, e := loadAIUsageStore(cfg.ConfigDir)
	if e != nil {
		return fmt.Errorf("ai usage: %w", e)
	}
	auditFile, e := os.OpenFile(filepath.Join(cfg.ConfigDir, "audit.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer auditFile.Close()
	a := &app{cfg: cfg, db: db, accounts: accounts, secrets: secrets, aiUsage: aiUsage, files: f, totpPending: map[string]totpEnrollment{}, oauth: newOAuthStateStore(), audit: log.New(auditFile, "", log.LstdFlags|log.LUTC), config: store, setupToken: token(24)}
	a.auth = newAuth(accounts, cfg.SecureCookies, cfg.ConfigDir)
	if err := a.migrateLegacyState(); err != nil {
		return fmt.Errorf("legacy state migration: %w", err)
	}
	alertCtx, stopAlerts := context.WithCancel(context.Background())
	defer stopAlerts()
	defer a.syncLegacyState()
	go a.runLegacyStateMirror(alertCtx)
	go a.runAlertEvaluator(alertCtx)
	go a.runWebsiteJobs(alertCtx)
	if accounts.empty() {
		log.Printf("Warden first-run setup is required. Remote setup token: %s", a.setupToken)
	}
	mux := http.NewServeMux()
	for _, route := range a.apiRoutes() {
		mux.HandleFunc(route.Policy.Path, route.Handler)
	}
	if cfg.StaticFS != nil {
		mux.Handle("/", http.FileServer(http.FS(cfg.StaticFS)))
	} else {
		mux.Handle("/", http.FileServer(http.Dir(cfg.StaticDir)))
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: securityHeaders(httpBoundary(proxyTrust(cfg.TrustProxy, mux))), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 0, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	log.Printf("Warden %s listening on http://%s (root %s)", cfg.Version, cfg.Listen, f.root)
	return srv.ListenAndServe()
}
func (a *app) setupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", 405)
		return
	}
	jsonOut(w, map[string]any{"required": a.accounts.empty(), "legacyPasswordRequired": a.cfg.PasswordHash != "", "tokenRequired": !isLoopbackClient(r), "googleEnabled": a.googleReady()})
}
func (a *app) setup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	if !a.accounts.empty() {
		http.Error(w, "setup already complete", 409)
		return
	}
	var q struct{ DisplayName, Username, Password, LegacyPassword, SetupToken string }
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&q) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	if !isLoopbackClient(r) && subtle.ConstantTimeCompare([]byte(q.SetupToken), []byte(a.setupToken)) != 1 {
		http.Error(w, "invalid setup token", 403)
		return
	}
	if a.cfg.PasswordHash != "" && !verifyPassword(a.cfg.PasswordHash, q.LegacyPassword) {
		http.Error(w, "existing Warden password is required", 403)
		return
	}
	acct, err := a.accounts.createInitialAdmin(q.DisplayName, q.Username, q.Password)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	sess, err := a.auth.login(w, r, q.Username, q.Password)
	if err != nil {
		http.Error(w, "account created; sign in", 500)
		return
	}
	a.audit.Printf("setup_complete account=%s identity=%s ip=%s", acct.ID, sess.IdentityID, clientIP(r))
	jsonOut(w, a.sessionPayload(sess))
}
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	if a.accounts.empty() {
		http.Error(w, "setup required", 409)
		return
	}
	var q struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	acct, identity, e := a.auth.authenticatePassword(r, q.Username, q.Password)
	if e != nil {
		a.audit.Printf("auth_failed username=%q ip=%s", q.Username, clientIP(r))
		if e.Error() == "too many attempts" {
			http.Error(w, e.Error(), 429)
		} else {
			http.Error(w, "invalid credentials", 401)
		}
		return
	}
	if identity.TOTPEnabled {
		challenge := a.auth.beginChallenge(r, acct.ID, identity.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"twoFactorRequired": true, "challenge": challenge})
		return
	}
	sess, e := a.auth.createSession(w, r, acct.ID, identity.ID)
	if e != nil {
		http.Error(w, "session unavailable", 500)
		return
	}
	a.audit.Printf("auth_login account=%s identity=%s ip=%s", sess.AccountID, sess.IdentityID, clientIP(r))
	jsonOut(w, a.sessionPayload(sess))
}
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	a.auth.logout(w, r)
	a.audit.Printf("auth_logout ip=%s", clientIP(r))
	jsonOut(w, map[string]any{"ok": true})
}
func (a *app) session(w http.ResponseWriter, r *http.Request) {
	s, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	jsonOut(w, a.sessionPayload(s))
}
func (a *app) sessionPayload(s session) map[string]any {
	acct, _ := a.accounts.accountByID(s.AccountID)
	return map[string]any{
		"ok": true, "csrf": s.CSRF, "version": a.cfg.Version, "account": map[string]any{"id": acct.ID, "displayName": acct.DisplayName, "roles": acct.Roles, "capabilities": a.accounts.capabilities(acct.ID)},
		"fileStart":     a.files.startPath(a.cfg.HomeDir),
		"fileRoot":      a.files.virtualRootLabel(),
		"terminalStart": a.files.shellStart(a.cfg.HomeDir),
	}
}

func (a *app) auditEvent(r *http.Request, event, detail string) {
	accountID, identityID := "-", "-"
	if s, ok := a.auth.get(r); ok {
		accountID, identityID = s.AccountID, s.IdentityID
	}
	if strings.TrimSpace(detail) != "" {
		detail = " " + strings.TrimSpace(detail)
	}
	a.audit.Printf("event=%s account=%s identity=%s ip=%s%s", event, accountID, identityID, clientIP(r), detail)
	if a.db != nil {
		_, _ = a.db.Exec("INSERT INTO audit_events(event,account_id,identity_id,remote_ip,detail,created_at) VALUES(?,?,?,?,?,?)", event, accountID, identityID, clientIP(r), strings.TrimSpace(detail), time.Now().UnixMilli())
	}
}

func (a *app) exportConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="warden-config-export.json"`)
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(a.portableConfig())
}

func (a *app) monitor(w http.ResponseWriter, r *http.Request)   { jsonOut(w, monitor(a.files.root)) }
func (a *app) listFiles(w http.ResponseWriter, r *http.Request) { a.files.list(w, r) }
func (a *app) file(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if !a.sessionHasCapability(r, "files.read") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		a.files.read(w, r)
	case "PUT":
		if !a.sessionHasCapability(r, "files.write") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		a.auditEvent(r, "file_write", fmt.Sprintf("path=%q", r.URL.Query().Get("path")))
		a.files.write(w, r)
	default:
		http.Error(w, "method", 405)
	}
}
func (a *app) mutate(w http.ResponseWriter, r *http.Request) {
	a.auditEvent(r, "file_mutate", "")
	a.files.mutate(w, r)
}
func (a *app) archiveDownload(w http.ResponseWriter, r *http.Request) { a.files.archiveDownload(w, r) }
func (a *app) compress(w http.ResponseWriter, r *http.Request) {
	a.auditEvent(r, "file_compress", "")
	a.files.compress(w, r)
}
func (a *app) extract(w http.ResponseWriter, r *http.Request) {
	a.auditEvent(r, "file_extract", "")
	a.files.extract(w, r)
}
func (a *app) workspaceSearch(w http.ResponseWriter, r *http.Request) { a.files.workspaceSearch(w, r) }
func (a *app) workspaceReplace(w http.ResponseWriter, r *http.Request) {
	a.auditEvent(r, "workspace_replace", "")
	a.files.workspaceReplace(w, r)
}
func (a *app) workspaceUndoReplace(w http.ResponseWriter, r *http.Request) {
	a.auditEvent(r, "workspace_replace_undo", "")
	a.files.workspaceUndoReplace(w, r)
}
func (a *app) sourceControlStatus(w http.ResponseWriter, r *http.Request) {
	a.files.sourceControlStatus(w, r)
}
func (a *app) sourceControlMutate(w http.ResponseWriter, r *http.Request) {
	a.auditEvent(r, "source_control_mutate", "")
	a.files.sourceControlMutate(w, r)
}
func (a *app) terminal(w http.ResponseWriter, r *http.Request) {
	s, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	if !a.accounts.hasCapability(s.AccountID, "terminal.open") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.URL.Query().Get("csrf") != s.CSRF {
		http.Error(w, "csrf", 403)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "origin", 403)
		return
	}
	cwd := a.files.shellStart(a.cfg.HomeDir)
	sessionCWD := "/"
	if q := r.URL.Query().Get("cwd"); q != "" {
		if resolved, e := a.files.resolve(q, false); e == nil {
			if info, statErr := os.Stat(resolved); statErr == nil && info.IsDir() {
				cwd = resolved
				sessionCWD = q
			} else {
				http.Error(w, "terminal cwd must be a directory", 400)
				return
			}
		} else {
			http.Error(w, "invalid terminal cwd", 400)
			return
		}
	}
	sessionID := strings.TrimSpace(r.URL.Query().Get("session"))
	if !validAgentSessionID(sessionID) {
		http.Error(w, "invalid terminal session", 400)
		return
	}
	if err := a.connectTerminalSession(s.AccountID, sessionID, sessionCWD); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	a.auditEvent(r, "terminal_open", fmt.Sprintf("cwd=%q", cwd))
	hooks := ptyHooks{Output: func(p []byte) { a.appendTerminalScrollback(s.AccountID, sessionID, p) }}
	if e := servePTY(w, r, cwd, a.config.environmentFor(s.AccountID), hooks); e != nil {
		a.auditEvent(r, "terminal_error", fmt.Sprintf("err=%q", e))
	}
	a.disconnectTerminalSession(s.AccountID, sessionID)
}
func (a *app) protect(next http.HandlerFunc) http.HandlerFunc { return a.require("", next) }
func (a *app) require(capability string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.auth.get(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if capability != "" && !a.accounts.hasCapability(s.AccountID, capability) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Warden-CSRF") != s.CSRF {
			http.Error(w, "csrf", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
func (a *app) sessionHasCapability(r *http.Request, capability string) bool {
	s, ok := a.auth.get(r)
	return ok && a.accounts.hasCapability(s.AccountID, capability)
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

const maxRequestBody = 64 << 20

func httpBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if enc := strings.TrimSpace(r.Header.Get("Content-Encoding")); enc != "" && !strings.EqualFold(enc, "identity") {
			http.Error(w, "unsupported content encoding", http.StatusUnsupportedMediaType)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}
func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

type proxyTrustKey struct{}

func proxyTrust(enabled bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if enabled {
			r = r.WithContext(context.WithValue(r.Context(), proxyTrustKey{}, true))
		}
		next.ServeHTTP(w, r)
	})
}

func trustedProxy(r *http.Request) bool {
	trusted, _ := r.Context().Value(proxyTrustKey{}).(bool)
	if !trusted {
		return false
	}
	ip := net.ParseIP(directClientIP(r))
	return ip != nil && ip.IsLoopback()
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if trustedProxy(r) {
		raw := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
		if strings.Contains(raw, ",") {
			return "http"
		}
		if proto := strings.ToLower(raw); proto == "https" || proto == "http" {
			return proto
		}
	}
	return "http"
}

func forwardedClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		candidate := strings.TrimSpace(strings.Split(xff, ",")[0])
		if ip := net.ParseIP(candidate); ip != nil {
			return ip.String()
		}
	}
	if raw := strings.TrimSpace(r.Header.Get("X-Real-IP")); raw != "" {
		if ip := net.ParseIP(raw); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func directClientIP(r *http.Request) string {
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		return h
	}
	return r.RemoteAddr
}

func clientIP(r *http.Request) string {
	if trustedProxy(r) {
		if ip := forwardedClientIP(r); ip != "" {
			return ip
		}
	}
	return directClientIP(r)
}

func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host) && strings.EqualFold(u.Scheme, requestScheme(r))
}

func isLoopbackClient(r *http.Request) bool {
	if !trustedProxy(r) && (strings.TrimSpace(r.Header.Get("X-Forwarded-For")) != "" || strings.TrimSpace(r.Header.Get("X-Real-IP")) != "") {
		return false
	}
	ip := net.ParseIP(clientIP(r))
	return ip != nil && ip.IsLoopback()
}

var _ = filepath.Separator
