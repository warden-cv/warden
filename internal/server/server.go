package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Listen, FileRoot, HomeDir, StaticDir, PasswordHash, Version string
	SecureCookies, TrustProxy                                   bool
}
type app struct {
	cfg   Config
	auth  *authStore
	files *fileAPI
	audit *log.Logger
}

func Run(cfg Config) error {
	f, e := newFiles(cfg.FileRoot)
	if e != nil {
		return fmt.Errorf("file root: %w", e)
	}
	auditFile, e := os.OpenFile("warden-audit.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer auditFile.Close()
	a := &app{cfg: cfg, auth: newAuth(cfg.PasswordHash, cfg.SecureCookies), files: f, audit: log.New(auditFile, "", log.LstdFlags|log.LUTC)}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", a.login)
	mux.HandleFunc("/api/logout", a.protect(a.logout))
	mux.HandleFunc("/api/session", a.session)
	mux.HandleFunc("/api/monitor", a.protect(a.monitor))
	mux.HandleFunc("/api/files", a.protect(a.listFiles))
	mux.HandleFunc("/api/file", a.protect(a.file))
	mux.HandleFunc("/api/files/mutate", a.protect(a.mutate))
	mux.HandleFunc("/api/files/archive", a.protect(a.archiveDownload))
	mux.HandleFunc("/api/files/compress", a.protect(a.compress))
	mux.HandleFunc("/api/files/extract", a.protect(a.extract))
	mux.HandleFunc("/api/workspace/search", a.protect(a.workspaceSearch))
	mux.HandleFunc("/api/workspace/replace", a.protect(a.workspaceReplace))
	mux.HandleFunc("/api/workspace/replace/undo", a.protect(a.workspaceUndoReplace))
	mux.HandleFunc("/api/source-control/status", a.protect(a.sourceControlStatus))
	mux.HandleFunc("/api/source-control/mutate", a.protect(a.sourceControlMutate))
	mux.HandleFunc("/api/admin/", a.protect(a.admin))
	mux.HandleFunc("/api/terminal", a.terminal)
	mux.Handle("/", http.FileServer(http.Dir(cfg.StaticDir)))
	srv := &http.Server{Addr: cfg.Listen, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 0, IdleTimeout: 60 * time.Second}
	log.Printf("Warden %s listening on http://%s (root %s)", cfg.Version, cfg.Listen, f.root)
	return srv.ListenAndServe()
}
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	var q struct {
		Password string `json:"password"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	csrf, e := a.auth.login(w, r, q.Password)
	if e != nil {
		a.audit.Printf("auth_failed ip=%s", clientIP(r))
		http.Error(w, "invalid credentials", 401)
		return
	}
	a.audit.Printf("auth_login ip=%s", clientIP(r))
	jsonOut(w, a.sessionPayload(csrf))
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
	jsonOut(w, a.sessionPayload(s.CSRF))
}
func (a *app) sessionPayload(csrf string) map[string]any {
	return map[string]any{
		"ok": true, "csrf": csrf, "version": a.cfg.Version,
		"fileStart":     a.files.startPath(a.cfg.HomeDir),
		"fileRoot":      a.files.virtualRootLabel(),
		"terminalStart": a.files.shellStart(a.cfg.HomeDir),
	}
}

func (a *app) monitor(w http.ResponseWriter, r *http.Request)   { jsonOut(w, monitor(a.files.root)) }
func (a *app) listFiles(w http.ResponseWriter, r *http.Request) { a.files.list(w, r) }
func (a *app) file(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		a.files.read(w, r)
	case "PUT":
		a.audit.Printf("file_write ip=%s path=%q", clientIP(r), r.URL.Query().Get("path"))
		a.files.write(w, r)
	default:
		http.Error(w, "method", 405)
	}
}
func (a *app) mutate(w http.ResponseWriter, r *http.Request) {
	a.audit.Printf("file_mutate ip=%s", clientIP(r))
	a.files.mutate(w, r)
}
func (a *app) archiveDownload(w http.ResponseWriter, r *http.Request) { a.files.archiveDownload(w, r) }
func (a *app) compress(w http.ResponseWriter, r *http.Request) {
	a.audit.Printf("file_compress ip=%s", clientIP(r))
	a.files.compress(w, r)
}
func (a *app) extract(w http.ResponseWriter, r *http.Request) {
	a.audit.Printf("file_extract ip=%s", clientIP(r))
	a.files.extract(w, r)
}
func (a *app) workspaceSearch(w http.ResponseWriter, r *http.Request) { a.files.workspaceSearch(w, r) }
func (a *app) workspaceReplace(w http.ResponseWriter, r *http.Request) {
	a.audit.Printf("workspace_replace ip=%s", clientIP(r))
	a.files.workspaceReplace(w, r)
}
func (a *app) workspaceUndoReplace(w http.ResponseWriter, r *http.Request) {
	a.audit.Printf("workspace_replace_undo ip=%s", clientIP(r))
	a.files.workspaceUndoReplace(w, r)
}
func (a *app) sourceControlStatus(w http.ResponseWriter, r *http.Request) {
	a.files.sourceControlStatus(w, r)
}
func (a *app) sourceControlMutate(w http.ResponseWriter, r *http.Request) {
	a.audit.Printf("source_control_mutate ip=%s", clientIP(r))
	a.files.sourceControlMutate(w, r)
}
func (a *app) terminal(w http.ResponseWriter, r *http.Request) {
	s, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
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
	if q := r.URL.Query().Get("cwd"); q != "" {
		if resolved, e := a.files.resolve(q, false); e == nil {
			if info, statErr := os.Stat(resolved); statErr == nil && info.IsDir() {
				cwd = resolved
			} else {
				http.Error(w, "terminal cwd must be a directory", 400)
				return
			}
		} else {
			http.Error(w, "invalid terminal cwd", 400)
			return
		}
	}
	a.audit.Printf("terminal_open ip=%s cwd=%q", clientIP(r), cwd)
	if e := servePTY(w, r, cwd); e != nil {
		a.audit.Printf("terminal_error ip=%s err=%q", clientIP(r), e)
	}
}
func (a *app) protect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.auth.get(r)
		if !ok {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Header.Get("X-Warden-CSRF") != s.CSRF {
			http.Error(w, "csrf", 403)
			return
		}
		next(w, r)
	}
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}
func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func clientIP(r *http.Request) string {
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		return h
	}
	return r.RemoteAddr
}
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

var _ = filepath.Separator
