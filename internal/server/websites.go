package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type managedWebsite struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	DocumentRoot string   `json:"documentRoot"`
	Upstream     string   `json:"upstream"`
	Enabled      bool     `json:"enabled"`
	Domains      []string `json:"domains"`
	Revision     int      `json:"revision,omitempty"`
	CreatedAt    int64    `json:"createdAt,omitempty"`
	UpdatedAt    int64    `json:"updatedAt,omitempty"`
}

type operationJob struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	TargetID   string `json:"targetId"`
	State      string `json:"state"`
	Result     string `json:"result"`
	CreatedAt  int64  `json:"createdAt"`
	StartedAt  int64  `json:"startedAt,omitempty"`
	FinishedAt int64  `json:"finishedAt,omitempty"`
}

func (a *app) websitesAPI(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method == http.MethodGet {
		sites, jobs, err := a.loadWebsites()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		jsonOut(w, map[string]any{"websites": sites, "jobs": jobs, "fragmentDir": filepath.Join(a.cfg.ConfigDir, "sites"), "canManage": a.accounts.hasCapability(sess.AccountID, "system.manage")})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	if !a.accounts.hasCapability(sess.AccountID, "system.manage") {
		http.Error(w, "forbidden", 403)
		return
	}
	var q struct {
		Action  string         `json:"action"`
		Website managedWebsite `json:"website"`
		ID      string         `json:"id"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&q) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	var err error
	switch q.Action {
	case "save":
		err = a.saveWebsite(sess.AccountID, &q.Website)
	case "delete":
		_, err = a.db.Exec("DELETE FROM websites WHERE id=?", q.ID)
	case "publish":
		err = a.queueWebsiteJob(sess.AccountID, q.ID, "publish")
	default:
		err = errors.New("unknown website action")
	}
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	jsonOut(w, map[string]bool{"ok": true})
}

func (a *app) saveWebsite(accountID string, site *managedWebsite) error {
	if site.ID == "" {
		site.ID = token(18)
	}
	if !validAgentSessionID(site.ID) || len(site.Name) > 200 || len(site.Domains) == 0 || len(site.Domains) > 20 {
		return errors.New("invalid website")
	}
	if site.Kind != "static" && site.Kind != "proxy" {
		return errors.New("website kind must be static or proxy")
	}
	for i := range site.Domains {
		site.Domains[i] = strings.ToLower(strings.TrimSpace(site.Domains[i]))
		if !validDomain(site.Domains[i]) {
			return errors.New("invalid website domain")
		}
	}
	sort.Strings(site.Domains)
	if site.Kind == "static" {
		if _, err := a.files.resolve(site.DocumentRoot, false); err != nil {
			return errors.New("invalid document root")
		}
		site.Upstream = ""
	} else {
		if !validLoopbackUpstream(site.Upstream) {
			return errors.New("proxy upstream must be an http(s) loopback URL")
		}
		site.DocumentRoot = ""
	}
	now := time.Now().UnixMilli()
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO websites(id,name,kind,document_root,upstream,enabled,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,kind=excluded.kind,document_root=excluded.document_root,upstream=excluded.upstream,enabled=excluded.enabled,updated_at=excluded.updated_at`, site.ID, strings.TrimSpace(site.Name), site.Kind, site.DocumentRoot, site.Upstream, site.Enabled, accountID, now, now)
	if err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM website_domains WHERE website_id=?", site.ID); err != nil {
		return err
	}
	for i, domain := range site.Domains {
		if _, err = tx.Exec("INSERT INTO website_domains(website_id,domain,primary_domain) VALUES(?,?,?)", site.ID, domain, i == 0); err != nil {
			return err
		}
	}
	var sequence int
	if err = tx.QueryRow("SELECT COALESCE(MAX(sequence),0)+1 FROM website_revisions WHERE website_id=?", site.ID).Scan(&sequence); err != nil {
		return err
	}
	site.Revision = sequence
	snapshot, _ := json.Marshal(site)
	if _, err = tx.Exec("INSERT INTO website_revisions(id,website_id,sequence,configuration_json,created_by,created_at) VALUES(?,?,?,?,?,?)", token(18), site.ID, sequence, snapshot, accountID, now); err != nil {
		return err
	}
	return tx.Commit()
}

func validDomain(domain string) bool {
	if domain == "localhost" {
		return true
	}
	if len(domain) == 0 || len(domain) > 253 || strings.ContainsAny(domain, "/:@ ") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func validLoopbackUpstream(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (a *app) queueWebsiteJob(accountID, siteID, kind string) error {
	var exists int
	if err := a.db.QueryRow("SELECT COUNT(*) FROM websites WHERE id=?", siteID).Scan(&exists); err != nil || exists != 1 {
		return errors.New("website not found")
	}
	_, err := a.db.Exec("INSERT INTO operation_jobs(id,kind,target_type,target_id,state,requested_by,created_at) VALUES(?,?, 'website',?,'queued',?,?)", token(18), kind, siteID, accountID, time.Now().UnixMilli())
	return err
}

func (a *app) loadWebsites() ([]managedWebsite, []operationJob, error) {
	rows, err := a.db.Query(`SELECT w.id,w.name,w.kind,w.document_root,w.upstream,w.enabled,w.created_at,w.updated_at,
		COALESCE((SELECT MAX(sequence) FROM website_revisions r WHERE r.website_id=w.id),0) FROM websites w ORDER BY w.name`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	sites := []managedWebsite{}
	for rows.Next() {
		var s managedWebsite
		if err := rows.Scan(&s.ID, &s.Name, &s.Kind, &s.DocumentRoot, &s.Upstream, &s.Enabled, &s.CreatedAt, &s.UpdatedAt, &s.Revision); err != nil {
			return nil, nil, err
		}
		drows, err := a.db.Query("SELECT domain FROM website_domains WHERE website_id=? ORDER BY primary_domain DESC,domain", s.ID)
		if err != nil {
			return nil, nil, err
		}
		for drows.Next() {
			var d string
			_ = drows.Scan(&d)
			s.Domains = append(s.Domains, d)
		}
		drows.Close()
		sites = append(sites, s)
	}
	jobs := []operationJob{}
	jrows, err := a.db.Query("SELECT id,kind,target_id,state,result,created_at,started_at,finished_at FROM operation_jobs WHERE target_type='website' ORDER BY created_at DESC LIMIT 50")
	if err != nil {
		return nil, nil, err
	}
	defer jrows.Close()
	for jrows.Next() {
		var j operationJob
		var started, finished sql.NullInt64
		if err := jrows.Scan(&j.ID, &j.Kind, &j.TargetID, &j.State, &j.Result, &j.CreatedAt, &started, &finished); err != nil {
			return nil, nil, err
		}
		if started.Valid {
			j.StartedAt = started.Int64
		}
		if finished.Valid {
			j.FinishedAt = finished.Int64
		}
		jobs = append(jobs, j)
	}
	return sites, jobs, jrows.Err()
}

func (a *app) runWebsiteJobs(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.processWebsiteJob()
		}
	}
}

func (a *app) processWebsiteJob() {
	var id, siteID string
	err := a.db.QueryRow("SELECT id,target_id FROM operation_jobs WHERE state='queued' ORDER BY created_at LIMIT 1").Scan(&id, &siteID)
	if err != nil {
		return
	}
	now := time.Now().UnixMilli()
	result := ""
	state := "completed"
	_, _ = a.db.Exec("UPDATE operation_jobs SET state='running',started_at=? WHERE id=? AND state='queued'", now, id)
	sites, _, err := a.loadWebsites()
	var site *managedWebsite
	for i := range sites {
		if sites[i].ID == siteID {
			site = &sites[i]
			break
		}
	}
	if err != nil || site == nil {
		state = "failed"
		result = "website not found"
	} else {
		if site.Kind == "static" {
			if resolved, resolveErr := a.files.resolve(site.DocumentRoot, false); resolveErr == nil {
				site.DocumentRoot = resolved
			} else {
				err = resolveErr
			}
		}
		dir := filepath.Join(a.cfg.ConfigDir, "sites")
		if err == nil {
			err = os.MkdirAll(dir, 0700)
		}
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, site.ID+".caddy"), []byte(renderCaddyWebsite(*site)), 0600)
		}
		if err != nil {
			state = "failed"
			result = err.Error()
		} else {
			result = fmt.Sprintf("Rendered revision %d to %s", site.Revision, filepath.Join(dir, site.ID+".caddy"))
		}
	}
	_, _ = a.db.Exec("UPDATE operation_jobs SET state=?,result=?,finished_at=? WHERE id=?", state, result, time.Now().UnixMilli(), id)
}

func renderCaddyWebsite(site managedWebsite) string {
	if !site.Enabled {
		return fmt.Sprintf("# disabled website %s (%s)\n", site.Name, strings.Join(site.Domains, ", "))
	}
	target := site.DocumentRoot
	directive := "root * " + target + "\n\tfile_server"
	if site.Kind == "proxy" {
		directive = "reverse_proxy " + site.Upstream
	}
	return fmt.Sprintf("%s {\n\t%s\n}\n", strings.Join(site.Domains, ", "), directive)
}
