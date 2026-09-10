package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const launcherConfigVersion = 1

var launcherIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type launcherInstance struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Port   *int   `json:"port,omitempty"`
}

type launcherInstanceView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Port   *int   `json:"port,omitempty"`
	AppURL string `json:"appUrl"`
}

type launcherConfigDocument struct {
	Version   int                `json:"version"`
	Product   string             `json:"product,omitempty"`
	Instances []launcherInstance `json:"instances"`
}

type launcherConfigView struct {
	Version   int                    `json:"version"`
	Product   string                 `json:"product"`
	Instances []launcherInstanceView `json:"instances"`
}

func (a *app) launcherRoot(static http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Query().Has("config") {
			sess, ok := a.auth.get(r)
			if !ok {
				http.Redirect(w, r, "/app/?return=%2F%3Fconfig", http.StatusFound)
				return
			}
			if !a.accounts.hasCapability(sess.AccountID, "settings.manage") {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			a.serveLauncher(static, w, r)
			return
		}
		instances, err := a.loadLauncherInstances(r.Context())
		if err != nil {
			http.Error(w, "launcher unavailable", http.StatusInternalServerError)
			return
		}
		switch len(instances) {
		case 0:
			http.Redirect(w, r, "/app/", http.StatusFound)
		case 1:
			target, err := launcherAppURL(instances[0])
			if err != nil {
				http.Error(w, "invalid launcher configuration", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, target, http.StatusFound)
		default:
			a.serveLauncher(static, w, r)
		}
	}
}

func (a *app) serveLauncher(static http.Handler, w http.ResponseWriter, r *http.Request) {
	clone := r.Clone(r.Context())
	clone.URL.Path = "/launcher.html"
	clone.URL.RawPath = ""
	w.Header().Set("Cache-Control", "no-store")
	static.ServeHTTP(w, clone)
}

func (a *app) launcherInstances(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	instances, err := a.loadLauncherInstances(r.Context())
	if err != nil {
		http.Error(w, "launcher unavailable", http.StatusInternalServerError)
		return
	}
	view, err := launcherView(instances)
	if err != nil {
		http.Error(w, "invalid launcher configuration", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonOut(w, view)
}

func (a *app) launcherConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var document launcherConfigDocument
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	instances, err := normalizeLauncherDocument(document)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.replaceLauncherInstances(r.Context(), instances); err != nil {
		http.Error(w, "unable to save launcher configuration", http.StatusInternalServerError)
		return
	}
	a.auditEvent(r, "launcher_configuration_replace", fmt.Sprintf("instances=%d", len(instances)))
	view, _ := launcherView(instances)
	jsonOut(w, view)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("trailing json")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func normalizeLauncherDocument(document launcherConfigDocument) ([]launcherInstance, error) {
	if document.Version != launcherConfigVersion {
		return nil, errors.New("unsupported launcher configuration version")
	}
	if document.Product != "" && document.Product != "warden" {
		return nil, errors.New("launcher configuration is for another product")
	}
	if document.Instances == nil {
		return nil, errors.New("instances must be an array")
	}
	if len(document.Instances) > 1000 {
		return nil, errors.New("too many launcher instances")
	}
	seen := make(map[string]bool, len(document.Instances))
	instances := make([]launcherInstance, 0, len(document.Instances))
	for _, item := range document.Instances {
		name := strings.TrimSpace(item.Name)
		if name == "" || len(name) > 100 {
			return nil, errors.New("every instance requires a name of at most 100 characters")
		}
		domain, err := normalizeLauncherDomain(item.Domain)
		if err != nil {
			return nil, err
		}
		if item.Port != nil && (*item.Port < 1 || *item.Port > 65535) {
			return nil, errors.New("instance ports must be from 1 to 65535")
		}
		id := strings.TrimSpace(item.ID)
		if !launcherIDPattern.MatchString(id) || seen[id] {
			id = token(18)
			for seen[id] {
				id = token(18)
			}
		}
		seen[id] = true
		instances = append(instances, launcherInstance{ID: id, Name: name, Domain: domain, Port: item.Port})
	}
	return instances, nil
}

func normalizeLauncherDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 512 || strings.IndexFunc(raw, func(r rune) bool { return r <= ' ' }) >= 0 {
		return "", errors.New("every instance requires a valid domain or IP")
	}
	explicit := strings.Contains(raw, "://")
	probe := raw
	if !explicit {
		probe = "https://" + raw
	}
	u, err := url.Parse(probe)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("every instance requires a valid HTTP(S) domain or IP without a path")
	}
	return strings.TrimSuffix(raw, "/"), nil
}

func launcherAppURL(instance launcherInstance) (string, error) {
	raw := instance.Domain
	explicit := strings.Contains(raw, "://")
	if !explicit {
		probe, err := url.Parse("https://" + raw)
		if err != nil {
			return "", err
		}
		host := probe.Hostname()
		scheme := "https"
		if host == "localhost" || strings.HasSuffix(host, ".localhost") || net.ParseIP(host) != nil {
			scheme = "http"
		}
		raw = scheme + "://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if instance.Port != nil {
		u.Host = net.JoinHostPort(u.Hostname(), fmt.Sprint(*instance.Port))
	}
	u.Path = "/app/"
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	return u.String(), nil
}

func launcherView(instances []launcherInstance) (launcherConfigView, error) {
	view := launcherConfigView{Version: launcherConfigVersion, Product: "warden", Instances: make([]launcherInstanceView, 0, len(instances))}
	for _, instance := range instances {
		appURL, err := launcherAppURL(instance)
		if err != nil {
			return launcherConfigView{}, err
		}
		view.Instances = append(view.Instances, launcherInstanceView{
			ID: instance.ID, Name: instance.Name, Domain: instance.Domain, Port: instance.Port, AppURL: appURL,
		})
	}
	return view, nil
}

func (a *app) loadLauncherInstances(ctx context.Context) ([]launcherInstance, error) {
	rows, err := a.db.QueryContext(ctx, "SELECT id,name,domain,port FROM launcher_instances ORDER BY sort_order,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var instances []launcherInstance
	for rows.Next() {
		var item launcherInstance
		var port sql.NullInt64
		if err := rows.Scan(&item.ID, &item.Name, &item.Domain, &port); err != nil {
			return nil, err
		}
		if port.Valid {
			value := int(port.Int64)
			item.Port = &value
		}
		instances = append(instances, item)
	}
	return instances, rows.Err()
}

func (a *app) replaceLauncherInstances(ctx context.Context, instances []launcherInstance) error {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM launcher_instances"); err != nil {
		return err
	}
	now := time.Now().UnixMilli()
	for index, item := range instances {
		var port any
		if item.Port != nil {
			port = *item.Port
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO launcher_instances(id,name,domain,port,sort_order,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", item.ID, item.Name, item.Domain, port, index, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}
