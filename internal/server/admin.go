package server

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type adminEnvelope struct {
	Kind      string `json:"kind"`
	Available bool   `json:"available"`
	Message   string `json:"message,omitempty"`
	Data      any    `json:"data,omitempty"`
}

func (a *app) admin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	kind := strings.TrimPrefix(r.URL.Path, "/api/admin/")
	var env adminEnvelope
	switch kind {
	case "certs":
		env = collectCertificates()
	case "cron":
		env = collectCron()
	case "docker":
		env = collectDocker()
	case "fail2ban":
		env = collectFail2ban()
	case "firewall":
		env = collectFirewall()
	case "services":
		env = collectServices()
	case "ssh":
		env = collectSSH()
	case "users":
		env = collectUsers()
	default:
		http.NotFound(w, r)
		return
	}
	jsonOut(w, env)
}

func collectCertificates() adminEnvelope {
	type certRow struct {
		Name      string   `json:"name"`
		Path      string   `json:"path"`
		Issuer    string   `json:"issuer"`
		Subject   string   `json:"subject"`
		DNSNames  []string `json:"dnsNames"`
		NotBefore int64    `json:"notBefore"`
		NotAfter  int64    `json:"notAfter"`
		DaysLeft  int      `json:"daysLeft"`
	}
	paths := []string{}
	_ = filepath.WalkDir("/etc/letsencrypt/live", func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Base(path) == "fullchain.pem" {
			paths = append(paths, path)
		}
		return nil
	})
	if len(paths) == 0 {
		matches, _ := filepath.Glob("/etc/ssl/certs/*.pem")
		if len(matches) > 80 {
			matches = matches[:80]
		}
		paths = append(paths, matches...)
	}
	rows := []certRow{}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		name := filepath.Base(filepath.Dir(path))
		if name == "certs" {
			name = filepath.Base(path)
		}
		rows = append(rows, certRow{Name: name, Path: path, Issuer: c.Issuer.CommonName, Subject: c.Subject.CommonName, DNSNames: c.DNSNames, NotBefore: c.NotBefore.Unix(), NotAfter: c.NotAfter.Unix(), DaysLeft: int(time.Until(c.NotAfter).Hours() / 24)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].NotAfter < rows[j].NotAfter })
	return adminEnvelope{Kind: "certs", Available: len(rows) > 0, Message: emptyMessage(rows, "No readable TLS certificates found in standard locations."), Data: map[string]any{"certificates": rows}}
}

func collectCron() adminEnvelope {
	type cronRow struct {
		Schedule string `json:"schedule"`
		User     string `json:"user"`
		Command  string `json:"command"`
		Source   string `json:"source"`
	}
	rows := []cronRow{}
	parse := func(path string, hasUser bool) {
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "" || strings.HasPrefix(line, "#") || (strings.Contains(line, "=") && !strings.HasPrefix(line, "@")) {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			if strings.HasPrefix(fields[0], "@") {
				i := 1
				user := ""
				if hasUser && len(fields) > 2 {
					user = fields[1]
					i = 2
				}
				rows = append(rows, cronRow{Schedule: fields[0], User: user, Command: strings.Join(fields[i:], " "), Source: path})
				continue
			}
			need := 6
			if hasUser {
				need = 7
			}
			if len(fields) < need {
				continue
			}
			user, cmdStart := "", 5
			if hasUser {
				user, cmdStart = fields[5], 6
			}
			rows = append(rows, cronRow{Schedule: strings.Join(fields[:5], " "), User: user, Command: strings.Join(fields[cmdStart:], " "), Source: path})
		}
	}
	parse("/etc/crontab", true)
	if matches, _ := filepath.Glob("/etc/cron.d/*"); len(matches) > 0 {
		for _, p := range matches {
			parse(p, true)
		}
	}
	if out, err := fixedCommand(2*time.Second, "crontab", "-l"); err == nil {
		tmp, err := os.CreateTemp("", "warden-cron-*")
		if err == nil {
			_, _ = tmp.Write(out)
			_ = tmp.Close()
			parse(tmp.Name(), false)
			_ = os.Remove(tmp.Name())
			for i := range rows {
				if strings.HasPrefix(rows[i].Source, os.TempDir()) {
					rows[i].Source = "user crontab"
				}
			}
		}
	}
	return adminEnvelope{Kind: "cron", Available: true, Message: emptyMessage(rows, "No cron entries found."), Data: map[string]any{"entries": rows}}
}

func collectDocker() adminEnvelope {
	type container struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Image  string `json:"image"`
		State  string `json:"state"`
		Status string `json:"status"`
	}
	conn, err := net.DialTimeout("unix", "/var/run/docker.sock", 800*time.Millisecond)
	if err != nil {
		return adminEnvelope{Kind: "docker", Available: false, Message: "Docker daemon socket is unavailable."}
	}
	_ = conn.Close()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/docker.sock")
	}}}
	get := func(path string, dst any) error {
		resp, err := client.Get("http://docker" + path)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return errors.New(resp.Status)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(dst)
	}
	var ver struct{ Version, APIVersion, Os, Arch string }
	if err := get("/version", &ver); err != nil {
		return adminEnvelope{Kind: "docker", Available: false, Message: "Docker is installed but the daemon did not answer."}
	}
	var raw []struct {
		ID, Image, State, Status string
		Names                    []string
	}
	_ = get("/containers/json?all=1", &raw)
	rows := make([]container, 0, len(raw))
	for _, c := range raw {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		id := c.ID
		if len(id) > 12 {
			id = id[:12]
		}
		rows = append(rows, container{ID: id, Name: name, Image: c.Image, State: c.State, Status: c.Status})
	}
	return adminEnvelope{Kind: "docker", Available: true, Data: map[string]any{"version": ver.Version, "apiVersion": ver.APIVersion, "os": ver.Os, "arch": ver.Arch, "containers": rows}}
}

func collectFail2ban() adminEnvelope {
	type jail struct {
		Name            string `json:"name"`
		CurrentlyFailed int    `json:"currentlyFailed"`
		TotalFailed     int    `json:"totalFailed"`
		CurrentlyBanned int    `json:"currentlyBanned"`
		TotalBanned     int    `json:"totalBanned"`
	}
	out, err := fixedCommand(2*time.Second, "fail2ban-client", "status")
	if err != nil {
		return adminEnvelope{Kind: "fail2ban", Available: false, Message: "fail2ban is not available or its control socket cannot be read."}
	}
	jailNames := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, "Jail list:"); i >= 0 {
			for _, n := range strings.Split(strings.TrimSpace(line[i+len("Jail list:"):]), ",") {
				if n = strings.TrimSpace(n); n != "" {
					jailNames = append(jailNames, n)
				}
			}
		}
	}
	rows := []jail{}
	for _, name := range jailNames {
		o, e := fixedCommand(2*time.Second, "fail2ban-client", "status", name)
		if e != nil {
			continue
		}
		r := jail{Name: name}
		for _, line := range strings.Split(string(o), "\n") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "|-"))
			v = strings.TrimSpace(strings.TrimPrefix(v, "`-"))
			parts := strings.SplitN(v, ":", 2)
			if len(parts) != 2 {
				continue
			}
			n, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
			switch strings.TrimSpace(parts[0]) {
			case "Currently failed":
				r.CurrentlyFailed = n
			case "Total failed":
				r.TotalFailed = n
			case "Currently banned":
				r.CurrentlyBanned = n
			case "Total banned":
				r.TotalBanned = n
			}
		}
		rows = append(rows, r)
	}
	return adminEnvelope{Kind: "fail2ban", Available: true, Message: emptyMessage(rows, "No fail2ban jails configured."), Data: map[string]any{"jails": rows}}
}

func collectFirewall() adminEnvelope {
	type rule struct {
		To     string `json:"to"`
		Action string `json:"action"`
		From   string `json:"from"`
	}
	out, err := fixedCommand(2*time.Second, "ufw", "status", "numbered")
	if err != nil {
		return adminEnvelope{Kind: "firewall", Available: false, Message: "UFW is not available or cannot be queried."}
	}
	status := "unknown"
	rows := []rule{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Status:") {
			status = strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
			continue
		}
		if !strings.HasPrefix(line, "[") {
			continue
		}
		if i := strings.Index(line, "]"); i >= 0 {
			body := strings.TrimSpace(line[i+1:])
			fields := strings.Fields(body)
			actionIdx := -1
			for j, f := range fields {
				if f == "ALLOW" || f == "DENY" || f == "REJECT" || f == "LIMIT" {
					actionIdx = j
					break
				}
			}
			if actionIdx > 0 {
				rows = append(rows, rule{To: strings.Join(fields[:actionIdx], " "), Action: fields[actionIdx], From: strings.Join(fields[actionIdx+1:], " ")})
			}
		}
	}
	return adminEnvelope{Kind: "firewall", Available: true, Data: map[string]any{"status": status, "rules": rows}}
}

func collectServices() adminEnvelope {
	type service struct {
		Name        string `json:"name"`
		Load        string `json:"load"`
		Active      string `json:"active"`
		Sub         string `json:"sub"`
		Description string `json:"description"`
	}
	out, err := fixedCommand(3*time.Second, "systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain")
	if err != nil {
		return adminEnvelope{Kind: "services", Available: false, Message: "systemd services are not available."}
	}
	rows := []service{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		rows = append(rows, service{Name: fields[0], Load: fields[1], Active: fields[2], Sub: fields[3], Description: strings.Join(fields[4:], " ")})
	}
	if len(rows) > 300 {
		rows = rows[:300]
	}
	return adminEnvelope{Kind: "services", Available: true, Data: map[string]any{"services": rows}}
}

func collectSSH() adminEnvelope {
	settings := map[string]string{}
	f, err := os.Open("/etc/ssh/sshd_config")
	if err != nil {
		return adminEnvelope{Kind: "ssh", Available: false, Message: "OpenSSH server configuration is not readable."}
	}
	defer f.Close()
	wanted := map[string]bool{"port": true, "permitrootlogin": true, "passwordauthentication": true, "pubkeyauthentication": true, "maxauthtries": true, "allowusers": true, "allowgroups": true, "x11forwarding": true}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		k := strings.ToLower(fields[0])
		if wanted[k] {
			if _, ok := settings[k]; !ok {
				settings[k] = strings.Join(fields[1:], " ")
			}
		}
	}
	active := false
	if out, e := fixedCommand(2*time.Second, "systemctl", "is-active", "ssh"); e == nil && strings.TrimSpace(string(out)) == "active" {
		active = true
	} else if out, e := fixedCommand(2*time.Second, "systemctl", "is-active", "sshd"); e == nil && strings.TrimSpace(string(out)) == "active" {
		active = true
	}
	return adminEnvelope{Kind: "ssh", Available: true, Data: map[string]any{"active": active, "settings": settings}}
}

func collectUsers() adminEnvelope {
	type userRow struct {
		Name  string `json:"name"`
		UID   int    `json:"uid"`
		GID   int    `json:"gid"`
		Home  string `json:"home"`
		Shell string `json:"shell"`
		Login bool   `json:"login"`
	}
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return adminEnvelope{Kind: "users", Available: false, Message: "/etc/passwd is not readable."}
	}
	rows := []userRow{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		gid, _ := strconv.Atoi(f[3])
		sh := f[6]
		login := sh != "/usr/sbin/nologin" && sh != "/bin/false" && sh != "/usr/bin/nologin"
		rows = append(rows, userRow{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: sh, Login: login})
	}
	return adminEnvelope{Kind: "users", Available: true, Data: map[string]any{"users": rows}}
}

func fixedCommand(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return out, err
}
func emptyMessage[T any](v []T, msg string) string {
	if len(v) == 0 {
		return msg
	}
	return ""
}
