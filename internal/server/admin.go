package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	rel := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/admin/"), "/")
	parts := strings.Split(rel, "/")
	kind := parts[0]
	if len(parts) == 2 && parts[1] == "action" {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if kind == "warden" {
			a.wardenConfigAction(w, r)
			return
		}
		a.adminAction(w, r, kind)
		return
	}
	if len(parts) != 1 || r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
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
		env = collectServices(r.URL.Query().Get("scope"))
	case "ssh":
		env = collectSSH()
	case "users":
		env = collectUsers(r.URL.Query().Get("scope"))
	case "warden":
		env = a.collectWardenConfiguration()
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
		Managed   bool     `json:"managed"`
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
		rows = append(rows, certRow{Name: name, Path: path, Issuer: c.Issuer.CommonName, Subject: c.Subject.CommonName, DNSNames: c.DNSNames, NotBefore: c.NotBefore.Unix(), NotAfter: c.NotAfter.Unix(), DaysLeft: int(time.Until(c.NotAfter).Hours() / 24), Managed: strings.Contains(path, "/etc/letsencrypt/live/")})
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
		Editable bool   `json:"editable"`
		Line     string `json:"line,omitempty"`
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
				rows = append(rows, cronRow{Schedule: fields[0], User: user, Command: strings.Join(fields[i:], " "), Source: path, Editable: !hasUser, Line: line})
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
			rows = append(rows, cronRow{Schedule: strings.Join(fields[:5], " "), User: user, Command: strings.Join(fields[cmdStart:], " "), Source: path, Editable: !hasUser, Line: line})
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
		Number int    `json:"number"`
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
			numText := strings.TrimSpace(strings.TrimPrefix(line[:i], "["))
			num, _ := strconv.Atoi(numText)
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
				rows = append(rows, rule{Number: num, To: strings.Join(fields[:actionIdx], " "), Action: fields[actionIdx], From: strings.Join(fields[actionIdx+1:], " ")})
			}
		}
	}
	return adminEnvelope{Kind: "firewall", Available: true, Data: map[string]any{"status": status, "rules": rows}}
}

func collectServices(scope string) adminEnvelope {
	type service struct {
		Name        string `json:"name"`
		Load        string `json:"load"`
		Active      string `json:"active"`
		Sub         string `json:"sub"`
		Description string `json:"description"`
		Scope       string `json:"scope"`
	}
	if scope != "user" {
		scope = "system"
	}
	args := []string{"list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain"}
	if scope == "user" {
		args = append([]string{"--user"}, args...)
	}
	out, err := fixedCommand(3*time.Second, "systemctl", args...)
	if err != nil {
		msg := "systemd services are not available."
		if scope == "user" {
			msg = "The current user's systemd service manager is not available."
		}
		return adminEnvelope{Kind: "services", Available: false, Message: msg, Data: map[string]any{"scope": scope}}
	}
	rows := []service{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		rows = append(rows, service{Name: fields[0], Load: fields[1], Active: fields[2], Sub: fields[3], Description: strings.Join(fields[4:], " "), Scope: scope})
	}
	if len(rows) > 300 {
		rows = rows[:300]
	}
	return adminEnvelope{Kind: "services", Available: true, Data: map[string]any{"services": rows, "scope": scope}}
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

func loginUIDMin() int {
	f, err := os.Open("/etc/login.defs")
	if err != nil {
		return 1000
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) >= 2 && fields[0] == "UID_MIN" {
			if n, err := strconv.Atoi(fields[1]); err == nil && n > 0 {
				return n
			}
		}
	}
	return 1000
}

func collectUsers(scope string) adminEnvelope {
	type userRow struct {
		Name   string `json:"name"`
		UID    int    `json:"uid"`
		GID    int    `json:"gid"`
		Home   string `json:"home"`
		Shell  string `json:"shell"`
		Login  bool   `json:"login"`
		System bool   `json:"system"`
	}
	if scope != "system" {
		scope = "regular"
	}
	uidMin := loginUIDMin()
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
		system := uid < uidMin
		if scope == "regular" && system {
			continue
		}
		if scope == "system" && !system {
			continue
		}
		rows = append(rows, userRow{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: sh, Login: login, System: system})
	}
	return adminEnvelope{Kind: "users", Available: true, Data: map[string]any{"users": rows, "scope": scope, "uidMin": uidMin}}
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

type adminActionRequest struct {
	Action     string `json:"action"`
	Name       string `json:"name,omitempty"`
	Target     string `json:"target,omitempty"`
	Value      string `json:"value,omitempty"`
	Schedule   string `json:"schedule,omitempty"`
	Command    string `json:"command,omitempty"`
	Password   string `json:"password,omitempty"`
	Scope      string `json:"scope,omitempty"`
	RemoveHome bool   `json:"removeHome,omitempty"`
}

type adminActionResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

var safeNameRE = regexp.MustCompile(`^[A-Za-z0-9_.@:-]+$`)
var safeUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func (a *app) adminAction(w http.ResponseWriter, r *http.Request, kind string) {
	var q adminActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&q); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	q.Action = strings.ToLower(strings.TrimSpace(q.Action))
	var err error
	var msg string
	switch kind {
	case "certs":
		msg, err = actionCertificate(q)
	case "cron":
		msg, err = actionCron(q)
	case "docker":
		msg, err = actionDocker(q)
	case "fail2ban":
		msg, err = actionFail2ban(q)
	case "firewall":
		msg, err = actionFirewall(q)
	case "services":
		msg, err = actionService(q)
	case "ssh":
		msg, err = actionSSH(q)
	case "users":
		msg, err = actionUser(q)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		a.audit.Printf("admin_action_failed ip=%s kind=%q action=%q name=%q err=%q", clientIP(r), kind, q.Action, q.Name, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.audit.Printf("admin_action ip=%s kind=%q action=%q name=%q target=%q", clientIP(r), kind, q.Action, q.Name, q.Target)
	jsonOut(w, adminActionResult{OK: true, Message: msg})
}

func actionCertificate(q adminActionRequest) (string, error) {
	if q.Action != "renew" || !safeNameRE.MatchString(q.Name) {
		return "", errors.New("invalid certificate action")
	}
	if _, err := exec.LookPath("certbot"); err != nil {
		return "", errors.New("certbot is not installed")
	}
	out, err := fixedCommand(90*time.Second, "certbot", "renew", "--cert-name", q.Name, "--non-interactive")
	if err != nil {
		return "", commandError("certbot renewal failed", out, err)
	}
	return "Certificate renewal completed.", nil
}

func actionCron(q adminActionRequest) (string, error) {
	out, _ := fixedCommand(2*time.Second, "crontab", "-l")
	text := string(out)
	switch q.Action {
	case "add":
		schedule := strings.TrimSpace(q.Schedule)
		command := strings.TrimSpace(q.Command)
		if !validCronSchedule(schedule) || command == "" || strings.ContainsAny(command, "\r\n") {
			return "", errors.New("invalid cron schedule or command")
		}
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += schedule + " " + command + "\n"
	case "delete":
		needle := strings.TrimSpace(q.Value)
		if needle == "" || strings.ContainsAny(needle, "\r\n") {
			return "", errors.New("invalid cron entry")
		}
		lines := strings.Split(text, "\n")
		removed := false
		kept := lines[:0]
		for _, line := range lines {
			if !removed && strings.TrimSpace(line) == needle {
				removed = true
				continue
			}
			kept = append(kept, line)
		}
		if !removed {
			return "", errors.New("cron entry not found in current user crontab")
		}
		text = strings.Join(kept, "\n")
	default:
		return "", errors.New("unsupported cron action")
	}
	if _, err := fixedCommandInput(3*time.Second, []byte(text), "crontab", "-"); err != nil {
		return "", err
	}
	return "User crontab updated.", nil
}

func validCronSchedule(s string) bool {
	if strings.HasPrefix(s, "@") {
		return safeNameRE.MatchString(strings.TrimPrefix(s, "@"))
	}
	return len(strings.Fields(s)) == 5 && !strings.ContainsAny(s, "\r\n")
}

func dockerHTTP(method, path string) ([]byte, error) {
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/docker.sock")
	}}}
	req, err := http.NewRequest(method, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return b, fmt.Errorf("docker: %s", resp.Status)
	}
	return b, nil
}

func actionDocker(q adminActionRequest) (string, error) {
	if q.Name == "" || strings.ContainsAny(q.Name, "/\\\r\n") {
		return "", errors.New("invalid container")
	}
	id := url.PathEscape(q.Name)
	var method, path string
	switch q.Action {
	case "start":
		method, path = http.MethodPost, "/containers/"+id+"/start"
	case "stop":
		method, path = http.MethodPost, "/containers/"+id+"/stop?t=10"
	case "restart":
		method, path = http.MethodPost, "/containers/"+id+"/restart?t=10"
	case "remove":
		method, path = http.MethodDelete, "/containers/"+id+"?v=1"
	default:
		return "", errors.New("unsupported docker action")
	}
	if b, err := dockerHTTP(method, path); err != nil {
		return "", commandError("docker action failed", b, err)
	}
	return "Docker container action completed.", nil
}

func actionFail2ban(q adminActionRequest) (string, error) {
	if !safeNameRE.MatchString(q.Name) {
		return "", errors.New("invalid jail")
	}
	ip := net.ParseIP(strings.TrimSpace(q.Target))
	if ip == nil {
		return "", errors.New("invalid IP address")
	}
	cmd := ""
	switch q.Action {
	case "ban":
		cmd = "banip"
	case "unban":
		cmd = "unbanip"
	default:
		return "", errors.New("unsupported fail2ban action")
	}
	out, err := fixedCommand(4*time.Second, "fail2ban-client", "set", q.Name, cmd, ip.String())
	if err != nil {
		return "", commandError("fail2ban action failed", out, err)
	}
	return "Fail2ban jail updated.", nil
}

func actionFirewall(q adminActionRequest) (string, error) {
	var args []string
	switch q.Action {
	case "enable":
		args = []string{"--force", "enable"}
	case "disable":
		args = []string{"disable"}
	case "delete":
		n, err := strconv.Atoi(q.Value)
		if err != nil || n < 1 {
			return "", errors.New("invalid firewall rule number")
		}
		args = []string{"--force", "delete", strconv.Itoa(n)}
	case "allow", "deny", "reject", "limit":
		target := strings.TrimSpace(q.Target)
		if target == "" || len(target) > 128 || strings.ContainsAny(target, "\r\n") {
			return "", errors.New("invalid firewall target")
		}
		args = []string{q.Action, target}
	default:
		return "", errors.New("unsupported firewall action")
	}
	out, err := fixedCommand(8*time.Second, "ufw", args...)
	if err != nil {
		return "", commandError("firewall action failed", out, err)
	}
	return "Firewall updated.", nil
}

func actionService(q adminActionRequest) (string, error) {
	if !safeNameRE.MatchString(q.Name) || !strings.HasSuffix(q.Name, ".service") {
		return "", errors.New("invalid service unit")
	}
	switch q.Action {
	case "start", "stop", "restart", "enable", "disable":
	default:
		return "", errors.New("unsupported service action")
	}
	args := []string{q.Action, q.Name}
	if q.Scope == "user" {
		args = append([]string{"--user"}, args...)
	} else if q.Scope != "" && q.Scope != "system" {
		return "", errors.New("invalid service scope")
	}
	out, err := fixedCommand(12*time.Second, "systemctl", args...)
	if err != nil {
		return "", commandError("service action failed", out, err)
	}
	return "Service action completed.", nil
}

func actionSSH(q adminActionRequest) (string, error) {
	allowed := map[string]bool{"port": true, "permitrootlogin": true, "passwordauthentication": true, "pubkeyauthentication": true, "maxauthtries": true, "x11forwarding": true}
	key := strings.ToLower(strings.TrimSpace(q.Name))
	value := strings.TrimSpace(q.Value)
	if q.Action != "set" || !allowed[key] || value == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("invalid SSH setting")
	}
	path := "/etc/ssh/sshd_config.d/99-warden.conf"
	settings := map[string]string{}
	if b, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				settings[strings.ToLower(f[0])] = strings.Join(f[1:], " ")
			}
		}
	}
	settings[key] = value
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf strings.Builder
	buf.WriteString("# Managed by Warden\n")
	for _, k := range keys {
		buf.WriteString(k + " " + settings[k] + "\n")
	}
	var old []byte
	old, _ = os.ReadFile(path)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", err
	}
	if err := writeAtomicPath(path, []byte(buf.String()), 0644); err != nil {
		return "", err
	}
	if out, err := fixedCommand(5*time.Second, "sshd", "-t"); err != nil {
		if old != nil {
			_ = writeAtomicPath(path, old, 0644)
		} else {
			_ = os.Remove(path)
		}
		return "", commandError("SSH configuration validation failed", out, err)
	}
	if _, err := fixedCommand(5*time.Second, "systemctl", "reload", "ssh"); err != nil {
		if out, err2 := fixedCommand(5*time.Second, "systemctl", "reload", "sshd"); err2 != nil {
			return "", commandError("SSH configuration saved but daemon reload failed", out, err2)
		}
	}
	return "SSH setting updated and daemon reloaded.", nil
}

func actionUser(q adminActionRequest) (string, error) {
	name := strings.TrimSpace(q.Name)
	if !safeUserRE.MatchString(name) {
		return "", errors.New("invalid username")
	}
	var out []byte
	var err error
	switch q.Action {
	case "add":
		out, err = fixedCommand(10*time.Second, "useradd", "-m", "-s", "/bin/bash", name)
		if err == nil && q.Password != "" {
			if _, passErr := fixedCommandInput(5*time.Second, []byte(name+":"+q.Password+"\n"), "chpasswd"); passErr != nil {
				_, _ = fixedCommand(8*time.Second, "userdel", "-r", name)
				err = passErr
			}
		}
	case "delete":
		args := []string{}
		if q.RemoveHome {
			args = append(args, "-r")
		}
		args = append(args, name)
		out, err = fixedCommand(12*time.Second, "userdel", args...)
	case "lock":
		out, err = fixedCommand(5*time.Second, "usermod", "-L", name)
	case "unlock":
		out, err = fixedCommand(5*time.Second, "usermod", "-U", name)
	default:
		return "", errors.New("unsupported user action")
	}
	if err != nil {
		return "", commandError("user action failed", out, err)
	}
	return "User account updated.", nil
}

func fixedCommandInput(timeout time.Duration, input []byte, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if err != nil {
		return out, commandError(name+" failed", out, err)
	}
	return out, nil
}

func commandError(prefix string, out []byte, err error) error {
	msg := strings.TrimSpace(string(out))
	if len(msg) > 600 {
		msg = msg[:600] + "…"
	}
	if msg != "" {
		return fmt.Errorf("%s: %s", prefix, msg)
	}
	return fmt.Errorf("%s: %v", prefix, err)
}
