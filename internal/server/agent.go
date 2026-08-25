package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	wardenAgentProvider = "openrouter"
	wardenAgentModel    = "openrouter/deepseek/deepseek-v4-flash"
)

type agentRunRequest struct {
	Workspace string `json:"workspace"`
	Prompt    string `json:"prompt"`
	Session   string `json:"session,omitempty"`
}

func (a *app) agentStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	sess, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	_, source, credential := a.resolveAICredential(sess.AccountID, wardenAgentProvider)
	_, err := exec.LookPath("opencode")
	jsonOut(w, map[string]any{
		"available":           err == nil && credential,
		"opencodeInstalled":   err == nil,
		"credentialAvailable": credential,
		"credentialSource":    source,
		"provider":            wardenAgentProvider,
		"model":               wardenAgentModel,
	})
}

func (a *app) agentRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	sess, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var q agentRunRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&q); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	q.Prompt = strings.TrimSpace(q.Prompt)
	if q.Prompt == "" {
		http.Error(w, "prompt is required", http.StatusBadRequest)
		return
	}
	if len(q.Prompt) > 100000 {
		http.Error(w, "prompt is too large", http.StatusBadRequest)
		return
	}
	workspace, err := a.files.resolve(q.Workspace, false)
	if err != nil {
		http.Error(w, "invalid workspace: "+err.Error(), http.StatusBadRequest)
		return
	}
	info, err := os.Stat(workspace)
	if err != nil || !info.IsDir() {
		http.Error(w, "workspace must be a directory", http.StatusBadRequest)
		return
	}
	key, source, ok := a.resolveAICredential(sess.AccountID, wardenAgentProvider)
	if !ok {
		http.Error(w, "OpenRouter credential is not configured", http.StatusBadRequest)
		return
	}
	binary, err := exec.LookPath("opencode")
	if err != nil {
		http.Error(w, "OpenCode is not installed or not in Warden's PATH", http.StatusServiceUnavailable)
		return
	}

	// Keep OpenCode's own global auth/config/session state out of shared Warden users.
	runDir, err := os.MkdirTemp("", "warden-opencode-"+sess.AccountID+"-")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(runDir)
	configDir := filepath.Join(runDir, "config")
	dataDir := filepath.Join(runDir, "data")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	cfg := []byte(`{"autoupdate":false}`)
	if err := os.WriteFile(filepath.Join(configDir, "opencode.json"), cfg, 0600); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	args := []string{"run", "--format", "json", "--auto", "--dir", workspace, "--model", wardenAgentModel}
	if strings.TrimSpace(q.Session) != "" {
		args = append(args, "--session", strings.TrimSpace(q.Session))
	}
	args = append(args, q.Prompt)
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = workspace
	env := append([]string{}, os.Environ()...)
	env = append(env,
		"OPENROUTER_API_KEY="+key,
		"OPENCODE_CONFIG="+filepath.Join(configDir, "opencode.json"),
		"OPENCODE_CONFIG_DIR="+configDir,
		"XDG_CONFIG_HOME="+configDir,
		"XDG_DATA_HOME="+dataDir,
		"OPENCODE_DISABLE_AUTOUPDATE=1",
	)
	// Apply Warden's persistent instance/account environment after the inherited OS environment.
	for name, value := range a.config.environmentFor(sess.AccountID) {
		env = setEnvPair(env, name, value)
	}
	cmd.Env = env
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unavailable", 500)
		return
	}
	a.auditEvent(r, "agent_run_start", "provider="+wardenAgentProvider+" credential="+source+" workspace="+q.Workspace)
	if err := cmd.Start(); err != nil {
		writeAgentEvent(w, flusher, "error", map[string]any{"message": err.Error()})
		return
	}

	var inputTokens, outputTokens uint64
	var cost float64
	scan := bufio.NewScanner(stdout)
	scan.Buffer(make([]byte, 64<<10), 4<<20)
	for scan.Scan() {
		line := append([]byte(nil), scan.Bytes()...)
		var raw map[string]any
		if json.Unmarshal(line, &raw) == nil {
			collectAgentUsage(raw, &inputTokens, &outputTokens, &cost)
			writeAgentEvent(w, flusher, "opencode", raw)
		} else {
			writeAgentEvent(w, flusher, "output", map[string]any{"text": string(line)})
		}
	}
	errText, _ := new(strings.Builder), error(nil)
	b, _ := ioReadAllLimit(stderr, 256<<10)
	if len(b) > 0 {
		errText.Write(b)
	}
	waitErr := cmd.Wait()
	if scan.Err() != nil && waitErr == nil {
		waitErr = scan.Err()
	}
	_ = a.aiUsage.record(sess.AccountID, wardenAgentProvider, inputTokens, outputTokens, cost)
	if waitErr != nil {
		msg := strings.TrimSpace(errText.String())
		if msg == "" {
			msg = waitErr.Error()
		}
		writeAgentEvent(w, flusher, "error", map[string]any{"message": msg})
		a.auditEvent(r, "agent_run_finish", "status=error workspace="+q.Workspace)
		return
	}
	writeAgentEvent(w, flusher, "done", map[string]any{"inputTokens": inputTokens, "outputTokens": outputTokens, "estimatedCostUsd": cost})
	a.auditEvent(r, "agent_run_finish", "status=ok workspace="+q.Workspace)
}

func writeAgentEvent(w http.ResponseWriter, f http.Flusher, kind string, data any) {
	_ = json.NewEncoder(w).Encode(map[string]any{"type": kind, "data": data})
	f.Flush()
}

func setEnvPair(env []string, key, value string) []string {
	prefix := key + "="
	for i := range env {
		if strings.HasPrefix(env[i], prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func ioReadAllLimit(r interface{ Read([]byte) (int, error) }, max int64) ([]byte, error) {
	var out strings.Builder
	buf := make([]byte, 4096)
	for int64(out.Len()) < max {
		n, e := r.Read(buf)
		if n > 0 {
			remain := int(max - int64(out.Len()))
			if n > remain {
				n = remain
			}
			out.Write(buf[:n])
		}
		if e != nil {
			return []byte(out.String()), nil
		}
	}
	return []byte(out.String()), errors.New("limit reached")
}

func collectAgentUsage(v any, input, output *uint64, cost *float64) {
	if xs, ok := v.([]any); ok {
		for _, x := range xs {
			collectAgentUsage(x, input, output, cost)
		}
		return
	}
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	for k, val := range m {
		lk := strings.ToLower(k)
		switch lk {
		case "inputtokens", "input_tokens", "prompttokens", "prompt_tokens":
			if n, ok := numberUint(val); ok && n > *input {
				*input = n
			}
		case "outputtokens", "output_tokens", "completiontokens", "completion_tokens":
			if n, ok := numberUint(val); ok && n > *output {
				*output = n
			}
		case "cost", "costusd", "cost_usd", "estimatedcostusd", "estimated_cost_usd":
			if n, ok := numberFloat(val); ok && n > *cost {
				*cost = n
			}
		}
		collectAgentUsage(val, input, output, cost)
	}
}
func numberUint(v any) (uint64, bool) {
	switch n := v.(type) {
	case float64:
		if n >= 0 {
			return uint64(n), true
		}
	case json.Number:
		x, e := strconv.ParseUint(string(n), 10, 64)
		return x, e == nil
	}
	return 0, false
}
func numberFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		x, e := strconv.ParseFloat(string(n), 64)
		return x, e == nil
	}
	return 0, false
}
