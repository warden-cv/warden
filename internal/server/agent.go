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

type agentProviderRuntime struct {
	OpenCodeID    string
	FallbackModel string
	NeedsKey      bool
}

var agentProviderRuntimes = map[string]agentProviderRuntime{
	"opencode":   {OpenCodeID: "opencode", FallbackModel: "deepseek-v4-flash", NeedsKey: true},
	"openrouter": {OpenCodeID: "openrouter", FallbackModel: "anthropic/claude-sonnet-4.5", NeedsKey: true},
	"openai":     {OpenCodeID: "openai", FallbackModel: "gpt-5.2", NeedsKey: true},
	"anthropic":  {OpenCodeID: "anthropic", FallbackModel: "claude-sonnet-4-20250514", NeedsKey: true},
	"gemini":     {OpenCodeID: "google", FallbackModel: "gemini-2.5-pro", NeedsKey: true},
	"deepseek":   {OpenCodeID: "deepseek", FallbackModel: "deepseek-chat", NeedsKey: true},
	"ollama":     {OpenCodeID: "ollama", NeedsKey: false},
}

type agentRunRequest struct {
	Workspace     string `json:"workspace"`
	Prompt        string `json:"prompt"`
	Session       string `json:"session,omitempty"`
	ClientSession string `json:"clientSession,omitempty"`
	Provider      string `json:"provider,omitempty"`
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
	providerID := strings.TrimSpace(r.URL.Query().Get("provider"))
	if providerID == "" {
		providerID = "opencode"
	}
	runtime, provider, err := a.agentProvider(providerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	source := "local"
	credential := !runtime.NeedsKey
	if runtime.NeedsKey {
		_, source, credential = a.resolveAICredential(sess.AccountID, providerID)
	}
	model := strings.TrimSpace(provider.DefaultModel)
	if model == "" {
		model = runtime.FallbackModel
	}
	_, lookupErr := exec.LookPath("opencode")
	cfg := a.config.aiSnapshot()
	providerViews := make([]map[string]any, 0, len(agentProviderRuntimes))
	for _, id := range sortedAIProviderIDs(cfg) {
		rt, supported := agentProviderRuntimes[id]
		if !supported {
			continue
		}
		p := cfg.Providers[id]
		modelName := strings.TrimSpace(p.DefaultModel)
		if modelName == "" {
			modelName = rt.FallbackModel
		}
		src := "local"
		hasCredential := !rt.NeedsKey
		if rt.NeedsKey {
			_, src, hasCredential = a.resolveAICredential(sess.AccountID, id)
		}
		providerViews = append(providerViews, map[string]any{
			"id": id, "label": p.Label, "model": modelName,
			"credentialAvailable": hasCredential, "credentialSource": src,
		})
	}
	jsonOut(w, map[string]any{
		"available":           lookupErr == nil && credential && model != "",
		"opencodeInstalled":   lookupErr == nil,
		"credentialAvailable": credential,
		"credentialSource":    source,
		"provider":            providerID,
		"providerLabel":       provider.Label,
		"model":               runtime.OpenCodeID + "/" + model,
		"providers":           providerViews,
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
	providerID := strings.TrimSpace(q.Provider)
	if providerID == "" {
		providerID = "opencode"
	}
	runtime, provider, err := a.agentProvider(providerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	model := strings.TrimSpace(provider.DefaultModel)
	if model == "" {
		model = runtime.FallbackModel
	}
	if model == "" {
		http.Error(w, provider.Label+" has no model configured", http.StatusBadRequest)
		return
	}
	key, source := "", "local"
	if runtime.NeedsKey {
		var configured bool
		key, source, configured = a.resolveAICredential(sess.AccountID, providerID)
		if !configured {
			http.Error(w, provider.Label+" credential is not configured", http.StatusBadRequest)
			return
		}
	}
	modelRef := runtime.OpenCodeID + "/" + model
	binary, err := exec.LookPath("opencode")
	if err != nil {
		http.Error(w, "OpenCode is not installed or not in Warden's PATH", http.StatusServiceUnavailable)
		return
	}

	clientSession := strings.TrimSpace(q.ClientSession)
	if clientSession == "" {
		clientSession = "default"
	}
	if !validAgentSessionID(clientSession) {
		http.Error(w, "invalid client session", http.StatusBadRequest)
		return
	}
	// Keep OpenCode config temporary, but persist each Warden account/session's
	// OpenCode data so follow-up prompts and restored sessions can continue.
	runDir, err := os.MkdirTemp("", "warden-opencode-config-"+sess.AccountID+"-")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(runDir)
	configDir := filepath.Join(runDir, "config")
	dataDir := filepath.Join(a.cfg.ConfigDir, "agent-sessions", sess.AccountID, clientSession, "data")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	cfg, err := a.agentOpenCodeConfig(providerID, runtime, provider, model)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := os.WriteFile(filepath.Join(configDir, "opencode.json"), cfg, 0600); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	args := []string{"--print-logs", "--log-level", "INFO", "run", "--format", "json", "--auto", "--dir", workspace, "--model", modelRef}
	if strings.TrimSpace(q.Session) != "" {
		args = append(args, "--session", strings.TrimSpace(q.Session))
	}
	args = append(args, q.Prompt)
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = workspace
	env := append([]string{}, os.Environ()...)
	env = append(env,
		"OPENCODE_CONFIG="+filepath.Join(configDir, "opencode.json"),
		"OPENCODE_CONFIG_DIR="+configDir,
		"XDG_CONFIG_HOME="+configDir,
		"XDG_DATA_HOME="+dataDir,
		"OPENCODE_DISABLE_AUTOUPDATE=1",
	)
	if runtime.NeedsKey {
		env = setEnvPair(env, "WARDEN_AGENT_API_KEY", key)
	}
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
	a.auditEvent(r, "agent_run_start", "provider="+providerID+" credential="+source+" workspace="+q.Workspace)
	if err := cmd.Start(); err != nil {
		writeAgentEvent(w, flusher, "error", map[string]any{"message": err.Error()})
		return
	}

	var inputTokens, outputTokens uint64
	var cost float64
	var sessionID string
	sawAssistantText := false
	errCh := make(chan string, 1)
	go func() {
		b, _ := ioReadAllLimit(stderr, 256<<10)
		errCh <- string(b)
	}()
	scan := bufio.NewScanner(stdout)
	scan.Buffer(make([]byte, 64<<10), 4<<20)
	for scan.Scan() {
		line := append([]byte(nil), scan.Bytes()...)
		var raw map[string]any
		if json.Unmarshal(line, &raw) == nil {
			collectAgentUsage(raw, &inputTokens, &outputTokens, &cost)
			if id, _ := raw["sessionID"].(string); id != "" {
				sessionID = id
			}
			if agentEventText(raw) != "" {
				sawAssistantText = true
			}
			writeAgentEvent(w, flusher, "opencode", raw)
		} else {
			writeAgentEvent(w, flusher, "output", map[string]any{"text": string(line)})
		}
	}
	waitErr := cmd.Wait()
	errText := <-errCh
	if scan.Err() != nil && waitErr == nil {
		waitErr = scan.Err()
	}
	if waitErr == nil && sessionID != "" {
		if recovered, usageIn, usageOut, recoveredCost, recoverErr := recoverOpenCodeSession(ctx, binary, sessionID, workspace, env); recoverErr == nil {
			if !sawAssistantText && strings.TrimSpace(recovered) != "" {
				writeAgentEvent(w, flusher, "recovered", map[string]any{"text": recovered, "sessionID": sessionID})
			}
			if usageIn > inputTokens {
				inputTokens = usageIn
			}
			if usageOut > outputTokens {
				outputTokens = usageOut
			}
			if recoveredCost > cost {
				cost = recoveredCost
			}
		} else if !sawAssistantText {
			writeAgentEvent(w, flusher, "diagnostic", map[string]any{"message": "OpenCode produced no assistant text on stdout and session recovery failed: " + sanitizeAgentDiagnostic(recoverErr.Error(), key)})
		}
	}
	_ = a.aiUsage.record(sess.AccountID, providerID, inputTokens, outputTokens, cost)
	if waitErr != nil {
		msg := sanitizeAgentDiagnostic(strings.TrimSpace(errText), key)
		if msg == "" {
			msg = waitErr.Error()
		}
		writeAgentEvent(w, flusher, "error", map[string]any{"message": msg})
		a.auditEvent(r, "agent_run_finish", "status=error workspace="+q.Workspace)
		return
	}
	writeAgentEvent(w, flusher, "done", map[string]any{"inputTokens": inputTokens, "outputTokens": outputTokens, "estimatedCostUsd": cost, "sessionID": sessionID})
	a.auditEvent(r, "agent_run_finish", "status=ok workspace="+q.Workspace)
}

func (a *app) agentProvider(id string) (agentProviderRuntime, aiProviderConfig, error) {
	runtime, ok := agentProviderRuntimes[id]
	if !ok {
		return agentProviderRuntime{}, aiProviderConfig{}, errors.New("provider is not supported by Warden Agent")
	}
	cfg := a.config.aiSnapshot()
	provider, ok := cfg.Providers[id]
	if !ok {
		return agentProviderRuntime{}, aiProviderConfig{}, errors.New("unknown AI provider")
	}
	return runtime, provider, nil
}

func (a *app) agentOpenCodeConfig(id string, runtime agentProviderRuntime, provider aiProviderConfig, model string) ([]byte, error) {
	modelRef := runtime.OpenCodeID + "/" + model
	cfg := map[string]any{
		"$schema":    "https://opencode.ai/config.json",
		"model":      modelRef,
		"permission": "allow",
	}
	options := map[string]any{}
	if runtime.NeedsKey {
		options["apiKey"] = "{env:WARDEN_AGENT_API_KEY}"
	}
	if strings.TrimSpace(provider.BaseURL) != "" {
		options["baseURL"] = strings.TrimSpace(provider.BaseURL)
	}
	entry := map[string]any{"options": options}
	if id == "opencode" {
		entry["npm"] = "@ai-sdk/openai-compatible"
		entry["name"] = "OpenCode Zen"
		entry["models"] = map[string]any{model: map[string]any{"name": model}}
	}
	cfg["provider"] = map[string]any{runtime.OpenCodeID: entry}
	return json.Marshal(cfg)
}

func validAgentSessionID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func agentEventText(raw map[string]any) string {
	if raw["type"] != "text" {
		return ""
	}
	part, _ := raw["part"].(map[string]any)
	text, _ := part["text"].(string)
	return strings.TrimSpace(text)
}

func recoverOpenCodeSession(ctx context.Context, binary, sessionID, workspace string, env []string) (string, uint64, uint64, float64, error) {
	cmd := exec.CommandContext(ctx, binary, "export", sessionID)
	cmd.Dir = workspace
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", 0, 0, 0, errors.New(strings.TrimSpace(string(ee.Stderr)))
		}
		return "", 0, 0, 0, err
	}
	// Older OpenCode releases briefly prefixed export JSON with a status line.
	start := strings.IndexByte(string(out), '{')
	if start < 0 {
		return "", 0, 0, 0, errors.New("session export did not contain JSON")
	}
	var exported any
	if err := json.Unmarshal(out[start:], &exported); err != nil {
		return "", 0, 0, 0, err
	}
	texts := exportAssistantTexts(exported)
	var input, output uint64
	var cost float64
	collectAgentUsage(exported, &input, &output, &cost)
	return strings.Join(texts, "\n\n"), input, output, cost, nil
}

func exportAssistantTexts(v any) []string {
	var out []string
	var walk func(any)
	walk = func(value any) {
		switch x := value.(type) {
		case []any:
			for _, item := range x {
				walk(item)
			}
		case map[string]any:
			role := ""
			if info, ok := x["info"].(map[string]any); ok {
				role, _ = info["role"].(string)
			}
			if role == "" {
				role, _ = x["role"].(string)
			}
			if role == "assistant" {
				if parts, ok := x["parts"].([]any); ok {
					for _, item := range parts {
						part, _ := item.(map[string]any)
						if part["type"] == "text" {
							if text, _ := part["text"].(string); strings.TrimSpace(text) != "" {
								out = append(out, text)
							}
						}
					}
					return
				}
			}
			for _, value := range x {
				walk(value)
			}
		}
	}
	walk(v)
	return out
}

func sanitizeAgentDiagnostic(message, secret string) string {
	if secret != "" {
		message = strings.ReplaceAll(message, secret, "[redacted]")
	}
	if len(message) > 12000 {
		message = message[len(message)-12000:]
	}
	return message
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
	if tokens, ok := m["tokens"].(map[string]any); ok {
		if n, ok := numberUint(tokens["input"]); ok && n > *input {
			*input = n
		}
		if n, ok := numberUint(tokens["output"]); ok && n > *output {
			*output = n
		}
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
