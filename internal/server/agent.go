package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	maxImageCount = 6
	maxImageBytes = 10 << 20
	maxRunBytes   = 96 << 20
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
	Workspace     string        `json:"workspace"`
	Prompt        string        `json:"prompt"`
	Session       string        `json:"session,omitempty"`
	ClientSession string        `json:"clientSession,omitempty"`
	Provider      string        `json:"provider,omitempty"`
	Images        []imageUpload `json:"images,omitempty"`
}

type imageUpload struct {
	Name string `json:"name"`
	Data string `json:"data"`
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
		"model":               modelRefFor(runtime, model),
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRunBytes)).Decode(&q); err != nil {
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
	if len(q.Images) > maxImageCount {
		http.Error(w, "too many images", http.StatusRequestEntityTooLarge)
		return
	}
	if q.Session != "" && !validAgentSessionID(strings.TrimSpace(q.Session)) {
		http.Error(w, "invalid provider session", http.StatusBadRequest)
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
	modelRef := modelRefFor(runtime, model)
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
	imageFiles := []string{}
	imageDir := ""
	if len(q.Images) > 0 {
		var err error
		imageDir, imageFiles, err = writeImageAttachments(q.Images)
		if err != nil {
			http.Error(w, "invalid image: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer os.RemoveAll(imageDir)
	}
	args := agentRunArgs(workspace, modelRef, q.Session, imageFiles, q.Prompt)
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = workspace
	env := agentSubprocessEnv(os.Environ(), configDir, dataDir, key, runtime.NeedsKey, a.config.environmentFor(sess.AccountID))
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
	runID := token(18)
	if err := a.startDurableAgentRun(runID, sess.AccountID, clientSession, q.Prompt, q.Workspace, providerID, model); err != nil {
		cancel()
		_ = cmd.Wait()
		writeAgentEvent(w, flusher, "error", map[string]any{"message": "persist agent run: " + err.Error()})
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
			if id, _ := raw["sessionID"].(string); validAgentSessionID(id) {
				sessionID = id
			}
			if agentEventText(raw) != "" {
				sawAssistantText = true
			}
			rewriteAgentImageURLs(raw, clientSession)
			writeAgentEvent(w, flusher, "opencode", sanitizeAgentProviderValue(raw, key, 0))
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
		if recovered, images, usageIn, usageOut, recoveredCost, recoverErr := recoverOpenCodeSession(ctx, binary, sessionID, workspace, clientSession, env); recoverErr == nil {
			if !sawAssistantText && strings.TrimSpace(recovered) != "" {
				writeAgentEvent(w, flusher, "recovered", map[string]any{"text": recovered, "sessionID": sessionID})
			}
			if len(images) > 0 {
				writeAgentEvent(w, flusher, "recovered-images", map[string]any{"images": images, "sessionID": sessionID})
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
		a.finishDurableAgentRun(runID, sess.AccountID, clientSession, "failed", sessionID, msg, inputTokens, outputTokens, cost)
		writeAgentEvent(w, flusher, "error", map[string]any{"message": msg})
		a.auditEvent(r, "agent_run_finish", "status=error workspace="+q.Workspace)
		return
	}
	a.finishDurableAgentRun(runID, sess.AccountID, clientSession, "completed", sessionID, "", inputTokens, outputTokens, cost)
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
	cfg := map[string]any{
		"$schema":    "https://opencode.ai/config.json",
		"model":      modelRefFor(runtime, model),
		"permission": "allow",
	}
	if id == "opencode" {
		cfg["provider"] = zenProviderConfig(model)
		return json.Marshal(cfg)
	}
	options := map[string]any{}
	if runtime.NeedsKey {
		options["apiKey"] = "{env:WARDEN_AGENT_API_KEY}"
	}
	if strings.TrimSpace(provider.BaseURL) != "" {
		options["baseURL"] = strings.TrimSpace(provider.BaseURL)
	}
	cfg["provider"] = map[string]any{runtime.OpenCodeID: map[string]any{"options": options}}
	return json.Marshal(cfg)
}

func modelRefFor(runtime agentProviderRuntime, model string) string {
	if runtime.OpenCodeID == "opencode" {
		return zenProviderKey(model) + "/" + model
	}
	return runtime.OpenCodeID + "/" + model
}

// zenModels is the OpenCode Zen catalogue, snapshot from
// https://opencode.ai/zen/v1/models on 2026-08-29. Zen serves each model family
// through a different protocol, so the catalogue is split by family and the
// generated config declares one provider entry per family (see zenProviderConfig).
// Unknown or newer IDs can still be typed manually; they route to the
// OpenAI-compatible chat family. Refresh this list with
// `curl https://opencode.ai/zen/v1/models` when needed.
var (
	zenOpenAIModels = []string{
		"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.5", "gpt-5.5-pro",
		"gpt-5.4", "gpt-5.4-pro", "gpt-5.4-mini", "gpt-5.4-nano", "gpt-5.3-codex-spark",
		"gpt-5.3-codex", "gpt-5.2", "gpt-5.2-codex", "gpt-5.1", "gpt-5.1-codex-max",
		"gpt-5.1-codex", "gpt-5.1-codex-mini", "gpt-5", "gpt-5-codex", "gpt-5-nano",
		"grok-build-0.1", "grok-4.6", "grok-4.5", "muse-spark-1.2",
	}
	zenAnthropicModels = []string{
		"claude-fable-5", "claude-opus-5", "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6",
		"claude-opus-4-5", "claude-sonnet-5", "claude-sonnet-4-6", "claude-sonnet-4-5", "claude-sonnet-4",
		"claude-haiku-4-5",
	}
	zenGoogleModels = []string{
		"gemini-3.6-flash", "gemini-3.7-flash", "gemini-3.5-flash-lite", "gemini-3.5-flash",
		"gemini-3.1-pro", "gemini-3-flash",
	}
	zenChatModels = []string{
		"deepseek-v4-pro", "deepseek-v4-flash", "glm-5.2", "glm-5.1", "glm-5",
		"minimax-m3", "minimax-m2.7", "minimax-m2.5", "kimi-k3", "kimi-k2.7-code",
		"kimi-k2.6", "kimi-k2.5", "qwen3.6-plus", "qwen3.5-plus", "big-pickle",
		"deepseek-v4-flash-free", "muse-spark-1.2-contributor-free", "mimo-v2.5-free", "hy3-free",
		"ling-3.0-flash-fin-free", "nemotron-3-ultra-free", "nemotron-3.5-lightning-free", "laguna-s-2.1-free",
	}
	zenModels = append(append(append(append([]string{}, zenOpenAIModels...), zenAnthropicModels...), zenGoogleModels...), zenChatModels...)
)

// zenProviderKey maps a Zen model ID to the generated provider entry that
// speaks the protocol that model family needs on the Zen gateway.
func zenProviderKey(modelID string) string {
	switch {
	case strings.HasPrefix(modelID, "gpt-"), strings.HasPrefix(modelID, "grok-"), modelID == "muse-spark-1.2":
		return "opencode"
	case strings.HasPrefix(modelID, "claude-"):
		return "opencode-anthropic"
	case strings.HasPrefix(modelID, "gemini-"):
		return "opencode-google"
	default:
		return "opencode-chat"
	}
}

func zenProviderConfig(selected string) map[string]any {
	providers := map[string]any{}
	addFamily := func(key, npm string, models []string) {
		m := make(map[string]any, len(models)+1)
		for _, id := range models {
			m[id] = map[string]any{"name": id}
		}
		if zenProviderKey(selected) == key {
			m[selected] = map[string]any{"name": selected}
		}
		providers[key] = map[string]any{
			"npm":     npm,
			"name":    "OpenCode Zen",
			"options": map[string]any{"apiKey": "{env:WARDEN_AGENT_API_KEY}", "baseURL": "https://opencode.ai/zen/v1"},
			"models":  m,
		}
	}
	addFamily("opencode", "@ai-sdk/openai", zenOpenAIModels)
	addFamily("opencode-anthropic", "@ai-sdk/anthropic", zenAnthropicModels)
	addFamily("opencode-google", "@ai-sdk/google", zenGoogleModels)
	addFamily("opencode-chat", "@ai-sdk/openai-compatible", zenChatModels)
	return providers
}

// agentRunArgs builds the opencode run argv. The prompt must follow the "--"
// separator: "--file" is an array option in opencode run, so bare words placed
// after it would otherwise be consumed as further file paths.
func agentRunArgs(workspace, modelRef, session string, files []string, prompt string) []string {
	args := []string{"--print-logs", "--log-level", "INFO", "run", "--format", "json", "--auto", "--dir", workspace, "--model", modelRef}
	if s := strings.TrimSpace(session); s != "" {
		args = append(args, "--session", s)
	}
	for _, p := range files {
		args = append(args, "--file", p)
	}
	return append(args, "--", prompt)
}

func writeImageAttachments(imgs []imageUpload) (dir string, paths []string, err error) {
	dir, err = os.MkdirTemp("", "warden-agent-images-")
	if err != nil {
		return "", nil, err
	}
	for _, img := range imgs {
		path, perr := writeImageAttachment(dir, img)
		if perr != nil {
			os.RemoveAll(dir)
			return "", nil, perr
		}
		paths = append(paths, path)
	}
	return dir, paths, nil
}

func writeImageAttachment(dir string, img imageUpload) (string, error) {
	const prefix = "data:image/"
	if len(img.Name) > 500 {
		return "", errors.New("image name is too long")
	}
	if !strings.HasPrefix(img.Data, prefix) {
		return "", errors.New("unsupported image format")
	}
	comma := strings.IndexByte(img.Data, ',')
	if comma < 0 {
		return "", errors.New("invalid image data")
	}
	meta := img.Data[len(prefix):comma]
	var ext string
	switch {
	case strings.HasPrefix(meta, "png;"):
		ext = ".png"
	case strings.HasPrefix(meta, "jpeg;") || strings.HasPrefix(meta, "jpg;"):
		ext = ".jpg"
	case strings.HasPrefix(meta, "gif;"):
		ext = ".gif"
	case strings.HasPrefix(meta, "webp;"):
		ext = ".webp"
	default:
		return "", errors.New("unsupported image type")
	}
	raw, err := base64.StdEncoding.DecodeString(img.Data[comma+1:])
	if err != nil {
		return "", errors.New("invalid image encoding")
	}
	if len(raw) == 0 {
		return "", errors.New("empty image")
	}
	if len(raw) > maxImageBytes {
		return "", errors.New("image exceeds the 10 MiB limit")
	}
	path := filepath.Join(dir, token(12)+ext)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return "", err
	}
	return path, nil
}

// agentImage serves a generated image from the authenticated account's session
// OpenCode data directory so the browser can display model-produced images. It
// resolves the path within that session data dir, rejects anything else
// (including symlinks escaping it), and only serves content that sniffs as an
// image.
func (a *app) agentImage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	sess, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	clientSession := strings.TrimSpace(r.URL.Query().Get("session"))
	if !validAgentSessionID(clientSession) {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}
	base := filepath.Join(a.cfg.ConfigDir, "agent-sessions", sess.AccountID, clientSession, "data")
	abs, err := filepath.Abs(r.URL.Query().Get("path"))
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	rel, err := filepath.Rel(base, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		http.Error(w, "path escapes session data", http.StatusBadRequest)
		return
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "file is unavailable", http.StatusNotFound)
			return
		}
		http.Error(w, "path is unavailable", http.StatusBadRequest)
		return
	}
	rel, err = filepath.Rel(base, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		http.Error(w, "path escapes session data", http.StatusBadRequest)
		return
	}
	f, err := os.Open(real)
	if err != nil {
		http.Error(w, "file is unavailable", http.StatusNotFound)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		http.Error(w, "not a regular file", http.StatusBadRequest)
		return
	}
	if st.Size() > 20<<20 {
		http.Error(w, "file too large", http.StatusRequestEntityTooLarge)
		return
	}
	header := make([]byte, 512)
	n, _ := io.ReadFull(f, header)
	ct := http.DetectContentType(header[:n])
	if !strings.HasPrefix(ct, "image/") {
		http.Error(w, "not an image", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", ct)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "file is unavailable", http.StatusInternalServerError)
		return
	}
	_, _ = io.Copy(w, f)
}

// rewriteAgentImageURLs converts file:// image URLs in an OpenCode streamed or
// exported event into Warden endpoint URLs the browser can fetch. Images
// produced by a model arrive as file parts or tool-result attachments carrying
// mediaType/mime.
func rewriteAgentImageURLs(v any, clientSession string) {
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, y := range x {
				walk(y)
			}
		case map[string]any:
			u, _ := x["url"].(string)
			mime, _ := x["mediaType"].(string)
			if mime == "" {
				mime, _ = x["mime"].(string)
			}
			if strings.HasPrefix(u, "file://") && strings.HasPrefix(strings.ToLower(mime), "image/") {
				if p := fileURLPath(u); p != "" {
					x["url"] = "/api/agent/image?session=" + url.QueryEscape(clientSession) + "&path=" + url.QueryEscape(p)
				}
			}
			for _, y := range x {
				walk(y)
			}
		}
	}
	walk(v)
}

func fileURLPath(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return u.Path
}

// agentModels lists the models opencode knows for a provider by running
// `opencode models <id>` in the same isolated environment as a run. For the
// OpenCode Zen provider it returns the bundled catalogue directly so the
// dropdown works without a configured credential.
func (a *app) agentModels(w http.ResponseWriter, r *http.Request) {
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
	empty := func(note string) {
		jsonOut(w, map[string]any{"provider": providerID, "models": []string{}, "note": note})
	}
	if providerID == "opencode" {
		jsonOut(w, map[string]any{"provider": providerID, "models": zenModels})
		return
	}
	model := strings.TrimSpace(provider.DefaultModel)
	if model == "" {
		model = runtime.FallbackModel
	}
	key := ""
	if runtime.NeedsKey {
		var configured bool
		key, _, configured = a.resolveAICredential(sess.AccountID, providerID)
		if !configured {
			empty("Configure a " + provider.Label + " credential to list models")
			return
		}
	}
	binary, err := exec.LookPath("opencode")
	if err != nil {
		empty("OpenCode is not installed")
		return
	}
	runDir, err := os.MkdirTemp("", "warden-opencode-config-"+sess.AccountID+"-")
	if err != nil {
		empty("")
		return
	}
	defer os.RemoveAll(runDir)
	configDir := filepath.Join(runDir, "config")
	dataDir := filepath.Join(runDir, "data")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		empty("")
		return
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		empty("")
		return
	}
	cfg, err := a.agentOpenCodeConfig(providerID, runtime, provider, model)
	if err != nil {
		empty("")
		return
	}
	configPath := filepath.Join(configDir, "opencode.json")
	if err := os.WriteFile(configPath, cfg, 0600); err != nil {
		empty("")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "models", runtime.OpenCodeID)
	env := agentSubprocessEnv(os.Environ(), configDir, dataDir, key, runtime.NeedsKey, a.config.environmentFor(sess.AccountID))
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		note := sanitizeAgentDiagnostic(strings.TrimSpace(string(out)), key)
		if note == "" {
			note = err.Error()
		}
		empty(note)
		return
	}
	jsonOut(w, map[string]any{"provider": providerID, "models": parseModelLines(out, runtime.OpenCodeID)})
}

func parseModelLines(out []byte, providerID string) []string {
	models := []string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, providerID+"/") {
			continue
		}
		id := strings.TrimPrefix(line, providerID+"/")
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		models = append(models, id)
		if len(models) >= 500 {
			break
		}
	}
	return models
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

func recoverOpenCodeSession(ctx context.Context, binary, sessionID, workspace, clientSession string, env []string) (string, []map[string]string, uint64, uint64, float64, error) {
	if !validAgentSessionID(sessionID) {
		return "", nil, 0, 0, 0, errors.New("invalid provider session")
	}
	cmd := exec.CommandContext(ctx, binary, "export", sessionID)
	cmd.Dir = workspace
	cmd.Env = env
	out := &boundedCommandOutput{limit: 8 << 20}
	errOut := &boundedCommandOutput{limit: 256 << 10}
	cmd.Stdout = out
	cmd.Stderr = errOut
	err := cmd.Run()
	if out.truncated || errOut.truncated {
		return "", nil, 0, 0, 0, errors.New("session export exceeded output limit")
	}
	if err != nil {
		message := strings.TrimSpace(errOut.String())
		if message == "" {
			message = err.Error()
		}
		return "", nil, 0, 0, 0, errors.New(message)
	}
	// Older OpenCode releases briefly prefixed export JSON with a status line.
	start := strings.IndexByte(out.String(), '{')
	if start < 0 {
		return "", nil, 0, 0, 0, errors.New("session export did not contain JSON")
	}
	var exported any
	if err := json.Unmarshal(out.Bytes()[start:], &exported); err != nil {
		return "", nil, 0, 0, 0, err
	}
	rewriteAgentImageURLs(exported, clientSession)
	texts := exportAssistantTexts(exported)
	images := exportAssistantImages(exported)
	var input, output uint64
	var cost float64
	collectAgentUsage(exported, &input, &output, &cost)
	return strings.Join(texts, "\n\n"), images, input, output, cost, nil
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

func exportAssistantImages(v any) []map[string]string {
	out := []map[string]string{}
	seen := map[string]bool{}
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
						if part == nil {
							continue
						}
						if part["type"] == "file" || part["type"] == "image" {
							if m, _ := part["mediaType"].(string); strings.HasPrefix(strings.ToLower(m), "image/") {
								u, _ := part["url"].(string)
								n, _ := part["filename"].(string)
								if u != "" && !seen[u] {
									seen[u] = true
									out = append(out, map[string]string{"url": u, "name": n})
								}
							}
						}
						if part["type"] == "tool" {
							if state, ok := part["state"].(map[string]any); ok {
								if atts, ok := state["attachments"].([]any); ok {
									for _, a := range atts {
										am, _ := a.(map[string]any)
										if am == nil {
											continue
										}
										if m, _ := am["mime"].(string); strings.HasPrefix(strings.ToLower(m), "image/") {
											u, _ := am["url"].(string)
											if u != "" && !seen[u] {
												seen[u] = true
												out = append(out, map[string]string{"url": u})
											}
										}
									}
								}
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
	if len(out) > 20 {
		out = out[:20]
	}
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

func sanitizeAgentProviderValue(v any, secret string, depth int) any {
	if depth > 32 {
		return "[depth limit]"
	}
	switch x := v.(type) {
	case string:
		if secret != "" {
			x = strings.ReplaceAll(x, secret, "[redacted]")
		}
		if len(x) > 65536 {
			x = x[:65536] + "[truncated]"
		}
		return x
	case []any:
		if len(x) > 1024 {
			x = x[:1024]
		}
		out := make([]any, len(x))
		for i := range x {
			out[i] = sanitizeAgentProviderValue(x[i], secret, depth+1)
		}
		return out
	case map[string]any:
		out := make(map[string]any)
		count := 0
		for k, value := range x {
			if count >= 256 {
				out["_truncated"] = true
				break
			}
			lower := strings.ToLower(k)
			if strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "credential") || strings.Contains(lower, "authorization") || strings.Contains(lower, "apikey") || strings.Contains(lower, "api_key") {
				out[k] = "[redacted]"
			} else {
				out[k] = sanitizeAgentProviderValue(value, secret, depth+1)
			}
			count++
		}
		return out
	default:
		return v
	}
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

// hostGitHubEnvVars are scrubbed from inherited subprocess environments so
// Warden's default-deny policy cannot be bypassed by a terminal or service
// environment that happens to carry host GitHub credentials. GH_HOST is not a
// credential but changes host selection, so it is account-controlled too: an
// administrator may re-introduce any of these per-account through the
// protected environment mechanism.
var hostGitHubEnvVars = []string{"GH_CONFIG_DIR", "GH_TOKEN", "GITHUB_TOKEN", "GH_HOST"}

func scrubHostGitHubEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, v := range env {
		name, _, ok := strings.Cut(v, "=")
		if !ok {
			continue
		}
		skip := false
		for _, n := range hostGitHubEnvVars {
			if name == n {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		out = append(out, v)
	}
	return out
}

// agentSubprocessEnv builds the environment for an OpenCode subprocess. It
// starts from the inherited OS environment, removes any host GitHub credential
// selectors so they are never inherited globally by accident, redirects
// OpenCode's own configuration into temporary XDG directories, and then
// applies Warden's persistent per-account environment overrides last so an
// administrator can explicitly grant one account access to host tooling such
// as the GitHub CLI. Host GitHub authentication is intentionally NOT inherited
// by default: it is only shared when an account's environment sets GH_*
// variables explicitly.
func agentSubprocessEnv(baseEnv []string, configDir, dataDir, key string, needsKey bool, overrides map[string]string) []string {
	env := scrubHostGitHubEnv(baseEnv)
	env = setEnvPair(env, "OPENCODE_CONFIG", filepath.Join(configDir, "opencode.json"))
	env = setEnvPair(env, "OPENCODE_CONFIG_DIR", configDir)
	env = setEnvPair(env, "XDG_CONFIG_HOME", configDir)
	env = setEnvPair(env, "XDG_DATA_HOME", dataDir)
	env = setEnvPair(env, "OPENCODE_DISABLE_AUTOUPDATE", "1")
	if needsKey {
		env = setEnvPair(env, "WARDEN_AGENT_API_KEY", key)
	}
	for name, value := range overrides {
		env = setEnvPair(env, name, value)
	}
	return env
}

func agentEnvValue(env []string, key string) string {
	prefix := key + "="
	for _, v := range env {
		if strings.HasPrefix(v, prefix) {
			return v[len(prefix):]
		}
	}
	return ""
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
