package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentRunRejectsWorkspaceOutsideConfiguredRoot(t *testing.T) {
	a, user, sess, cookie := permissionTestApp(t)
	files, err := newFiles(a.cfg.FileRoot)
	if err != nil {
		t.Fatal(err)
	}
	a.files = files
	if err := a.accounts.setRole("user", "User", []string{"agent.run", "ai.use", "ai.credentials"}); err != nil {
		t.Fatal(err)
	}
	if err := a.secrets.set(aiAccountSecretName(user.ID, "opencode"), "secret"); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"workspace":"/../../tmp","prompt":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/agent/run", bytes.NewReader(body))
	req.AddCookie(cookie)
	req.Header.Set("X-Warden-CSRF", sess.CSRF)
	rec := httptest.NewRecorder()
	a.agentRun(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestAgentStatusDoesNotExposeCredential(t *testing.T) {
	a, user, sess, cookie := permissionTestApp(t)
	if err := a.accounts.setRole("user", "User", []string{"agent.run", "ai.use", "ai.credentials"}); err != nil {
		t.Fatal(err)
	}
	if err := a.secrets.set(aiAccountSecretName(user.ID, "opencode"), "super-secret-agent-key"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://warden/api/agent/status", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	a.agentStatus(rec, req)
	if bytes.Contains(rec.Body.Bytes(), []byte("super-secret-agent-key")) {
		t.Fatal("agent status leaked credential")
	}
	_ = sess
}

func TestAgentDiagnosticRedactsCredential(t *testing.T) {
	const key = "sk-or-v1-super-secret"
	got := sanitizeAgentDiagnostic("provider failed with "+key, key)
	if bytes.Contains([]byte(got), []byte(key)) {
		t.Fatal("diagnostic leaked credential")
	}
	if !bytes.Contains([]byte(got), []byte("[redacted]")) {
		t.Fatal("diagnostic did not retain useful redaction marker")
	}
}

func TestAgentProviderEventsAreBoundedAndRedacted(t *testing.T) {
	const key = "sk-provider-secret"
	raw := map[string]any{
		"type": "tool",
		"data": map[string]any{
			"apiKey": key,
			"text":   "provider repeated " + key,
			"long":   string(bytes.Repeat([]byte("x"), 70000)),
		},
	}
	clean := sanitizeAgentProviderValue(raw, key, 0)
	b, err := json.Marshal(clean)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(key)) {
		t.Fatalf("provider event leaked credential: %s", b)
	}
	if !bytes.Contains(b, []byte("[redacted]")) || !bytes.Contains(b, []byte("[truncated]")) {
		t.Fatalf("provider event was not visibly bounded/redacted: %s", b)
	}
}

func TestAgentRunRejectsHostileProviderSessionID(t *testing.T) {
	a, _, sess, cookie := permissionTestApp(t)
	files, err := newFiles(a.cfg.FileRoot)
	if err != nil {
		t.Fatal(err)
	}
	a.files = files
	if err := a.accounts.setRole("user", "User", []string{"agent.run", "ai.use", "ai.credentials"}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"workspace":"/","prompt":"test","session":"../../escape"}`)
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/agent/run", bytes.NewReader(body))
	req.AddCookie(cookie)
	req.Header.Set("X-Warden-CSRF", sess.CSRF)
	rec := httptest.NewRecorder()
	a.agentRun(rec, req)
	if rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte("invalid provider session")) {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestAgentEventTextReadsOpenCodeTextPart(t *testing.T) {
	raw := map[string]any{"type": "text", "part": map[string]any{"type": "text", "text": "Hello from DeepSeek"}}
	if got := agentEventText(raw); got != "Hello from DeepSeek" {
		t.Fatalf("got %q", got)
	}
}

func TestExportAssistantTextsFindsAssistantPartsOnly(t *testing.T) {
	exported := map[string]any{"messages": []any{
		map[string]any{"info": map[string]any{"role": "user"}, "parts": []any{map[string]any{"type": "text", "text": "user text"}}},
		map[string]any{"info": map[string]any{"role": "assistant"}, "parts": []any{map[string]any{"type": "reasoning", "text": "private"}, map[string]any{"type": "text", "text": "assistant answer"}}},
	}}
	got := exportAssistantTexts(exported)
	if len(got) != 1 || got[0] != "assistant answer" {
		t.Fatalf("got %#v", got)
	}
}

func TestOpenCodeConfigAllowsCodingTools(t *testing.T) {
	a, _, _, _ := permissionTestApp(t)
	runtime, provider, err := a.agentProvider("opencode")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := a.agentOpenCodeConfig("opencode", runtime, provider, "deepseek-v4-flash")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(cfg, []byte(`"permission":"allow"`)) {
		t.Fatal("isolated OpenCode config does not explicitly allow coding tools")
	}
}

func TestAgentUsageReadsOpenCodeTokensObject(t *testing.T) {
	raw := map[string]any{
		"type":   "step-finish",
		"tokens": map[string]any{"input": float64(32527), "output": float64(3575), "reasoning": float64(42)},
		"cost":   float64(0.42),
	}
	var input, output uint64
	var cost float64
	collectAgentUsage(raw, &input, &output, &cost)
	if input != 32527 || output != 3575 || cost != 0.42 {
		t.Fatalf("usage=%d/%d cost=%v", input, output, cost)
	}
}

func TestAgentOpenAIConfigUsesWardenCredentialEnv(t *testing.T) {
	a, _, _, _ := permissionTestApp(t)
	runtime, provider, err := a.agentProvider("openai")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := a.agentOpenCodeConfig("openai", runtime, provider, "gpt-5.2")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(cfg, []byte(`"model":"openai/gpt-5.2"`)) {
		t.Fatalf("unexpected config: %s", cfg)
	}
	if !bytes.Contains(cfg, []byte(`"{env:WARDEN_AGENT_API_KEY}"`)) {
		t.Fatalf("provider key is not isolated through Warden env: %s", cfg)
	}
}

func TestAgentRunArgsSeparateFilesFromPrompt(t *testing.T) {
	args := agentRunArgs("/work", "opencode/grok-4.6", "sess1", []string{"/tmp/a.png"}, "can you describe what this image is to me")
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		t.Fatal("missing -- separator")
	}
	if strings.Join(args[sep+1:], " ") != "can you describe what this image is to me" {
		t.Fatalf("prompt = %v", args[sep+1:])
	}
	found := false
	for i, a := range args {
		if a == "--file" && i < sep && args[i+1] == "/tmp/a.png" {
			found = true
		}
	}
	if !found {
		t.Fatal("file not attached before separator")
	}
}

func TestWriteImageAttachmentPersistsDecodedImage(t *testing.T) {
	dir := t.TempDir()
	raw := []byte{0x89, 0x50, 0x4e, 0x47}
	data := "data:image/png;base64," + base64.StdEncoding.EncodeToString(raw)
	path, err := writeImageAttachment(dir, imageUpload{Name: "shot.png", Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, ".png") {
		t.Fatalf("extension = %q", path)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("decoded image mismatch")
	}
}

func TestWriteImageAttachmentRejectsOversizeAndNonImage(t *testing.T) {
	dir := t.TempDir()
	if _, err := writeImageAttachment(dir, imageUpload{Name: "b.png", Data: "data:image/png;base64," + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, maxImageBytes+1))}); err == nil {
		t.Fatal("oversize image accepted")
	}
	for _, c := range []imageUpload{
		{Name: "a.png", Data: "data:image/svg+xml;base64,PHN2Zz4="},
		{Name: "b", Data: "not a data url"},
		{Name: "c.png", Data: "data:image/png;base64,%%%"},
	} {
		if _, err := writeImageAttachment(dir, c); err == nil {
			t.Fatalf("accepted %#v", c)
		}
	}
}

func TestAgentRunRejectsTooManyImages(t *testing.T) {
	a, _, sess, cookie := permissionTestApp(t)
	files, err := newFiles(a.cfg.FileRoot)
	if err != nil {
		t.Fatal(err)
	}
	a.files = files
	if err := a.accounts.setRole("user", "User", []string{"agent.run", "ai.use", "ai.credentials"}); err != nil {
		t.Fatal(err)
	}
	var imgs []imageUpload
	for i := 0; i < maxImageCount+1; i++ {
		imgs = append(imgs, imageUpload{Name: "x.png", Data: "data:image/png;base64,AAAA"})
	}
	body, _ := json.Marshal(map[string]any{"workspace": "/", "prompt": "look", "clientSession": "sess1", "images": imgs})
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/agent/run", bytes.NewReader(body))
	req.AddCookie(cookie)
	req.Header.Set("X-Warden-CSRF", sess.CSRF)
	rec := httptest.NewRecorder()
	a.agentRun(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestExportAssistantImagesRecoveredFromExport(t *testing.T) {
	v := map[string]any{"messages": []any{
		map[string]any{"info": map[string]any{"role": "user"}, "parts": []any{map[string]any{"type": "file", "mediaType": "image/png", "url": "file:///u/a.png", "filename": "a.png"}}},
		map[string]any{"info": map[string]any{"role": "assistant"}, "parts": []any{
			map[string]any{"type": "file", "mediaType": "image/png", "url": "file:///g/x.png", "filename": "x.png"},
			map[string]any{"type": "tool", "state": map[string]any{"attachments": []any{map[string]any{"mime": "image/webp", "url": "file:///g/a.webp"}}}},
		}},
	}}
	rewriteAgentImageURLs(v, "sess1")
	imgs := exportAssistantImages(v)
	if len(imgs) != 2 {
		t.Fatalf("images = %v", imgs)
	}
	for _, im := range imgs {
		if !strings.HasPrefix(im["url"], "/api/agent/image?session=sess1&path=") {
			t.Fatalf("url not rewritten: %v", im)
		}
	}
	if imgs[0]["name"] != "x.png" {
		t.Fatalf("filename lost: %v", imgs[0])
	}
}

func TestParseModelLines(t *testing.T) {
	out := []byte("opencode/deepseek-v4-flash\nopencode/deepseek-v4-pro\n\nopencode/deepseek-v4-flash\nother/gpt\n")
	models := parseModelLines(out, "opencode")
	if len(models) != 2 || models[0] != "deepseek-v4-flash" || models[1] != "deepseek-v4-pro" {
		t.Fatalf("models = %v", models)
	}
}

func TestZenModelFamilyRouting(t *testing.T) {
	cases := map[string]string{
		"grok-4.6": "opencode", "gpt-5.6-sol": "opencode", "muse-spark-1.2": "opencode",
		"claude-sonnet-5": "opencode-anthropic", "claude-haiku-4-5": "opencode-anthropic",
		"gemini-3.5-flash": "opencode-google", "gemini-3-flash": "opencode-google",
		"deepseek-v4-flash": "opencode-chat", "glm-5": "opencode-chat", "future-custom": "opencode-chat",
	}
	runtime := agentProviderRuntime{OpenCodeID: "opencode"}
	for model, want := range cases {
		if got := zenProviderKey(model); got != want {
			t.Fatalf("%s -> %s, want %s", model, got, want)
		}
		if ref := modelRefFor(runtime, model); ref != want+"/"+model {
			t.Fatalf("%s ref = %s", model, ref)
		}
	}
}

func TestZenConfigIncludesCatalogueAndCustomModel(t *testing.T) {
	a, _, _, _ := permissionTestApp(t)
	runtime, provider, err := a.agentProvider("opencode")
	if err != nil {
		t.Fatal(err)
	}
	b, err := a.agentOpenCodeConfig("opencode", runtime, provider, "future-custom-model")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["model"] != "opencode-chat/future-custom-model" {
		t.Fatalf("model = %#v", cfg["model"])
	}
	providers, _ := cfg["provider"].(map[string]any)
	if len(providers) != 4 {
		t.Fatalf("provider entries = %d, want 4", len(providers))
	}
	total := 0
	for _, v := range providers {
		entry, _ := v.(map[string]any)
		models, _ := entry["models"].(map[string]any)
		total += len(models)
		opts, _ := entry["options"].(map[string]any)
		if opts["apiKey"] != "{env:WARDEN_AGENT_API_KEY}" || opts["baseURL"] != "https://opencode.ai/zen/v1" {
			t.Fatalf("options = %#v", opts)
		}
	}
	if total != len(zenModels)+1 {
		t.Fatalf("model total = %d, want %d", total, len(zenModels)+1)
	}
}

func TestAgentModelsZenUsesHardcodedCatalogue(t *testing.T) {
	a, _, _, cookie := permissionTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "http://warden/api/agent/models?provider=opencode", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	a.agentModels(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var out struct {
		Models []string `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Models) != len(zenModels) {
		t.Fatalf("models = %d, want %d", len(out.Models), len(zenModels))
	}
}

func TestAgentImageServesOnlySessionImages(t *testing.T) {
	a, user, _, cookie := permissionTestApp(t)
	dir := filepath.Join(a.cfg.ConfigDir, "agent-sessions", user.ID, "sess1", "data")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	png := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}
	if err := os.WriteFile(filepath.Join(dir, "img.png"), png, 0600); err != nil {
		t.Fatal(err)
	}
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://warden/api/agent/image?session=sess1&path="+url.QueryEscape(path), nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		a.agentImage(rec, req)
		return rec
	}
	if w := get(filepath.Join(dir, "img.png")); w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("valid image: code=%d ct=%q", w.Code, w.Header().Get("Content-Type"))
	}
	if w := get("/etc/passwd"); w.Code == http.StatusOK {
		t.Fatal("escaping path served")
	}
	if err := os.WriteFile(filepath.Join(dir, "x.txt"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if w := get(filepath.Join(dir, "x.txt")); w.Code == http.StatusOK {
		t.Fatal("non-image served")
	}
}
