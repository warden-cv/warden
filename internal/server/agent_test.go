package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
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
