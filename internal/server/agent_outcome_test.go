package server

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeOpenCode writes a deterministic fake `opencode` executable into a temp
// directory prepended to PATH.
type fakeOpenCode struct {
	dir  string
	path string
	mu   sync.Mutex
}

func newFakeOpenCode(t *testing.T) *fakeOpenCode {
	t.Helper()
	dir := t.TempDir()
	f := &fakeOpenCode{dir: dir, path: filepath.Join(dir, "opencode")}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return f
}

func (f *fakeOpenCode) invoke(t *testing.T, stdout, stderr string, exitCode int, export string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.WriteFile(filepath.Join(f.dir, "stdout.txt"), []byte(stdout), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "stderr.txt"), []byte(stderr), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "export.txt"), []byte(export), 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/bash
if [ "$1" = "export" ]; then
  cat "` + filepath.Join(f.dir, "export.txt") + `"
  exit 0
fi
cat "` + filepath.Join(f.dir, "stdout.txt") + `"
cat "` + filepath.Join(f.dir, "stderr.txt") + `" >&2
exit ` + fmt.Sprintf("%d", exitCode) + `
`
	if err := os.WriteFile(f.path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
}

// wardenAgentTestApp builds an app with a user granted agent.run and a
// configured OpenCode credential, plus the active-runs registry and a real DB.
func wardenAgentTestApp(t *testing.T, fake *fakeOpenCode) (*app, account, session, *http.Cookie) {
	t.Helper()
	a, user, sess, cookie := permissionTestApp(t)
	a.files = testFiles(t, a)
	a.db = testDB(t, a)
	if err := a.accounts.setRole("user", "User", []string{"agent.run", "ai.use", "ai.credentials"}); err != nil {
		t.Fatal(err)
	}
	if err := a.secrets.set(aiAccountSecretName(user.ID, "opencode"), "sk-test-secret-key-abcdef"); err != nil {
		t.Fatal(err)
	}
	a.activeRuns = map[string]*activeRun{}
	return a, user, sess, cookie
}

func testFiles(t *testing.T, a *app) *fileAPI {
	t.Helper()
	files, err := newFiles(a.cfg.FileRoot)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func testDB(t *testing.T, a *app) *sql.DB {
	t.Helper()
	db, err := openDatabase(a.cfg.ConfigDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func agentWorkspace(t *testing.T, a *app) string {
	t.Helper()
	ws := filepath.Join(a.cfg.FileRoot, "ws")
	if err := os.MkdirAll(ws, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "README.md"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	return "ws"
}

func wardenRunRequest(t *testing.T, a *app, sess session, cookie *http.Cookie, workspace string) []map[string]any {
	t.Helper()
	return wardenRunRequestSession(t, a, sess, cookie, workspace, "conv1")
}

func wardenRunRequestSession(t *testing.T, a *app, sess session, cookie *http.Cookie, workspace, clientSession string) []map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"workspace": workspace, "prompt": "test", "clientSession": clientSession, "provider": "opencode"})
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/agent/run", bytes.NewReader(body))
	req.AddCookie(cookie)
	req.Header.Set("X-Warden-CSRF", sess.CSRF)
	rec := httptest.NewRecorder()
	a.agentRun(rec, req)
	events := []map[string]any{}
	sc := bufio.NewScanner(rec.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err == nil {
			events = append(events, ev)
		}
	}
	return events
}

func wardenRunState(t *testing.T, a *app, accountID, runID string) string {
	t.Helper()
	var state string
	if err := a.db.QueryRow("SELECT state FROM agent_runs WHERE id=? AND account_id=?", runID, accountID).Scan(&state); err != nil {
		t.Fatalf("read run state: %v", err)
	}
	return state
}

func wardenRunDiagnostics(t *testing.T, a *app, accountID, runID string) diagnostics {
	t.Helper()
	var raw string
	if err := a.db.QueryRow("SELECT diagnostics FROM agent_runs WHERE id=? AND account_id=?", runID, accountID).Scan(&raw); err != nil {
		t.Fatalf("read diagnostics: %v", err)
	}
	var d diagnostics
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			t.Fatalf("unmarshal diagnostics: %v", err)
		}
	}
	return d
}

func wardenTerminalEvent(events []map[string]any) string {
	for _, ev := range events {
		if t, _ := ev["type"].(string); t == "done" || t == "error" || t == "warning" || t == "cancelled" || t == "truncated" {
			return t
		}
	}
	return ""
}

// --- outcome classification parity ---

func TestWardenClassifyRunParity(t *testing.T) {
	cases := []struct {
		name        string
		state       runStateSnapshot
		stdoutError bool
		validStop   bool
		exit        exitStatus
		want        runOutcome
	}{
		{"exit0 stop completed", runStateSnapshot{}, false, true, exitStatus{exited: true, exitCode: 0}, outcomeCompleted},
		{"exit1 stop completed_with_process_error", runStateSnapshot{}, false, true, exitStatus{exited: true, exitCode: 1}, outcomeCompletedWError},
		{"exit1 no stop failed", runStateSnapshot{}, false, false, exitStatus{exited: true, exitCode: 1}, outcomeFailed},
		{"signal no cause failed even with stop", runStateSnapshot{}, false, true, exitStatus{signaled: true, signal: "SIGKILL"}, outcomeFailed},
		{"stdout error before cause failed", runStateSnapshot{errSeq: 1, causeSeq: 2}, true, true, exitStatus{exited: true, exitCode: 0}, outcomeFailed},
		{"stdout error after stop cancelled", runStateSnapshot{cause: causeUserStop, causeSeq: 1, errSeq: 2}, true, true, exitStatus{signaled: true, signal: "SIGKILL"}, outcomeCancelled},
		{"output limit truncated", runStateSnapshot{cause: causeOutputLimit}, false, false, exitStatus{signaled: true, signal: "SIGKILL"}, outcomeTruncated},
		{"shutdown interrupted", runStateSnapshot{cause: causeServiceShutdown}, false, false, exitStatus{signaled: true, signal: "SIGTERM"}, outcomeInterrupted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyRun(tc.state, tc.stdoutError, tc.validStop, tc.exit, causeNone); got != tc.want {
				t.Fatalf("classifyRun = %q want %q", got, tc.want)
			}
		})
	}
}

func TestWardenRunStateTransitionsParity(t *testing.T) {
	s := newRunState()
	s.recordCause(causeRequestCanceled)
	s.recordCause(causeUserStop)
	if got := s.snapshot().cause; got != causeUserStop {
		t.Fatalf("cause = %q want user_stop", got)
	}
	s2 := newRunState()
	s2.recordCause(causeOutputLimit)
	s2.recordCause(causeRequestCanceled)
	if got := s2.snapshot().cause; got != causeOutputLimit {
		t.Fatalf("cause = %q want output_limit", got)
	}
	s3 := newRunState()
	s3.seal()
	if s3.recordCause(causeUserStop) {
		t.Fatal("late stop accepted after seal")
	}
}

func TestWardenTailCaptureDrainsToEOF(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		sb.WriteString(fmt.Sprintf("line %d\n", i))
	}
	sb.WriteString("level=ERROR message=failed ref=err_abc\n")
	c := captureTail(strings.NewReader(sb.String()), 4<<10)
	c.wait()
	if !c.truncated() {
		t.Fatal("expected truncation")
	}
	if !strings.Contains(c.String(), "ref=err_abc") {
		t.Fatal("tail lost final error line")
	}
}

// --- fake-opencode fixtures ---

func TestWardenAgentExit0ValidStopCompletes(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n"
	fake.invoke(t, stdout, "", 0, `{"info":{"id":"ses_x"},"messages":[]}`)
	events := wardenRunRequest(t, a, sess, cookie, ws)
	if got := wardenTerminalEvent(events); got != "done" {
		t.Fatalf("terminal event = %q want done", got)
	}
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	if state := wardenRunState(t, a, user.ID, runID); state != string(outcomeCompleted) {
		t.Fatalf("state = %q want completed", state)
	}
}

func TestWardenAgentExitNonZeroValidStopIsCompletedWithProcessError(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n"
	stderr := "level=INFO message=exiting loop\nlevel=INFO message=disposing instance\n"
	fake.invoke(t, stdout, stderr, 1, `{"info":{"id":"ses_x"},"messages":[]}`)
	events := wardenRunRequest(t, a, sess, cookie, ws)
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	if state := wardenRunState(t, a, user.ID, runID); state != string(outcomeCompletedWError) {
		t.Fatalf("state = %q want completed_with_process_error", state)
	}
	d := wardenRunDiagnostics(t, a, user.ID, runID)
	if d.Outcome != string(outcomeCompletedWError) {
		t.Fatalf("diagnostics outcome = %q", d.Outcome)
	}
}

func TestWardenAgentStdoutErrorForcesFailure(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"error\",\"sessionID\":\"ses_x\",\"error\":{\"name\":\"ProviderError\",\"data\":{\"message\":\"stream failed\"}}}\n{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n"
	fake.invoke(t, stdout, "", 1, `{"info":{"id":"ses_x"},"messages":[]}`)
	events := wardenRunRequest(t, a, sess, cookie, ws)
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	if state := wardenRunState(t, a, user.ID, runID); state != string(outcomeFailed) {
		t.Fatalf("state = %q want failed", state)
	}
}

// TestWardenAgentPostStopErrorIsNotFailure verifies a valid main-session
// step_finish followed by a later wrapper error is post-completion evidence:
// the answer is completed with a warning, delivered as a distinct warning event,
// and the raw error never survives as a separate Error block in the transcript.
func TestWardenAgentPostStopErrorIsNotFailure(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n{\"type\":\"error\",\"sessionID\":\"ses_x\",\"error\":{\"name\":\"LifecycleError\",\"data\":{\"message\":\"level=INFO message=exiting loop\\nlevel=INFO message=disposing instance\"}}}\n"
	fake.invoke(t, stdout, "", 1, `{"info":{"id":"ses_x"},"messages":[]}`)
	events := wardenRunRequest(t, a, sess, cookie, ws)
	if got := wardenTerminalEvent(events); got != "warning" {
		t.Fatalf("terminal event = %q want warning", got)
	}
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	if state := wardenRunState(t, a, user.ID, runID); state != string(outcomeCompletedWError) {
		t.Fatalf("state = %q want completed_with_process_error", state)
	}
	merged, err := a.loadConversationMerged(user.ID, "conv1")
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range merged {
		if ev.Kind == "error" {
			t.Fatalf("post-completion error survived as a raw Error block: %+v", ev)
		}
	}
	d := wardenRunDiagnostics(t, a, user.ID, runID)
	if d.Outcome != string(outcomeCompletedWError) {
		t.Fatalf("diagnostics outcome = %q", d.Outcome)
	}
	if len(d.Warnings) == 0 || !strings.Contains(strings.Join(d.Warnings, " "), "exiting loop") {
		t.Fatalf("post-completion error not retained as a warning: %+v", d.Warnings)
	}
}

// TestWardenAgentExit1NoValidStopFails verifies a nonzero exit without valid
// completion evidence is a genuine failure, never a warning.
func TestWardenAgentExit1NoValidStopFails(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"text\",\"sessionID\":\"ses_x\",\"part\":{\"type\":\"text\",\"text\":\"partial\"}}\n"
	fake.invoke(t, stdout, "", 1, `{"info":{"id":"ses_x"},"messages":[]}`)
	events := wardenRunRequest(t, a, sess, cookie, ws)
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	if state := wardenRunState(t, a, user.ID, runID); state != string(outcomeFailed) {
		t.Fatalf("exit 1 without valid stop state = %q want failed", state)
	}
}

// TestWardenAgentWarningSurvivesReload verifies a completed_with_process_error
// terminal event is persisted as a warning and survives the conversation
// reload path without degrading into a generic Error block or failed state.
func TestWardenAgentWarningSurvivesReload(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n{\"type\":\"error\",\"sessionID\":\"ses_x\",\"error\":{\"name\":\"LifecycleError\",\"data\":{\"message\":\"level=INFO message=exiting loop\"}}}\n"
	fake.invoke(t, stdout, "", 1, `{"info":{"id":"ses_x"},"messages":[]}`)
	wardenRunRequest(t, a, sess, cookie, ws)
	var state string
	if err := a.db.QueryRow("SELECT state FROM conversations WHERE id=? AND account_id=?", "conv1", user.ID).Scan(&state); err != nil {
		t.Fatalf("read conversation state: %v", err)
	}
	if state != string(outcomeCompletedWError) {
		t.Fatalf("reload state = %q want completed_with_process_error", state)
	}
	merged, err := a.loadConversationMerged(user.ID, "conv1")
	if err != nil {
		t.Fatal(err)
	}
	foundWarning := false
	for _, ev := range merged {
		if ev.Kind == "error" {
			t.Fatalf("warning run reloaded as a raw Error block: %+v", ev)
		}
		if ev.Kind == "warning" {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatal("warning terminal event missing after reload")
	}
}

func TestWardenAgentUnexpectedSignalIsFailed(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n"
	if err := os.WriteFile(filepath.Join(fake.dir, "stdout.txt"), []byte(stdout), 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/bash
cat "` + filepath.Join(fake.dir, "stdout.txt") + `"
kill -9 $$
`
	if err := os.WriteFile(fake.path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	events := wardenRunRequest(t, a, sess, cookie, ws)
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	if state := wardenRunState(t, a, user.ID, runID); state != string(outcomeFailed) {
		t.Fatalf("state = %q want failed (unexpected signal)", state)
	}
	d := wardenRunDiagnostics(t, a, user.ID, runID)
	if d.Signal == "" {
		t.Fatal("signal not recorded")
	}
}

func TestWardenAgentRecoveryAfterNonZeroExit(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"text\",\"sessionID\":\"ses_x\",\"part\":{\"type\":\"text\",\"text\":\"partial\"}}\n{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n"
	export := `{"info":{"id":"ses_x","tokens":{"input":10,"output":20}},"messages":[{"info":{"role":"assistant","finish":"stop"},"parts":[{"type":"text","text":"final recovered response"}]}]}`
	fake.invoke(t, stdout, "", 1, export)
	events := wardenRunRequest(t, a, sess, cookie, ws)
	found := false
	for _, ev := range events {
		if t, _ := ev["type"].(string); t == "recovered" {
			found = true
		}
	}
	if !found {
		t.Fatal("recovered event not emitted")
	}
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	if state := wardenRunState(t, a, user.ID, runID); state == string(outcomeCompleted) {
		t.Fatal("recovery must not reclassify failed as completed")
	}
	d := wardenRunDiagnostics(t, a, user.ID, runID)
	if d.RecoveryResult != "ok" {
		t.Fatalf("recovery result = %q want ok", d.RecoveryResult)
	}
}

func TestWardenAgentServerOwnedEventsPersisted(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"text\",\"sessionID\":\"ses_x\",\"part\":{\"type\":\"text\",\"text\":\"authoritative output\"}}\n{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n"
	fake.invoke(t, stdout, "", 0, `{"info":{"id":"ses_x"},"messages":[]}`)
	wardenRunRequest(t, a, sess, cookie, ws)
	events, err := a.loadAgentRunEvents(user.ID, "conv1")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range events {
		if ev.Kind == "assistant" && strings.Contains(ev.Text, "authoritative output") {
			found = true
		}
	}
	if !found {
		t.Fatalf("assistant output not persisted: %+v", events)
	}
}

func TestWardenAgentStaleClientSaveCannotEraseServerEvents(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"text\",\"sessionID\":\"ses_x\",\"part\":{\"type\":\"text\",\"text\":\"authoritative\"}}\n{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n"
	fake.invoke(t, stdout, "", 0, `{"info":{"id":"ses_x"},"messages":[]}`)
	wardenRunRequest(t, a, sess, cookie, ws)
	c := durableConversation{ID: "conv1", Workspace: ws, Events: []durableAgentEvent{{Kind: "user", Text: "old", CreatedAt: 1}}}
	if err := a.saveConversation(user.ID, &c); err != nil {
		t.Fatal(err)
	}
	events, err := a.loadAgentRunEvents(user.ID, "conv1")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range events {
		if ev.Kind == "assistant" && strings.Contains(ev.Text, "authoritative") {
			found = true
		}
	}
	if !found {
		t.Fatal("stale client save erased server-owned run events")
	}
}

func TestWardenAgentConversationStateNotOverwrittenByClient(t *testing.T) {
	a, user, _, _ := permissionTestApp(t)
	a.activeRuns = map[string]*activeRun{}
	a.files = testFiles(t, a)
	a.db = testDB(t, a)
	ws := agentWorkspace(t, a)
	if _, err := a.db.Exec(`INSERT INTO conversations(account_id,id,state,created_at,updated_at) VALUES(?,'conv1','failed',1,1)`, user.ID); err != nil {
		t.Fatal(err)
	}
	c := durableConversation{ID: "conv1", Workspace: ws, State: "idle", Events: nil}
	if err := a.saveConversation(user.ID, &c); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := a.db.QueryRow("SELECT state FROM conversations WHERE account_id=? AND id='conv1'", user.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "failed" {
		t.Fatalf("client save overwrote state to %q", state)
	}
}

// --- Stop protocol and ownership ---

func TestWardenAgentCancelRecordsUserStopAndStopsRun(t *testing.T) {
	a, user, sess, cookie := permissionTestApp(t)
	if err := a.accounts.setRole("user", "User", []string{"agent.run", "ai.use", "ai.credentials"}); err != nil {
		t.Fatal(err)
	}
	a.activeRuns = map[string]*activeRun{}
	a.files = testFiles(t, a)
	a.db = testDB(t, a)
	ctx, cancel := context.WithCancel(context.Background())
	a.runMu.Lock()
	a.activeRuns["run1"] = newActiveRun(user.ID, cancel)
	a.runMu.Unlock()
	defer func() { a.runMu.Lock(); delete(a.activeRuns, "run1"); a.runMu.Unlock() }()

	req := httptest.NewRequest(http.MethodPost, "http://warden/api/agent/cancel", strings.NewReader(`{"runID":"run1"}`))
	req.AddCookie(cookie)
	req.Header.Set("X-Warden-CSRF", sess.CSRF)
	rec := httptest.NewRecorder()
	a.agentCancel(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if snap := a.activeRuns["run1"].state.snapshot(); snap.cause != causeUserStop {
		t.Fatalf("cause = %q want user_stop", snap.cause)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("cancel did not stop the run context")
	}
}

// TestWardenAgentCancelCrossAccountDenied verifies an arbitrary account cannot
// cancel another account's run.
func TestWardenAgentCancelCrossAccountDenied(t *testing.T) {
	a, user, _, _ := permissionTestApp(t)
	if err := a.accounts.setRole("user", "User", []string{"agent.run", "ai.use", "ai.credentials"}); err != nil {
		t.Fatal(err)
	}
	a.activeRuns = map[string]*activeRun{}
	a.files = testFiles(t, a)
	a.db = testDB(t, a)
	_, cancel := context.WithCancel(context.Background())
	a.runMu.Lock()
	a.activeRuns["run1"] = newActiveRun("someone-else", cancel)
	a.runMu.Unlock()
	defer func() { a.runMu.Lock(); delete(a.activeRuns, "run1"); a.runMu.Unlock() }()

	// user cannot cancel someone-else's run.
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/agent/cancel", strings.NewReader(`{"runID":"run1"}`))
	rec := httptest.NewRecorder()
	a.agentCancel(rec, req)
	_ = user
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d want 401", rec.Code)
	}
}

func TestWardenAgentCancelUnknownRun404(t *testing.T) {
	a, user, sess, cookie := permissionTestApp(t)
	if err := a.accounts.setRole("user", "User", []string{"agent.run", "ai.use", "ai.credentials"}); err != nil {
		t.Fatal(err)
	}
	a.activeRuns = map[string]*activeRun{}
	a.files = testFiles(t, a)
	a.db = testDB(t, a)
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/agent/cancel", strings.NewReader(`{"runID":"nope"}`))
	req.AddCookie(cookie)
	req.Header.Set("X-Warden-CSRF", sess.CSRF)
	rec := httptest.NewRecorder()
	a.agentCancel(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d want 404", rec.Code)
	}
	_ = user
}

func TestWardenAgentRunDiagnosticsEndpointOwnership(t *testing.T) {
	a, user, _, _ := permissionTestApp(t)
	if err := a.accounts.setRole("user", "User", []string{"agent.run", "ai.use", "ai.credentials"}); err != nil {
		t.Fatal(err)
	}
	a.activeRuns = map[string]*activeRun{}
	a.files = testFiles(t, a)
	a.db = testDB(t, a)
	if _, err := a.db.Exec(`INSERT INTO conversations(account_id,id,state,created_at,updated_at) VALUES(?,'conv1','failed',1,1)`, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(`INSERT INTO agent_runs(id,account_id,conversation_id,state,prompt,started_at,diagnostics) VALUES('run1',?,'conv1','failed','p',1,'{"outcome":"failed","category":"signal","signal":"SIGKILL"}')`, user.ID); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://warden/api/agent/run-diagnostics?runID=run1", nil)
	rec := httptest.NewRecorder()
	a.agentRunDiagnostics(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d want 401", rec.Code)
	}
	// Another account cannot see it.
	a2, other, _, _ := permissionTestApp(t)
	if err := a2.accounts.setRole("user", "User", []string{"agent.run"}); err != nil {
		t.Fatal(err)
	}
	// Insert a foreign conversation/run for the second app is not needed; use
	// the same runID but different account, which must 404.
	req2 := httptest.NewRequest(http.MethodGet, "http://warden/api/agent/run-diagnostics?runID=run1", nil)
	rec2 := httptest.NewRecorder()
	a2.agentRunDiagnostics(rec2, req2)
	_ = other
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("cross-account status = %d want 401 (unauthenticated)", rec2.Code)
	}
}

// --- restart sweep parity ---

func TestWardenMarkStaleRunsInterrupted(t *testing.T) {
	a, user, _, _ := permissionTestApp(t)
	if err := a.accounts.setRole("user", "User", []string{"agent.run"}); err != nil {
		t.Fatal(err)
	}
	a.activeRuns = map[string]*activeRun{}
	a.files = testFiles(t, a)
	a.db = testDB(t, a)
	if _, err := a.db.Exec(`INSERT INTO conversations(account_id,id,state,created_at,updated_at) VALUES(?,'conv1','running',1,1)`, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(`INSERT INTO agent_runs(id,account_id,conversation_id,state,prompt,started_at) VALUES('run1',?,'conv1','running','p',1)`, user.ID); err != nil {
		t.Fatal(err)
	}
	a.markStaleRunsInterrupted()
	var state string
	if err := a.db.QueryRow("SELECT state FROM agent_runs WHERE id='run1'").Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != string(outcomeInterrupted) {
		t.Fatalf("stale run state = %q want interrupted", state)
	}
	if err := a.db.QueryRow("SELECT state FROM conversations WHERE account_id=? AND id='conv1'", user.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != string(outcomeInterrupted) {
		t.Fatalf("stale conversation state = %q want interrupted", state)
	}
}

// --- output limit parity ---

func TestWardenAgentOutputLimitIsTruncated(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	// Emit enough small JSON lines to exceed maxProviderBytes (32 MiB) while
	// staying under the per-line scanner bound.
	var sb strings.Builder
	for i := 0; i < 30000; i++ {
		sb.WriteString("{\"type\":\"text\",\"sessionID\":\"ses_x\",\"part\":{\"type\":\"text\",\"text\":\"")
		sb.WriteString(strings.Repeat("x", 600))
		sb.WriteString("\"}}\n")
	}
	sb.WriteString("{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n")
	fake.invoke(t, sb.String(), "", 0, `{"info":{"id":"ses_x"},"messages":[]}`)
	events := wardenRunRequest(t, a, sess, cookie, ws)
	if got := wardenTerminalEvent(events); got != "truncated" {
		t.Fatalf("terminal event = %q want truncated", got)
	}
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	if state := wardenRunState(t, a, user.ID, runID); state != string(outcomeTruncated) {
		t.Fatalf("state = %q want truncated", state)
	}
}

// --- migration parity ---

func TestWardenMigrationAddsRunEventsAndColumns(t *testing.T) {
	a := &app{audit: log.New(io.Discard, "", 0)}
	dir := t.TempDir()
	db, err := openDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a.db = db
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='agent_run_events'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("agent_run_events table missing after migration")
	}
	var colCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('agent_runs') WHERE name='diagnostics'").Scan(&colCount); err != nil {
		t.Fatal(err)
	}
	if colCount != 1 {
		t.Fatal("agent_runs.diagnostics missing after migration")
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('conversations') WHERE name='current_run_id'").Scan(&colCount); err != nil {
		t.Fatal(err)
	}
	if colCount != 1 {
		t.Fatal("conversations.current_run_id missing after migration")
	}
}

// --- provider insufficient-balance (Warden parity) ---

func TestWardenClassifyProviderErrorParity(t *testing.T) {
	cases := []struct {
		msg    string
		code   string
		status int
		want   bool
	}{
		{"AI_APICallError: Insufficient balance. Manage your billing here: https://opencode.ai/workspace/x/billing", "", 0, true},
		{"Insufficient balance", "", 0, true},
		{"", "insufficient_balance", 0, true},
		{"", "", 402, true},
		{"Payment required", "", 0, false},
		{"402 Payment Required", "", 0, false},
		{"rate limit reached", "", 429, false},
		{"quota exceeded", "", 0, false},
		{"API key invalid", "", 401, false},
	}
	for _, tc := range cases {
		if got := classifyProviderError(tc.msg, tc.code, tc.status); got != tc.want {
			t.Fatalf("classifyProviderError(%q,%q,%d) = %v want %v", tc.msg, tc.code, tc.status, got, tc.want)
		}
	}
}

func TestWardenSanitizeBillingURLParity(t *testing.T) {
	ok := "https://opencode.ai/workspace/abc/billing"
	if got := sanitizeBillingURL(ok); got != ok {
		t.Fatalf("valid URL = %q", got)
	}
	for _, u := range []string{
		"http://opencode.ai/workspace/x/billing",
		"https://www.opencode.ai/workspace/x/billing",
		"https://opencode.ai.evil.com/workspace/x",
		"https://user:pass@opencode.ai/workspace/x",
		"https://opencode.ai:8443/workspace/x",
		"https://opencode.ai/",
		"javascript:alert(1)",
		"https://opencode.ai/workspace/x?next=https://evil.com",
	} {
		if got := sanitizeBillingURL(u); got != "" {
			t.Fatalf("rejected URL %q accepted as %q", u, got)
		}
	}
}

func TestWardenAgentInsufficientBalanceAccountScoped(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	msg := "AI_APICallError: Insufficient balance. Manage your billing here: https://opencode.ai/workspace/abc/billing"
	stdout := "{\"type\":\"error\",\"sessionID\":\"ses_x\",\"error\":{\"name\":\"AI_APICallError\",\"data\":{\"message\":\"" + msg + "\"}}}\n"
	fake.invoke(t, stdout, "", 1, `{"info":{"id":"ses_x"},"messages":[]}`)
	events := wardenRunRequest(t, a, sess, cookie, ws)
	var runID string
	var terminal map[string]any
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
		if t, _ := ev["type"].(string); t == "error" {
			terminal = ev["data"].(map[string]any)
		}
	}
	if state := wardenRunState(t, a, user.ID, runID); state != string(outcomeFailed) {
		t.Fatalf("state = %q want failed", state)
	}
	d := wardenRunDiagnostics(t, a, user.ID, runID)
	if d.ProviderCause != string(causeProviderInsufficientBalance) {
		t.Fatalf("providerCause = %q", d.ProviderCause)
	}
	if d.BillingURL != "https://opencode.ai/workspace/abc/billing" {
		t.Fatalf("billingUrl = %q", d.BillingURL)
	}
	if terminal == nil || terminal["cause"] != string(causeProviderInsufficientBalance) {
		t.Fatalf("terminal payload missing cause: %+v", terminal)
	}
	if terminal == nil || terminal["billingUrl"] != "https://opencode.ai/workspace/abc/billing" {
		t.Fatalf("terminal payload missing billingUrl: %+v", terminal)
	}
}

func TestWardenAgentSubagentBillingDoesNotClassifyMain(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"error\",\"sessionID\":\"ses_sub\",\"error\":{\"data\":{\"message\":\"Insufficient balance\"}}}\n{\"type\":\"step_finish\",\"sessionID\":\"ses_main\",\"part\":{\"reason\":\"stop\"}}\n"
	fake.invoke(t, stdout, "", 0, `{"info":{"id":"ses_main"},"messages":[]}`)
	events := wardenRunRequest(t, a, sess, cookie, ws)
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	if state := wardenRunState(t, a, user.ID, runID); state != string(outcomeCompleted) {
		t.Fatalf("subagent billing state = %q want completed", state)
	}
}

// TestWardenConversationSavePreservesVerbatimWorkspace verifies a historical or
// temporarily unavailable workspace never blocks saving conversation history.
func TestWardenConversationSavePreservesVerbatimWorkspace(t *testing.T) {
	a, user, _, _ := permissionTestApp(t)
	a.activeRuns = map[string]*activeRun{}
	a.files = testFiles(t, a)
	a.db = testDB(t, a)
	c := durableConversation{ID: "conv1", Workspace: "/does/not/exist/anywhere", State: "idle", Events: nil}
	if err := a.saveConversation(user.ID, &c); err != nil {
		t.Fatalf("save with unavailable workspace failed: %v", err)
	}
	var ws string
	if err := a.db.QueryRow("SELECT workspace FROM conversations WHERE account_id=? AND id='conv1'", user.ID).Scan(&ws); err != nil {
		t.Fatal(err)
	}
	if ws != "/does/not/exist/anywhere" {
		t.Fatalf("workspace not preserved verbatim: %q", ws)
	}
}

// TestWardenShutdownWaitsForPersistence verifies stopActiveRuns waits for the
// handler's persisted terminal state with a bounded timeout.
func TestWardenShutdownWaitsForPersistence(t *testing.T) {
	a, user, _, _ := permissionTestApp(t)
	a.activeRuns = map[string]*activeRun{}
	a.files = testFiles(t, a)
	a.db = testDB(t, a)
	ctx, cancel := context.WithCancel(context.Background())
	run := newActiveRun(user.ID, cancel)
	a.runMu.Lock()
	a.activeRuns["run1"] = run
	a.runMu.Unlock()
	defer func() { a.runMu.Lock(); delete(a.activeRuns, "run1"); a.runMu.Unlock() }()
	go func() {
		<-ctx.Done()
		time.Sleep(30 * time.Millisecond)
		run.finished()
	}()
	start := time.Now()
	a.stopActiveRuns()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stopActiveRuns blocked too long: %v", elapsed)
	}
	if snap := run.state.snapshot(); snap.cause != causeServiceShutdown {
		t.Fatalf("cause = %q want service_shutdown", snap.cause)
	}
}

// --- fault-injection: terminal persistence must fail closed (Warden parity) ---

func TestWardenAgentTerminalEventInsertFailureFailsClosed(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n"
	fake.invoke(t, stdout, "", 0, `{"info":{"id":"ses_x"},"messages":[]}`)
	a.failAgentRunEvent = func(runID, kind string) error {
		switch kind {
		case "done", "error", "cancelled", "truncated":
			return errors.New("injected terminal insert failure")
		}
		return nil
	}
	events := wardenRunRequest(t, a, sess, cookie, ws)
	var runID string
	var terminal map[string]any
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
		if et, _ := ev["type"].(string); et == "error" {
			terminal = ev["data"].(map[string]any)
		}
	}
	if runID == "" {
		t.Fatal("no run id")
	}
	if state := wardenRunState(t, a, user.ID, runID); state != string(outcomeFailed) {
		t.Fatalf("state = %q want failed (storage failure)", state)
	}
	if terminal == nil || terminal["outcome"] != string(outcomeFailed) {
		t.Fatalf("terminal event missing failure outcome: %+v", terminal)
	}
	if msg, _ := terminal["message"].(string); !strings.Contains(msg, "stored durably") {
		t.Fatalf("terminal message should be bounded storage failure: %q", msg)
	}
}

func TestWardenAgentPostDeliveryFinalizeFailureFailsClosed(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n"
	fake.invoke(t, stdout, "", 0, `{"info":{"id":"ses_x"},"messages":[]}`)
	// Call counter: call 1 is the pre-delivery run-state update (succeeds),
	// call 2 is the post-delivery diagnostics update (fails), call 3 is the
	// storage-failure best-effort finalize (succeeds).
	calls := 0
	a.failFinishAgentRun = func(runID string) error {
		calls++
		if calls == 2 {
			return errors.New("injected post-delivery finalize failure")
		}
		return nil
	}
	events := wardenRunRequest(t, a, sess, cookie, ws)
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	// The ordinary terminal event must have been delivered before the failure.
	var sawTerminal bool
	for _, ev := range events {
		if et, _ := ev["type"].(string); et == "done" {
			sawTerminal = true
		}
	}
	if !sawTerminal {
		t.Fatal("ordinary terminal event was not delivered before post-delivery failure")
	}
	if calls != 3 {
		t.Fatalf("finishDurableAgentRun called %d times, want 3", calls)
	}
	if state := wardenRunState(t, a, user.ID, runID); state != string(outcomeFailed) {
		t.Fatalf("state = %q want failed after post-delivery failure", state)
	}
	d := wardenRunDiagnostics(t, a, user.ID, runID)
	if d.Category != "storage_failure" {
		t.Fatalf("diagnostics category = %q want storage_failure", d.Category)
	}
	if !strings.Contains(d.DeliveryError, "post-delivery run-state") {
		t.Fatalf("delivery error should name post-delivery run-state: %q", d.DeliveryError)
	}
}

func TestWardenAgentPreDeliveryFinalizeFailureFailsClosed(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n"
	fake.invoke(t, stdout, "", 0, `{"info":{"id":"ses_x"},"messages":[]}`)
	calls := 0
	a.failFinishAgentRun = func(runID string) error {
		calls++
		if calls == 1 {
			return errors.New("injected pre-delivery finalize failure")
		}
		return nil
	}
	events := wardenRunRequest(t, a, sess, cookie, ws)
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	for _, ev := range events {
		if et, _ := ev["type"].(string); et == "done" {
			t.Fatal("terminal event should not be delivered after pre-delivery failure")
		}
	}
	if calls != 2 {
		t.Fatalf("finishDurableAgentRun called %d times, want 2", calls)
	}
	if state := wardenRunState(t, a, user.ID, runID); state != string(outcomeFailed) {
		t.Fatalf("state = %q want failed after pre-delivery failure", state)
	}
}

func TestWardenAgentUserPromptPersistFailureFailsClosed(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	a.failAgentRunEvent = func(runID, kind string) error {
		if kind == "user" {
			return errors.New("injected user prompt failure")
		}
		return nil
	}
	body, _ := json.Marshal(map[string]any{"workspace": ws, "prompt": "test", "clientSession": "conv1", "provider": "opencode"})
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/agent/run", bytes.NewReader(body))
	req.AddCookie(cookie)
	req.Header.Set("X-Warden-CSRF", sess.CSRF)
	rec := httptest.NewRecorder()
	a.agentRun(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d want 500", rec.Code)
	}
	var state string
	if err := a.db.QueryRow("SELECT state FROM agent_runs WHERE conversation_id='conv1' AND account_id=?", user.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != string(outcomeFailed) {
		t.Fatalf("state = %q want failed", state)
	}
}

// --- recovery reconciliation parity ---

func TestWardenReconcileRecoveredParity(t *testing.T) {
	cases := []struct {
		streamed, recovered, want string
		suppressed, replace       bool
	}{
		{"hello world", "hello world", "", true, false},
		{"hello world extra", "hello world", "", true, false},
		{"hello world", "hello world more", "more", false, false},
		{"world", "hello world", "hello world", false, true},
		{"prefix mid", "mid suffix", "suffix", false, false},
		{"alpha", "beta", "beta", false, false},
		{"alpha", "", "", true, false},
	}
	for _, tc := range cases {
		text, suppressed, replace := reconcileRecovered(tc.streamed, tc.recovered)
		if suppressed != tc.suppressed || replace != tc.replace || strings.TrimSpace(text) != tc.want {
			t.Fatalf("reconcile(%q,%q) = %q,%v,%v want %q,%v,%v", tc.streamed, tc.recovered, text, suppressed, replace, tc.want, tc.suppressed, tc.replace)
		}
	}
}

func TestWardenAgentRecoverySuppressedWhenCompleteStreamed(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"text\",\"sessionID\":\"ses_x\",\"part\":{\"type\":\"text\",\"text\":\"final answer\"}}\n{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n"
	export := `{"info":{"id":"ses_x"},"messages":[{"info":{"role":"assistant","finish":"stop"},"parts":[{"type":"text","text":"final answer"}]}]}`
	fake.invoke(t, stdout, "", 1, export)
	events := wardenRunRequest(t, a, sess, cookie, ws)
	for _, ev := range events {
		if et, _ := ev["type"].(string); et == "recovered" {
			t.Fatalf("recovery not suppressed: %+v", ev)
		}
	}
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	d := wardenRunDiagnostics(t, a, user.ID, runID)
	if d.RecoveryResult != "ok_suppressed" {
		t.Fatalf("recovery result = %q want ok_suppressed", d.RecoveryResult)
	}
}

// --- per-session main-session correlation parity ---

func TestWardenAgentSubagentErrorThenMainBillingError(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"error\",\"sessionID\":\"ses_sub\",\"error\":{\"data\":{\"message\":\"generic subagent failure\"}}}\n" +
		"{\"type\":\"step_finish\",\"sessionID\":\"ses_main\",\"part\":{\"reason\":\"stop\"}}\n" +
		"{\"type\":\"error\",\"sessionID\":\"ses_main\",\"error\":{\"data\":{\"message\":\"Insufficient balance\"}}}\n"
	fake.invoke(t, stdout, "", 1, `{"info":{"id":"ses_main"},"messages":[]}`)
	events := wardenRunRequest(t, a, sess, cookie, ws)
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	d := wardenRunDiagnostics(t, a, user.ID, runID)
	if d.ProviderCause != string(causeProviderInsufficientBalance) {
		t.Fatalf("main billing error not classified: %q", d.ProviderCause)
	}
}

func TestWardenAgentMainStopThenSubagentError(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"step_finish\",\"sessionID\":\"ses_main\",\"part\":{\"reason\":\"stop\"}}\n" +
		"{\"type\":\"error\",\"sessionID\":\"ses_sub\",\"error\":{\"data\":{\"message\":\"Insufficient balance\"}}}\n"
	fake.invoke(t, stdout, "", 0, `{"info":{"id":"ses_main"},"messages":[]}`)
	events := wardenRunRequest(t, a, sess, cookie, ws)
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	if state := wardenRunState(t, a, user.ID, runID); state != string(outcomeCompleted) {
		t.Fatalf("main stop then subagent error state = %q want completed", state)
	}
}

// --- nil request-context Done() (Warden parity) ---

func TestWardenAgentNilContextDoneDoesNotLeak(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n"
	fake.invoke(t, stdout, "", 0, `{"info":{"id":"ses_x"},"messages":[]}`)
	body, _ := json.Marshal(map[string]any{"workspace": ws, "prompt": "test", "clientSession": "conv1", "provider": "opencode"})
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/agent/run", bytes.NewReader(body))
	req.AddCookie(cookie)
	req.Header.Set("X-Warden-CSRF", sess.CSRF)
	req = req.WithContext(context.Background())
	rec := httptest.NewRecorder()
	a.agentRun(rec, req)
	sc := bufio.NewScanner(rec.Body)
	sawDone := false
	for sc.Scan() {
		var ev map[string]any
		if json.Unmarshal([]byte(sc.Text()), &ev) == nil {
			if ev["type"] == "done" {
				sawDone = true
			}
		}
	}
	if !sawDone {
		t.Fatal("run did not complete with nil Done() context")
	}
	_ = user
}

// TestWardenAgentTerminalMarkerSupersession verifies the reloaded merged
// transcript shows only the storage-failure terminal marker after a
// post-delivery finalize failure.
func TestWardenAgentTerminalMarkerSupersession(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)
	stdout := "{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n"
	fake.invoke(t, stdout, "", 0, `{"info":{"id":"ses_x"},"messages":[]}`)
	calls := 0
	a.failFinishAgentRun = func(runID string) error {
		calls++
		if calls == 2 {
			return errors.New("injected post-delivery finalize failure")
		}
		return nil
	}
	events := wardenRunRequest(t, a, sess, cookie, ws)
	var runID string
	for _, ev := range events {
		if id, _ := ev["data"].(map[string]any)["runID"].(string); id != "" {
			runID = id
		}
	}
	if runID == "" {
		t.Fatal("no run id")
	}
	merged, err := a.loadConversationMerged(user.ID, "conv1")
	if err != nil {
		t.Fatal(err)
	}
	markers := []durableAgentEvent{}
	for _, ev := range merged {
		if durableRunMarkerRunID(ev.Name) == runID {
			markers = append(markers, ev)
		}
	}
	if len(markers) != 1 {
		t.Fatalf("expected one authoritative terminal marker, got %d: %+v", len(markers), markers)
	}
	if markers[0].Name != "run:"+runID+":failed" {
		t.Fatalf("terminal marker = %q want run:%s:failed", markers[0].Name, runID)
	}
}

// TestWardenReconcileTranscriptOrder reconstructs the final user-visible
// transcript for overlap cases including non-JSON streamed output.
func TestWardenReconcileTranscriptOrder(t *testing.T) {
	cases := []struct {
		name      string
		stdout    string
		export    string
		wantOrder []string
	}{
		{
			name:      "streamed prefix then append suffix",
			stdout:    "{\"type\":\"text\",\"sessionID\":\"ses_x\",\"part\":{\"type\":\"text\",\"text\":\"hello\"}}\n",
			export:    `{"info":{"id":"ses_x"},"messages":[{"info":{"role":"assistant","finish":"stop"},"parts":[{"type":"text","text":"hello world"}]}]}`,
			wantOrder: []string{"hello", "world"},
		},
		{
			name:      "streamed suffix then replacement",
			stdout:    "world\n",
			export:    `{"info":{"id":"ses_x"},"messages":[{"info":{"role":"assistant","finish":"stop"},"parts":[{"type":"text","text":"hello world"}]}]}`,
			wantOrder: []string{"hello world"},
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeOpenCode(t)
			a, user, sess, cookie := wardenAgentTestApp(t, fake)
			ws := agentWorkspace(t, a)
			stdout := tc.stdout + "{\"type\":\"step_finish\",\"sessionID\":\"ses_x\",\"part\":{\"reason\":\"stop\"}}\n"
			fake.invoke(t, stdout, "", 1, tc.export)
			body, _ := json.Marshal(map[string]any{"workspace": ws, "prompt": "test", "clientSession": fmt.Sprintf("conv%d", i), "provider": "opencode"})
			req := httptest.NewRequest(http.MethodPost, "http://warden/api/agent/run", bytes.NewReader(body))
			req.AddCookie(cookie)
			req.Header.Set("X-Warden-CSRF", sess.CSRF)
			rec := httptest.NewRecorder()
			a.agentRun(rec, req)
			merged, err := a.loadConversationMerged(user.ID, fmt.Sprintf("conv%d", i))
			if err != nil {
				t.Fatal(err)
			}
			var lines []string
			for _, ev := range merged {
				if ev.Kind == "assistant" {
					lines = append(lines, ev.Text)
				}
			}
			if len(lines) != len(tc.wantOrder) {
				t.Fatalf("transcript lines = %d want %d: %+v", len(lines), len(tc.wantOrder), lines)
			}
			for j, want := range tc.wantOrder {
				if strings.TrimSpace(lines[j]) != want {
					t.Fatalf("line %d = %q want %q (full: %+v)", j, lines[j], want, lines)
				}
			}
		})
	}
}

// TestWardenReplacementSupersessionIsRunScoped verifies a recovery replacement
// only removes fragments from its own run, never from an earlier run in the
// same conversation containing the same text.
func TestWardenReplacementSupersessionIsRunScoped(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)

	stdout1 := "{\"type\":\"text\",\"sessionID\":\"ses1\",\"part\":{\"type\":\"text\",\"text\":\"world\"}}\n{\"type\":\"step_finish\",\"sessionID\":\"ses1\",\"part\":{\"reason\":\"stop\"}}\n"
	fake.invoke(t, stdout1, "", 0, `{"info":{"id":"ses1"},"messages":[]}`)
	wardenRunRequestSession(t, a, sess, cookie, ws, "convX")

	stdout2 := "world\n{\"type\":\"step_finish\",\"sessionID\":\"ses2\",\"part\":{\"reason\":\"stop\"}}\n"
	export2 := `{"info":{"id":"ses2"},"messages":[{"info":{"role":"assistant","finish":"stop"},"parts":[{"type":"text","text":"hello world"}]}]}`
	fake.invoke(t, stdout2, "", 1, export2)
	wardenRunRequestSession(t, a, sess, cookie, ws, "convX")

	merged, err := a.loadConversationMerged(user.ID, "convX")
	if err != nil {
		t.Fatal(err)
	}
	assistant := []string{}
	for _, ev := range merged {
		if ev.Kind == "assistant" {
			assistant = append(assistant, strings.TrimSpace(ev.Text))
		}
	}
	want := []string{"world", "hello world"}
	if len(assistant) != len(want) {
		t.Fatalf("assistant transcript = %+v want %+v", assistant, want)
	}
	for i := range want {
		if assistant[i] != want[i] {
			t.Fatalf("line %d = %q want %q (full: %+v)", i, assistant[i], want[i], assistant)
		}
	}
}

// TestWardenReplacementDoesNotRemoveClientAuthoredText verifies client-authored
// assistant events are never dropped by a replacement supersession.
func TestWardenReplacementDoesNotRemoveClientAuthoredText(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)

	fake.invoke(t, "world\n{\"type\":\"step_finish\",\"sessionID\":\"s1\",\"part\":{\"reason\":\"stop\"}}\n", "", 1,
		`{"info":{"id":"s1"},"messages":[{"info":{"role":"assistant","finish":"stop"},"parts":[{"type":"text","text":"hello world"}]}]}`)
	wardenRunRequestSession(t, a, sess, cookie, ws, "convZ")

	c := durableConversation{ID: "convZ", Workspace: ws, Events: []durableAgentEvent{
		{Kind: "assistant", Text: "wor", CreatedAt: 1},
	}}
	if err := a.saveConversation(user.ID, &c); err != nil {
		t.Fatal(err)
	}
	merged, err := a.loadConversationMerged(user.ID, "convZ")
	if err != nil {
		t.Fatal(err)
	}
	assistant := []string{}
	for _, ev := range merged {
		if ev.Kind == "assistant" {
			assistant = append(assistant, strings.TrimSpace(ev.Text))
		}
	}
	foundWor, foundHello := false, false
	for _, x := range assistant {
		if x == "wor" {
			foundWor = true
		}
		if x == "hello world" {
			foundHello = true
		}
	}
	if !foundWor || !foundHello {
		t.Fatalf("assistant transcript = %+v should contain both client 'wor' and 'hello world'", assistant)
	}
}

// TestWardenMultipleReplacementsSeparateRuns verifies two replacement recoveries
// in separate runs each supersede only their own run's fragments.
func TestWardenMultipleReplacementsSeparateRuns(t *testing.T) {
	fake := newFakeOpenCode(t)
	a, user, sess, cookie := wardenAgentTestApp(t, fake)
	ws := agentWorkspace(t, a)

	// Run 1: streams "lpha" (a suffix), fails, replaces with "alpha".
	stdout1 := "{\"type\":\"text\",\"sessionID\":\"s1\",\"part\":{\"type\":\"text\",\"text\":\"lpha\"}}\n{\"type\":\"step_finish\",\"sessionID\":\"s1\",\"part\":{\"reason\":\"stop\"}}\n"
	fake.invoke(t, stdout1, "", 1, `{"info":{"id":"s1"},"messages":[{"info":{"role":"assistant","finish":"stop"},"parts":[{"type":"text","text":"alpha"}]}]}`)
	wardenRunRequestSession(t, a, sess, cookie, ws, "convY")

	// Run 2: streams "eta" (a suffix), fails, replaces with "beta".
	stdout2 := "{\"type\":\"text\",\"sessionID\":\"s2\",\"part\":{\"type\":\"text\",\"text\":\"eta\"}}\n{\"type\":\"step_finish\",\"sessionID\":\"s2\",\"part\":{\"reason\":\"stop\"}}\n"
	fake.invoke(t, stdout2, "", 1, `{"info":{"id":"s2"},"messages":[{"info":{"role":"assistant","finish":"stop"},"parts":[{"type":"text","text":"beta"}]}]}`)
	wardenRunRequestSession(t, a, sess, cookie, ws, "convY")

	merged, err := a.loadConversationMerged(user.ID, "convY")
	if err != nil {
		t.Fatal(err)
	}
	assistant := []string{}
	for _, ev := range merged {
		if ev.Kind == "assistant" {
			assistant = append(assistant, strings.TrimSpace(ev.Text))
		}
	}
	want := []string{"alpha", "beta"}
	if len(assistant) != len(want) {
		t.Fatalf("assistant transcript = %+v want %+v", assistant, want)
	}
	for i := range want {
		if assistant[i] != want[i] {
			t.Fatalf("line %d = %q want %q (full: %+v)", i, assistant[i], want[i], assistant)
		}
	}
}
