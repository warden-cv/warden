package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxImageCount = 6
	maxImageBytes = 10 << 20
	maxRunBytes   = 96 << 20

	// Provider output limits matching Cortex so Warden can classify a run as
	// truncated rather than a generic disconnect.
	maxProviderLine   = 1 << 20
	maxProviderBytes  = 32 << 20
	maxProviderEvents = 4096
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

// sessionEvidence collects per-session activity, terminal and error evidence
// during the stdout stream so the authoritative main session can be resolved
// after the loop.
type sessionEvidence struct {
	firstSeen   uint64
	hasActivity bool
	lastReason  string
	stopObs     uint64
	// stopSeq captures the valid-completion observation in the same runState
	// sequence used by firstErrSeq, so the error-vs-completion ordering is
	// comparable after the main session is resolved.
	stopSeq       uint64
	firstErrSeq   uint64
	errMsg        string
	errCode       string
	errStatus     int
	errBillingURL string
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
	runID := token(18)
	run := newActiveRun(sess.AccountID, cancel)
	defer run.finished()

	// Durable creation precedes process start so an untracked OpenCode process
	// is never launched if persistence fails. Once the durable row exists,
	// every later failure finalizes it.
	if err := a.startDurableAgentRun(runID, sess.AccountID, clientSession, q.Prompt, q.Workspace, providerID, model); err != nil {
		if strings.Contains(err.Error(), "already running") {
			http.Error(w, "agent is already running for this conversation", http.StatusConflict)
		} else {
			http.Error(w, "persist agent run: "+err.Error(), 500)
		}
		return
	}
	// The user prompt is persisted immediately after the durable run, at
	// sequence zero, before the process starts; provider events begin at one.
	seq := int64(0)
	if err := a.persistAgentRunEvent(sess.AccountID, runID, clientSession, "user", q.Prompt, "", seq, time.Now().UnixMilli()); err != nil {
		a.finishRunChecked(runID, sess.AccountID, clientSession, "failed", "persist user prompt: "+err.Error(), 0, 0, 0, "")
		http.Error(w, "persist user prompt: "+err.Error(), 500)
		return
	}
	seq++
	a.runMu.Lock()
	a.activeRuns[runID] = run
	a.runMu.Unlock()
	defer func() { a.runMu.Lock(); delete(a.activeRuns, runID); a.runMu.Unlock() }()

	imageFiles := []string{}
	imageDir := ""
	if len(q.Images) > 0 {
		var err error
		imageDir, imageFiles, err = writeImageAttachments(q.Images)
		if err != nil {
			run.state.recordCause(causeRequestCanceled)
			a.finishRunChecked(runID, sess.AccountID, clientSession, "failed", "invalid image: "+err.Error(), 0, 0, 0, "")
			http.Error(w, "invalid image: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer os.RemoveAll(imageDir)
	}
	args := agentRunArgs(workspace, modelRef, q.Session, imageFiles, q.Prompt)
	cmd := exec.CommandContext(ctx, binary, args...)
	configureAgentProcess(cmd)
	cmd.Dir = workspace
	env := agentSubprocessEnv(os.Environ(), configDir, dataDir, key, runtime.NeedsKey, a.config.environmentFor(sess.AccountID))
	cmd.Env = env
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		run.state.recordCause(causeRequestCanceled)
		a.finishRunChecked(runID, sess.AccountID, clientSession, "failed", "stdout pipe: "+err.Error(), 0, 0, 0, "")
		http.Error(w, err.Error(), 500)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		run.state.recordCause(causeRequestCanceled)
		a.finishRunChecked(runID, sess.AccountID, clientSession, "failed", "stderr pipe: "+err.Error(), 0, 0, 0, "")
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	flusher, ok := w.(http.Flusher)
	if !ok {
		run.state.recordCause(causeRequestCanceled)
		a.finishRunChecked(runID, sess.AccountID, clientSession, "failed", "streaming unavailable", 0, 0, 0, "")
		http.Error(w, "streaming unavailable", 500)
		return
	}
	a.auditEvent(r, "agent_run_start", "provider="+providerID+" credential="+source+" workspace="+q.Workspace)
	if err := cmd.Start(); err != nil {
		run.state.seal()
		diag, summary := a.runDiagnostics(outcomeFailed, run.state.snapshot(), "", false, processExitStatus(cmd), nil, nil, "", false, 0, true, nil, map[string]string{"result": "not_attempted"}, causeNone, "", providerID, model)
		a.finishRunChecked(runID, sess.AccountID, clientSession, "failed", summary, 0, 0, 0, diag)
		_ = writeAgentEvent(w, flusher, "error", map[string]any{"message": summary, "outcome": string(outcomeFailed)})
		a.auditEvent(r, "agent_run_finish", "status=failed workspace="+q.Workspace)
		return
	}

	// Expose the run ID before any assistant event.
	var deliveryErr error
	if err := writeAgentEvent(w, flusher, "run", map[string]any{"runID": runID}); err != nil {
		deliveryErr = err
	}

	// Record request/browser disconnection as a cancellation cause.
	// Guard against a nil Done() channel (background contexts in tests or
	// internal callers), where receiving would block forever.
	if requestDone := r.Context().Done(); requestDone != nil {
		go func() {
			<-requestDone
			run.state.recordCause(causeRequestCanceled)
			cancel()
		}()
	}

	tail := captureTail(stderr, 64<<10)
	var inputTokens, outputTokens uint64
	var cost float64
	sessionID := ""
	// Per-session evidence collected during the stream and resolved after the
	// loop so the authoritative main session is not assumed from the first
	// session seen.
	sessions := map[string]*sessionEvidence{}
	validStop := false
	// streamedAssistant accumulates the assistant text durably persisted for
	// the run, used by recovery reconciliation to avoid duplicating content.
	streamedAssistant := ""
	persistFailed := false
	var persistErr string
	var stdoutScanErr error
	truncated := false
	scan := bufio.NewScanner(stdout)
	scan.Buffer(make([]byte, 64<<10), maxProviderLine)
	streamBytes, streamEvents := 0, 0
	obs := uint64(0)
	for scan.Scan() {
		line := append([]byte(nil), scan.Bytes()...)
		streamBytes += len(line)
		streamEvents++
		if streamBytes > maxProviderBytes || streamEvents > maxProviderEvents {
			truncated = true
			run.state.recordCause(causeOutputLimit)
			cancel()
			break
		}
		var raw map[string]any
		if json.Unmarshal(line, &raw) == nil {
			obs++
			collectAgentUsage(raw, &inputTokens, &outputTokens, &cost)
			typ, _ := raw["type"].(string)
			id, _ := raw["sessionID"].(string)
			if !validAgentSessionID(id) {
				id = ""
			}
			// Activity and step_finish terminal evidence are recorded per
			// session.
			if typ == "step_start" || typ == "step_finish" || typ == "text" || typ == "tool_use" || typ == "reasoning" {
				if id != "" {
					ev := sessions[id]
					if ev == nil {
						ev = &sessionEvidence{firstSeen: obs}
						sessions[id] = ev
					}
					ev.hasActivity = true
					if typ == "step_finish" {
						if reason, _ := raw["part"].(map[string]any)["reason"].(string); reason != "" {
							ev.lastReason = reason
							// stopObs/stopSeq are genuine completion evidence
							// only for reason=="stop": non-terminal step_finish
							// reasons must never be treated as valid completion
							// by the error-ordering classifier.
							if reason == "stop" {
								ev.stopObs = obs
								// Valid-completion evidence is captured in the
								// same observation sequence as errors so the
								// classifier can order error-before-stop vs
								// error-after-stop.
								ev.stopSeq = run.state.nextSeq()
							}
						}
					}
				}
			}
			// Capture the first error per session with its chronological seq.
			if typ == "error" && id != "" {
				ev := sessions[id]
				if ev == nil {
					ev = &sessionEvidence{firstSeen: obs}
					sessions[id] = ev
				}
				if ev.firstErrSeq == 0 {
					ev.firstErrSeq = run.state.nextSeq()
					ev.errMsg = sanitizeAgentDiagnostic(errorEventText(raw), key)
					ev.errCode, ev.errStatus = providerErrorMeta(raw)
					ev.errBillingURL = sanitizeBillingURL(extractBillingURL(ev.errMsg))
				}
			}
			// Persist normalized server-owned events before delivery so a
			// disconnect cannot lose the transcript. Error events are excluded
			// here: their session is resolved only after the stream ends, and a
			// post-completion error must never survive as a raw Error block.
			kind, text, name := normalizedEvent(raw)
			if kind != "" && kind != "error" {
				if err := a.persistAgentRunEvent(sess.AccountID, runID, clientSession, kind, sanitizeAgentDiagnostic(text, key), name, seq, time.Now().UnixMilli()); err != nil {
					persistFailed = true
					persistErr = err.Error()
					cancel()
					break
				}
				if kind == "assistant" {
					streamedAssistant = strings.TrimSpace(streamedAssistant + "\n" + text)
				}
				seq++
			}
			// A valid todowrite snapshot is persisted as its own authoritative
			// task event so the task panel restores after reload, and streamed
			// as a normalized server-owned task event so the live panel opens
			// without waiting for terminal completion.
			if tasks := taskSnapshot(raw, key); tasks != "" {
				if err := a.persistAgentRunEvent(sess.AccountID, runID, clientSession, "task", tasks, "", seq, time.Now().UnixMilli()); err != nil {
					persistFailed = true
					persistErr = err.Error()
					cancel()
					break
				}
				seq++
				if err := writeAgentEvent(w, flusher, "task", map[string]any{"snapshot": tasks, "sessionID": sessionID}); err != nil {
					deliveryErr = err
				}
			}
			rewriteAgentImageURLs(raw, clientSession)
			if err := writeAgentEvent(w, flusher, "opencode", sanitizeAgentProviderValue(raw, key, 0)); err != nil {
				deliveryErr = err
			}
		} else {
			lineText := strings.TrimSpace(string(line))
			if lineText != "" {
				if err := a.persistAgentRunEvent(sess.AccountID, runID, clientSession, "assistant", sanitizeAgentDiagnostic(lineText, key), "", seq, time.Now().UnixMilli()); err != nil {
					persistFailed = true
					persistErr = err.Error()
					cancel()
					break
				}
				streamedAssistant = strings.TrimSpace(streamedAssistant + "\n" + lineText)
				seq++
			}
			if err := writeAgentEvent(w, flusher, "output", map[string]any{"text": string(line)}); err != nil {
				deliveryErr = err
			}
		}
	}
	if err := scan.Err(); err != nil {
		stdoutScanErr = err
		if !truncated {
			cancel()
		}
	}
	// Resolve the authoritative main session from per-session evidence: latest
	// terminal stop, else most active, else first-error prompt-start.
	mainSessionID := ""
	var mainEv *sessionEvidence
	for sid, ev := range sessions {
		if ev == nil {
			continue
		}
		if ev.lastReason == "stop" {
			if mainEv == nil || ev.stopObs > mainEv.stopObs {
				mainSessionID, mainEv = sid, ev
			}
			continue
		}
		if mainEv == nil {
			mainSessionID, mainEv = sid, ev
		} else if mainEv.lastReason != "stop" && ev.hasActivity && ev.firstSeen > mainEv.firstSeen {
			mainSessionID, mainEv = sid, ev
		}
	}
	sessionID = mainSessionID
	// Promote the main session's error evidence only.
	var stdoutErrMsg string
	stdoutErr := false
	var providerCause runCause
	var billingURL string
	postCompletionErr := false
	if mainEv != nil {
		if mainEv.stopSeq != 0 {
			run.state.recordStopAt(mainEv.stopSeq)
		}
		if mainEv.firstErrSeq != 0 {
			stdoutErr = true
			run.state.recordErrorAt(mainEv.firstErrSeq)
			stdoutErrMsg = mainEv.errMsg
			if classifyProviderError(mainEv.errMsg, mainEv.errCode, mainEv.errStatus) {
				providerCause = causeProviderInsufficientBalance
				run.state.recordProviderFailureAt(mainEv.firstErrSeq)
				billingURL = mainEv.errBillingURL
			}
			// An error observed after the main session's step_finish is
			// post-completion evidence: it is not failure of the answer.
			postCompletionErr = mainEv.stopSeq != 0 && mainEv.firstErrSeq > mainEv.stopSeq
		}
	}
	if mainEv != nil {
		validStop = mainEv.lastReason == "stop"
	}
	waitErr := cmd.Wait()
	run.state.seal()
	tail.wait()
	stderrText := tail.String()
	stderrTrunc := tail.truncated()
	if stdoutScanErr != nil && waitErr == nil {
		waitErr = stdoutScanErr
	}
	exit := processExitStatus(cmd)
	snap := run.state.snapshot()
	outcome := classifyRun(snap, stdoutErr, validStop, exit, providerCause)
	if persistFailed {
		outcome = outcomeFailed
		stdoutErrMsg = "agent transcript persistence failed: " + persistErr
	}
	// Persist a pre-completion main-session error as a transcript error event.
	// A post-completion error is retained only as a diagnostic warning and must
	// not survive as a separate raw Error block beside the final warning.
	if stdoutErr && !postCompletionErr && stdoutErrMsg != "" {
		if err := a.persistAgentRunEvent(sess.AccountID, runID, clientSession, "error", sanitizeAgentDiagnostic(stdoutErrMsg, key), "", seq, time.Now().UnixMilli()); err != nil {
			persistFailed = true
			persistErr = err.Error()
			if !truncated {
				cancel()
			}
			outcome = outcomeFailed
			stdoutErrMsg = "agent transcript persistence failed: " + persistErr
		} else {
			seq++
		}
	}

	// Recovery reconciles with persisted content: it only runs for genuine
	// failures, skips known local causes, and never runs after a persistence
	// failure or truncation.
	recoveryResult := ""
	if outcome == outcomeFailed || outcome == outcomeCompletedWError {
		if !persistFailed && !truncated && snap.cause != causeRequestCanceled && snap.cause != causeUserStop && snap.cause != causeOutputLimit {
			if sessionID != "" {
				recCtx, recCancel := context.WithTimeout(context.Background(), 30*time.Second)
				recovered, images, usageIn, usageOut, recoveredCost, recoverErr := recoverOpenCodeSession(recCtx, binary, sessionID, workspace, clientSession, env)
				recCancel()
				if recoverErr != nil {
					recoveryResult = "failed"
				} else {
					recovered = strings.TrimSpace(recovered)
					// Reconcile against the assistant text already durably
					// streamed: only the missing portion is persisted, and
					// recovery is suppressed when the complete response is
					// already present. Replacement cases persist the full
					// response under a replacement marker.
					text, suppressed, replace := reconcileRecovered(streamedAssistant, recovered)
					recoveryName := "recovered"
					if replace {
						recoveryName = "repl:" + runID
					}
					if suppressed {
						recoveryResult = "ok_suppressed"
					} else if text == "" {
						recoveryResult = "ok_empty"
					} else {
						if err := a.persistAgentRunEvent(sess.AccountID, runID, clientSession, "assistant", sanitizeAgentDiagnostic(text, key), recoveryName, seq, time.Now().UnixMilli()); err != nil {
							recoveryResult = "persist_failed"
						} else {
							seq++
							recoveryResult = "ok"
							if err := writeAgentEvent(w, flusher, "recovered", map[string]any{"text": sanitizeAgentDiagnostic(text, key), "sessionID": sessionID, "recovered": true}); err != nil {
								deliveryErr = err
							}
						}
					}
					for _, im := range images {
						url := sanitizeImageURL(im["url"])
						if url == "" {
							continue
						}
						if err := a.persistAgentRunEvent(sess.AccountID, runID, clientSession, "image", sanitizeAgentDiagnostic(url, key), im["name"], seq, time.Now().UnixMilli()); err != nil {
							recoveryResult = "persist_failed"
							break
						}
						seq++
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
					if len(images) > 0 && recoveryResult == "ok" {
						if err := writeAgentEvent(w, flusher, "recovered-images", map[string]any{"images": images, "sessionID": sessionID}); err != nil {
							deliveryErr = err
						}
					}
				}
			} else {
				recoveryResult = "no_session"
			}
		}
	}
	_ = a.aiUsage.record(sess.AccountID, providerID, inputTokens, outputTokens, cost)

	// Determine and persist the execution outcome before terminal delivery.
	stderrErrors, stderrWarnings := parsedStderr(sanitizeAgentDiagnostic(stderrText, key))
	diag, summary := a.runDiagnostics(outcome, snap, stdoutErrMsg, validStop, exit, stderrErrors, stderrWarnings, sanitizeAgentDiagnostic(stderrText, key), stderrTrunc, seq, false, stdoutScanErr, map[string]string{"result": recoveryResult}, providerCause, billingURL, providerID, model)
	// The terminal event carries the run identity and outcome so technical
	// details survive reload: name = "run:<runID>:<outcome>". Persistence is
	// checked: a storage failure must never claim a durable completion.
	if err := a.persistAgentRunEvent(sess.AccountID, runID, clientSession, terminalKind(outcome), summary, "run:"+runID+":"+string(outcome), seq, time.Now().UnixMilli()); err != nil {
		a.storageFailure(runID, sess.AccountID, clientSession, sessionID, "terminal event", err, inputTokens, outputTokens, cost, w, flusher, key, seq)
		return
	}
	seq++
	if err := a.finishDurableAgentRun(runID, sess.AccountID, clientSession, string(outcome), sessionID, summary, inputTokens, outputTokens, cost, diag); err != nil {
		a.storageFailure(runID, sess.AccountID, clientSession, sessionID, "run-state", err, inputTokens, outputTokens, cost, w, flusher, key, seq)
		return
	}

	// Terminal delivery is attempted only when the stream is still writable;
	// the delivery outcome is captured from the actual write result.
	terminalDelivered := false
	var terminalDeliveryErr error
	if deliveryErr == nil {
		var payload map[string]any
		switch outcome {
		case outcomeCompleted:
			payload = map[string]any{"inputTokens": inputTokens, "outputTokens": outputTokens, "estimatedCostUsd": cost, "sessionID": sessionID, "outcome": string(outcomeCompleted), "runId": runID}
		case outcomeCompletedWError:
			payload = map[string]any{"message": summary, "exitCode": exit.exitCode, "signal": exit.signal, "outcome": string(outcomeCompletedWError), "runId": runID}
		case outcomeFailed:
			payload = map[string]any{"message": summary, "exitCode": exit.exitCode, "signal": exit.signal, "outcome": string(outcomeFailed), "runId": runID}
			if providerCause == causeProviderInsufficientBalance {
				payload["cause"] = string(causeProviderInsufficientBalance)
				payload["billingUrl"] = billingURL
			}
		case outcomeCancelled:
			payload = map[string]any{"message": "Agent stopped.", "outcome": string(outcomeCancelled), "runId": runID}
		case outcomeTruncated:
			payload = map[string]any{"message": "Provider output limit reached; the run was stopped.", "outcome": string(outcomeTruncated), "runId": runID}
		case outcomeInterrupted:
			payload = map[string]any{"message": "The agent was interrupted.", "outcome": string(outcomeInterrupted), "runId": runID}
		}
		var termErr error
		switch outcome {
		case outcomeCompleted:
			termErr = writeAgentEvent(w, flusher, "done", payload)
		case outcomeCompletedWError:
			termErr = writeAgentEvent(w, flusher, "warning", payload)
		case outcomeFailed:
			termErr = writeAgentEvent(w, flusher, "error", payload)
		case outcomeCancelled:
			termErr = writeAgentEvent(w, flusher, "cancelled", payload)
		case outcomeTruncated:
			termErr = writeAgentEvent(w, flusher, "truncated", payload)
		case outcomeInterrupted:
			termErr = writeAgentEvent(w, flusher, "cancelled", payload)
		}
		if termErr == nil {
			terminalDelivered = true
		} else {
			terminalDeliveryErr = termErr
		}
	} else {
		terminalDeliveryErr = deliveryErr
	}

	// Delivery diagnostics are recorded after the attempt; a delivery failure
	// never changes the execution outcome.
	diag2, summary2 := a.runDiagnostics(outcome, snap, stdoutErrMsg, validStop, exit, stderrErrors, stderrWarnings, sanitizeAgentDiagnostic(stderrText, key), stderrTrunc, seq, terminalDelivered, stdoutScanErr, map[string]string{"result": recoveryResult}, providerCause, billingURL, providerID, model)
	if terminalDeliveryErr != nil {
		var d diagnostics
		_ = json.Unmarshal([]byte(diag2), &d)
		d.DeliveryError = sanitizeAgentDiagnostic(terminalDeliveryErr.Error(), key)
		d.TerminalEventDeliver = false
		if b, err := json.Marshal(d); err == nil {
			diag2 = string(b)
		}
	}
	if err := a.finishDurableAgentRun(runID, sess.AccountID, clientSession, string(outcome), sessionID, summary2, inputTokens, outputTokens, cost, diag2); err != nil {
		a.storageFailure(runID, sess.AccountID, clientSession, sessionID, "post-delivery run-state", err, inputTokens, outputTokens, cost, w, flusher, key, seq)
	}
	// Audit records the exact outcome rather than a generic success/error.
	a.auditEvent(r, "agent_run_finish", "status="+string(outcome)+" workspace="+q.Workspace)
}

// storageFailure handles a terminal persistence failure: it logs at ERROR with
// the run ID, best-effort updates the durable run to a storage-failure outcome,
// and emits a bounded client-facing failure if the stream is still writable.
func (a *app) storageFailure(runID, accountID, clientSession, sessionID, stage string, err error, input, output uint64, cost float64, w http.ResponseWriter, f http.Flusher, key string, seq int64) {
	log.Printf("warden agent run %s: %s persistence failed: %v", runID, stage, err)
	summary := "The agent result could not be stored durably."
	d := diagnostics{
		Outcome:       string(outcomeFailed),
		Category:      "storage_failure",
		Summary:       summary,
		DeliveryError: stage + ": persistence failed: " + err.Error(),
	}
	diag, _ := json.Marshal(d)
	// Terminal-event supersession: append a sequenced storage-failure terminal
	// marker so the merged transcript/UI treats it as the authoritative final
	// outcome, superseding any earlier durable marker. The run row and
	// diagnostics remain the fallback if this insert also fails.
	if err := a.persistAgentRunEvent(accountID, runID, clientSession, "error", summary, "run:"+runID+":failed", seq+1, time.Now().UnixMilli()); err != nil {
		log.Printf("warden agent run %s: storage-failure terminal marker insert failed: %v", runID, err)
	}
	if ferr := a.finishDurableAgentRun(runID, accountID, clientSession, string(outcomeFailed), sessionID, summary, input, output, cost, string(diag)); ferr != nil {
		log.Printf("warden agent run %s: storage-failure finalization also failed: %v", runID, ferr)
	}
	if w != nil && f != nil {
		_ = writeAgentEvent(w, f, "error", map[string]any{"message": summary, "outcome": string(outcomeFailed), "runId": runID})
	}
}

// runDiagnostics builds the bounded, redacted diagnostic record and the
// user-facing summary for a run outcome.
func (a *app) runDiagnostics(outcome runOutcome, snap runStateSnapshot, stdoutErrMsg string, validStop bool, exit exitStatus, stderrErrors, stderrWarnings []string, stderrTail string, stderrTrunc bool, seq int64, delivered bool, scannerErr error, recovery map[string]string, providerCause runCause, billingURL, provider, model string) (string, string) {
	d := diagnostics{
		Outcome:              string(outcome),
		ExitCode:             exit.exitCode,
		Signal:               exit.signal,
		Cause:                string(snap.cause),
		StdoutError:          stdoutErrMsg,
		Errors:               boundedStrings(stderrErrors, 8),
		Warnings:             boundedStrings(stderrWarnings, 8),
		StderrTail:           boundedTail(stderrTail, 8<<10),
		StderrTruncated:      stderrTrunc,
		TerminalEventDeliver: delivered,
		OpenCodeVersion:      openCodeVersion(),
		Provider:             provider,
		Model:                model,
		ProviderCause:        string(providerCause),
		BillingURL:           billingURL,
	}
	if providerCause == causeProviderInsufficientBalance {
		d.Category = "provider_insufficient_balance"
		d.Summary, _ = insufficientBalanceMessage(billingURL)
	} else if snap.cause == causeUserStop {
		d.Category = "user_stop"
		d.Summary = "Agent stopped."
	} else if snap.cause == causeRequestCanceled {
		d.Category = "request_cancelled"
		d.Summary = "Agent connection closed; the run was stopped."
	} else if snap.cause == causeOutputLimit {
		d.Category = "output_limit"
		d.Summary = "Provider output limit reached; the run was stopped."
	} else if snap.cause == causeServiceShutdown {
		d.Category = "service_shutdown"
		d.Summary = "The agent was interrupted by a service shutdown."
	} else if outcome == outcomeFailed && stdoutErrMsg != "" {
		d.Category = "opencode_error"
		d.Summary = stdoutErrMsg
	} else if exit.signaled {
		d.Category = "signal"
		d.Summary = "OpenCode was terminated by signal " + exit.signal + "."
	} else if outcome == outcomeCompletedWError {
		d.Category = "opencode_exit"
		d.Summary = "OpenCode exited with status " + strconv.Itoa(exit.exitCode) + " after completing."
		// A post-completion stdout error is honest process evidence: it is
		// retained as a warning in technical diagnostics and never shown as the
		// failure text of the produced answer.
		if stdoutErrMsg != "" {
			d.Warnings = append([]string{stdoutErrMsg}, d.Warnings...)
		}
	} else if outcome == outcomeFailed {
		d.Category = "opencode_exit"
		d.Summary = "OpenCode exited with status " + strconv.Itoa(exit.exitCode) + "."
		if scannerErr != nil {
			d.Summary = "The provider output stream failed: " + scannerErr.Error()
		}
	} else {
		d.Category = "completed"
		d.Summary = ""
	}
	if d.Category != "completed" && d.Summary == "" {
		d.Summary = "Agent failed."
	}
	if len(d.Errors) > 0 && strings.TrimSpace(d.Summary) != "" && d.Category != "opencode_error" {
		d.Summary = d.Summary + " Details: " + strings.Join(d.Errors, "; ")
	}
	if rec, ok := recovery["result"]; ok {
		d.RecoveryAttempted = rec == "ok" || rec == "failed"
		d.RecoveryResult = rec
	}
	b, _ := json.Marshal(d)
	return string(b), d.Summary
}

func errorEventText(raw map[string]any) string {
	if e, ok := raw["error"].(map[string]any); ok {
		if data, ok := e["data"].(map[string]any); ok {
			if msg, _ := data["message"].(string); msg != "" {
				return msg
			}
		}
		if name, _ := e["name"].(string); name != "" {
			return name
		}
	}
	if msg, _ := raw["message"].(string); msg != "" {
		return msg
	}
	return "OpenCode reported a provider error."
}

func terminalKind(outcome runOutcome) string {
	switch outcome {
	case outcomeCompleted:
		return "done"
	case outcomeCompletedWError:
		return "warning"
	case outcomeFailed:
		return "error"
	case outcomeCancelled, outcomeInterrupted:
		return "cancelled"
	case outcomeTruncated:
		return "truncated"
	}
	return "error"
}

func parsedStderr(text string) (errors, warnings []string) {
	for _, line := range strings.Split(text, "\n") {
		msg := strings.TrimSpace(line)
		if msg == "" {
			continue
		}
		if len(msg) > 600 {
			msg = msg[:600]
		}
		switch stderrLevel(line) {
		case "ERROR":
			if len(errors) < 8 {
				errors = append(errors, msg)
			}
		case "WARN":
			if len(warnings) < 8 {
				warnings = append(warnings, msg)
			}
		}
	}
	return errors, warnings
}

func boundedStrings(v []string, n int) []string {
	if len(v) > n {
		v = v[:n]
	}
	return v
}

func boundedTail(s string, n int) string {
	if len(s) > n {
		s = s[len(s)-n:]
	}
	return s
}

// reconcileRecovered compares recovered assistant text against the assistant
// text already durably streamed for the run, returning the missing portion to
// persist and whether recovery should be suppressed entirely (the complete
// response is already present). See Cortex equivalent for the exact policy.
func reconcileRecovered(streamed, recovered string) (text string, suppressed, replace bool) {
	s := strings.TrimSpace(streamed)
	r := strings.TrimSpace(recovered)
	if r == "" {
		return "", true, false
	}
	if s == "" {
		return r, false, false
	}
	if r == s || strings.Contains(s, r) {
		return "", true, false
	}
	if strings.HasPrefix(r, s) {
		return strings.TrimSpace(r[len(s):]), false, false
	}
	// Streamed is a suffix of recovered: a missing prefix cannot be appended
	// after the existing suffix; the full recovered response replaces it.
	if strings.HasSuffix(r, s) {
		return r, false, true
	}
	for i := len(s); i > 0; i-- {
		if strings.HasPrefix(r, s[len(s)-i:]) {
			return strings.TrimSpace(r[i:]), false, false
		}
	}
	return r, false, false
}

// sanitizeImageURL validates or rewrites an unsafe file URL before persistence.
func sanitizeImageURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	if strings.HasPrefix(u, "data:") {
		if len(u) > 10<<20 {
			return ""
		}
		return u
	}
	if !strings.HasPrefix(u, "file://") {
		return ""
	}
	p := fileURLPath(u)
	if p == "" {
		return ""
	}
	return "file://" + p
}

// taskSnapshot extracts and validates a todowrite task list from a tool_use
// event, returning a normalized JSON string (kind "task") or "" when the
// payload is not a trusted structured todowrite snapshot.
// taskSnapshot extracts and normalizes a todowrite snapshot. Each accepted
// content field is redacted through the account/provider diagnostic sanitizer
// (including the active key) before the list is marshalled, so the exact JSON
// string can be used for durable persistence, live delivery and reload without
// a separate string-level pass that could miss JSON-escaped secrets. Length
// bounds are decided before redaction so an oversized original value cannot
// become acceptable merely because redaction shortened it.
func taskSnapshot(raw map[string]any, key string) string {
	part, _ := raw["part"].(map[string]any)
	tool, _ := part["tool"].(string)
	if tool != "todowrite" {
		return ""
	}
	state, _ := part["state"].(map[string]any)
	input, _ := state["input"].(map[string]any)
	items, ok := input["todos"].([]any)
	if !ok {
		return ""
	}
	if len(items) > 100 {
		items = items[:100]
	}
	// A valid todowrite with an empty todos list is an authoritative clear
	// operation: it must reach the frontend so a stale panel is hidden rather
	// than retained.
	if len(items) == 0 {
		return "[]"
	}
	out := make([]map[string]string, 0, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		content, _ := m["content"].(string)
		content = strings.TrimSpace(content)
		// Bound the length before redaction.
		if content == "" || len(content) > 500 {
			continue
		}
		content = sanitizeAgentDiagnostic(content, key)
		status := normalizeTaskStatus(fmt.Sprint(m["status"]))
		priority := normalizeTaskPriority(fmt.Sprint(m["priority"]))
		out = append(out, map[string]string{"content": content, "status": status, "priority": priority})
	}
	if len(out) == 0 {
		return ""
	}
	b, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(b)
}

func normalizeTaskStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "completed", "done":
		return "completed"
	case "in_progress", "in-progress", "running":
		return "in_progress"
	case "pending", "":
		return "pending"
	default:
		return "pending"
	}
}

func normalizeTaskPriority(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return "high"
	case "medium", "normal":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

// normalizedEvent maps an OpenCode stdout event to the server-owned
// conversation event kind/text/name that mirrors what the frontend renders.
func normalizedEvent(raw map[string]any) (kind, text, name string) {
	typ, _ := raw["type"].(string)
	switch typ {
	case "text":
		if t := agentEventText(raw); t != "" {
			return "assistant", t, ""
		}
	case "tool_use":
		part, _ := raw["part"].(map[string]any)
		tool, _ := part["tool"].(string)
		state, _ := part["state"].(map[string]any)
		status, _ := state["status"].(string)
		input, _ := state["input"].(map[string]any)
		lines := []string{"↳ " + tool}
		if status != "" {
			lines = []string{"↳ " + tool + " · " + status}
		}
		if command, _ := input["command"].(string); tool == "bash" && command != "" {
			lines = append(lines, "$ "+command)
		} else if fp, _ := input["filePath"].(string); fp != "" {
			lines = append(lines, fp)
		} else if fp, _ := input["path"].(string); fp != "" {
			lines = append(lines, fp)
		}
		if errTxt, _ := state["error"].(string); errTxt != "" {
			lines = append(lines, "ERROR: "+errTxt)
		} else if outTxt, _ := state["output"].(string); outTxt != "" {
			lines = append(lines, boundedTail(outTxt, 2600))
		}
		return "tool", strings.Join(lines, "\n"), ""
	case "error":
		return "error", errorEventText(raw), ""
	case "file":
		part, _ := raw["part"].(map[string]any)
		url, _ := part["url"].(string)
		mime, _ := part["mediaType"].(string)
		if mime == "" {
			mime, _ = part["mime"].(string)
		}
		if strings.HasPrefix(strings.ToLower(mime), "image/") && sanitizeImageURL(url) != "" {
			filename, _ := part["filename"].(string)
			return "image", sanitizeImageURL(url), filename
		}
	}
	return "", "", ""
}

// providerErrorMeta extracts an optional provider error code and numeric HTTP
// status from a serialized OpenCode error event, tolerating their absence.
func providerErrorMeta(raw map[string]any) (code string, statusCode int) {
	e, ok := raw["error"].(map[string]any)
	if !ok {
		return "", 0
	}
	if data, ok := e["data"].(map[string]any); ok {
		if c, _ := data["code"].(string); c != "" {
			code = c
		}
		if s, ok := data["statusCode"].(float64); ok {
			statusCode = int(s)
		} else if s, ok := data["status"].(float64); ok {
			statusCode = int(s)
		}
	}
	if c, _ := e["code"].(string); c != "" {
		code = c
	}
	if s, ok := e["statusCode"].(float64); ok {
		statusCode = int(s)
	}
	return code, statusCode
}

// finishRunChecked finalizes an early-failed run and logs at ERROR if that
// finalization itself fails, so a storage failure is never silently dropped.
func (a *app) finishRunChecked(runID, accountID, clientSession, state, message string, input, output uint64, cost float64, diag string) {
	if err := a.finishDurableAgentRun(runID, accountID, clientSession, state, "", message, input, output, cost, diag); err != nil {
		log.Printf("warden agent run %s: finalize failed: %v", runID, err)
	}
}

// agentCancel performs an authenticated, account-scoped Stop for a live run.
// The run ID is owned by the caller's account; another account's run returns
// 404 without disclosing its existence.
func (a *app) agentCancel(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var q struct {
		RunID string `json:"runID"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&q); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if !validAgentSessionID(q.RunID) {
		http.Error(w, "invalid run id", http.StatusBadRequest)
		return
	}
	a.runMu.Lock()
	run := a.activeRuns[q.RunID]
	a.runMu.Unlock()
	if run == nil || run.accountID != sess.AccountID {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	if !run.state.recordCause(causeUserStop) {
		if run.state.snapshot().sealed {
			http.Error(w, "run already finished", http.StatusGone)
			return
		}
	}
	run.cancel()
	jsonOut(w, map[string]bool{"cancelled": true})
}

// agentRunDiagnostics serves the bounded, redacted technical-detail record for
// a finished run to the owning account (or an admin). Raw stderr is never
// returned in conversation list responses; it is only available here.
func (a *app) agentRunDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	sess, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	runID := strings.TrimSpace(r.URL.Query().Get("runID"))
	if !validAgentSessionID(runID) {
		http.Error(w, "invalid run id", http.StatusBadRequest)
		return
	}
	var diag string
	err := a.db.QueryRow("SELECT diagnostics FROM agent_runs WHERE id=? AND account_id=?", runID, sess.AccountID).Scan(&diag)
	if err != nil {
		// Allow admins to inspect across accounts without exposing existence
		// to ordinary accounts.
		if acct, ok := a.accounts.accountByID(sess.AccountID); ok && hasRole(acct, "admin") {
			err = a.db.QueryRow("SELECT diagnostics FROM agent_runs WHERE id=?", runID).Scan(&diag)
		}
	}
	if err != nil || diag == "" {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(diag))
}

func hasRole(acct account, roleID string) bool {
	for _, r := range acct.Roles {
		if r == roleID {
			return true
		}
	}
	return false
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
	args := []string{"--print-logs", "--log-level", "WARN", "run", "--format", "json", "--auto", "--dir", workspace, "--model", modelRef}
	if s := strings.TrimSpace(session); s != "" {
		args = append(args, "--session", s)
	}
	for _, p := range files {
		args = append(args, "--file", p)
	}
	return append(args, "--", prompt)
}

// openCodeVersion returns the installed OpenCode version captured at first
// use, or the empty string when it cannot be determined.
var openCodeVersion = func() func() string {
	version := ""
	var once sync.Once
	return func() string {
		once.Do(func() {
			if b, err := exec.Command("opencode", "--version").Output(); err == nil {
				version = strings.TrimSpace(string(b))
				if len(version) > 64 {
					version = version[:64]
				}
			}
		})
		return version
	}
}()

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

func writeAgentEvent(w http.ResponseWriter, f http.Flusher, kind string, data any) error {
	if err := json.NewEncoder(w).Encode(map[string]any{"type": kind, "data": data}); err != nil {
		return err
	}
	f.Flush()
	return nil
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
