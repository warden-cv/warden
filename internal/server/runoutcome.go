package server

import (
	"io"
	"net/url"
	"strings"
	"sync"
)

// runCause enumerates the local cancellation causes a run may record before
// the process is stopped. Only the first accepted cause is retained; the
// transition rules below guarantee user-initiated or output-limit causes are
// never silently downgraded to a generic request cancellation.
type runCause string

const (
	causeNone            runCause = ""
	causeUserStop        runCause = "user_stop"
	causeRequestCanceled runCause = "request_cancelled"
	causeOutputLimit     runCause = "output_limit"
	causeServiceShutdown runCause = "service_shutdown"
	// causeProviderInsufficientBalance is a derived provider-failure cause,
	// distinct from any local termination cause.
	causeProviderInsufficientBalance runCause = "provider_insufficient_balance"
)

// runOutcome is the terminal classification persisted for a run. It mirrors
// the conversation states and the frontend badges.
type runOutcome string

const (
	outcomeCompleted       runOutcome = "completed"
	outcomeCompletedWError runOutcome = "completed_with_process_error"
	outcomeFailed          runOutcome = "failed"
	outcomeCancelled       runOutcome = "cancelled"
	outcomeTruncated       runOutcome = "truncated"
	outcomeInterrupted     runOutcome = "interrupted"
)

// runState is the synchronized cancellation-cause machine for one active run.
type runState struct {
	mu       sync.Mutex
	cause    runCause
	seq      uint64
	errSeq   uint64
	causeSeq uint64
	// stopSeq records the sequence at which the main session's valid completion
	// evidence (a step_finish with reason "stop") was observed, drawn from the
	// same observation sequence as errSeq so the classifier can establish
	// whether an error occurred before or after completion. Zero means no valid
	// completion evidence was seen.
	stopSeq uint64
	// providerErrSeq records the sequence at which an authoritative main-session
	// provider failure was observed, separate from the local cause machine.
	providerErrSeq uint64
	sealed         bool
}

// runStateSnapshot is a consistent view of the machine used by the classifier.
type runStateSnapshot struct {
	cause          runCause
	errSeq         uint64
	causeSeq       uint64
	stopSeq        uint64
	providerErrSeq uint64
	sealed         bool
}

func newRunState() *runState { return &runState{} }

// recordProviderFailureAt promotes a candidate provider failure captured
// earlier to the recorded provider sequence, preserving chronological order.
func (s *runState) recordProviderFailureAt(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq > 0 && s.providerErrSeq == 0 {
		s.providerErrSeq = seq
	}
}

// nextSeq allocates the next observation sequence without recording semantics.
func (s *runState) nextSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return s.seq
}

// recordErrorAt promotes a candidate error captured earlier, preserving order.
func (s *runState) recordErrorAt(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq > 0 && s.errSeq == 0 {
		s.errSeq = seq
	}
}

// recordStopAt promotes a candidate valid-completion (step_finish "stop")
// observation captured earlier to the recorded stop sequence, preserving its
// chronological position relative to errors.
func (s *runState) recordStopAt(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq > 0 && s.stopSeq == 0 {
		s.stopSeq = seq
	}
}

// recordCause accepts a cause only when the transition is legal and the run
// has not been sealed.
func (s *runState) recordCause(c runCause) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealed {
		return false
	}
	switch c {
	case causeRequestCanceled:
		if s.cause != causeNone {
			return false
		}
	case causeUserStop:
		if s.cause != causeNone && s.cause != causeRequestCanceled {
			return false
		}
	case causeOutputLimit:
		if s.cause != causeNone && s.cause != causeRequestCanceled && s.cause != causeUserStop {
			return false
		}
	case causeServiceShutdown:
		if s.cause != causeNone && s.cause != causeRequestCanceled {
			return false
		}
	default:
		return false
	}
	s.seq++
	s.cause = c
	s.causeSeq = s.seq
	return true
}

// observeError records the sequence at which an authoritative stdout
// `type:"error"` event was first seen.
func (s *runState) observeError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	if s.errSeq == 0 {
		s.errSeq = s.seq
	}
}

// seal closes the machine so late requests can no longer rewrite history.
func (s *runState) seal() {
	s.mu.Lock()
	s.sealed = true
	s.mu.Unlock()
}

func (s *runState) snapshot() runStateSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return runStateSnapshot{cause: s.cause, errSeq: s.errSeq, causeSeq: s.causeSeq, stopSeq: s.stopSeq, providerErrSeq: s.providerErrSeq, sealed: s.sealed}
}

// exitStatus describes the raw process termination facts.
type exitStatus struct {
	exited   bool
	exitCode int
	signaled bool
	signal   string
}

// classifyRun applies the authoritative outcome precedence. Error and
// completion evidence share one observation sequence (runState.seq): a
// main-session error observed before valid completion (or with no valid
// completion at all) is a genuine failure, while an error observed after the
// main-session step_finish is post-completion evidence and never fails the
// produced answer. Provider failures follow chronological order: a main-session
// provider failure before an accepted local cause produces failed; a local
// cause accepted earlier keeps its local outcome.
func classifyRun(state runStateSnapshot, stdoutError bool, validStop bool, exit exitStatus, providerCause runCause) runOutcome {
	if providerCause != "" {
		if state.stopSeq == 0 || state.providerErrSeq < state.stopSeq {
			if state.cause == causeNone || (state.causeSeq > 0 && state.providerErrSeq < state.causeSeq) {
				return outcomeFailed
			}
		}
	}
	if stdoutError {
		beforeStop := state.stopSeq == 0 || (state.errSeq > 0 && state.errSeq < state.stopSeq)
		if beforeStop {
			if state.cause == causeNone || (state.errSeq > 0 && state.causeSeq > 0 && state.errSeq < state.causeSeq) {
				return outcomeFailed
			}
		}
	}
	switch state.cause {
	case causeOutputLimit:
		return outcomeTruncated
	case causeUserStop, causeRequestCanceled:
		return outcomeCancelled
	case causeServiceShutdown:
		return outcomeInterrupted
	}
	if exit.signaled {
		return outcomeFailed
	}
	if exit.exited && exit.exitCode != 0 && validStop {
		return outcomeCompletedWError
	}
	if exit.exited && exit.exitCode != 0 {
		return outcomeFailed
	}
	if exit.exited && exit.exitCode == 0 && validStop {
		return outcomeCompleted
	}
	if exit.exited && exit.exitCode == 0 {
		return outcomeFailed
	}
	return outcomeFailed
}

// tailCapture drains an io.Reader to EOF in the background while retaining
// only the last limit bytes.
type tailCapture struct {
	mu        sync.Mutex
	buf       []byte
	discarded int64
	limit     int
	done      chan struct{}
}

func captureTail(r io.Reader, limit int) *tailCapture {
	c := &tailCapture{limit: limit, done: make(chan struct{})}
	go func() {
		defer close(c.done)
		tmp := make([]byte, 32<<10)
		for {
			n, err := r.Read(tmp)
			if n > 0 {
				c.write(tmp[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	return c
}

func (c *tailCapture) write(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(b) == 0 {
		return
	}
	if len(b) >= c.limit {
		c.discarded += int64(len(c.buf)) + int64(len(b)-c.limit)
		c.buf = append([]byte(nil), b[len(b)-c.limit:]...)
		return
	}
	need := c.limit - len(c.buf)
	if len(b) > need {
		drop := len(b) - need
		c.discarded += int64(drop)
		c.buf = c.buf[drop:]
	}
	c.buf = append(c.buf, b...)
}

func (c *tailCapture) wait() { <-c.done }

func (c *tailCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.buf)
}

func (c *tailCapture) truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.discarded > 0
}

// stderrLevel extracts the level field from a structured stderr line, or ""
// for unstructured lines.
func stderrLevel(line string) string {
	const marker = "level="
	i := strings.Index(line, marker)
	if i < 0 {
		return ""
	}
	rest := line[i+len(marker):]
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		rest = rest[:j]
	}
	if j := strings.IndexByte(rest, '\t'); j >= 0 {
		rest = rest[:j]
	}
	level := strings.ToUpper(rest)
	switch level {
	case "DEBUG", "INFO", "WARN", "ERROR":
		return level
	}
	return ""
}

// diagnostics is the structured outcome record persisted for a run and served
// through the owner-authorized technical-details endpoint.
type diagnostics struct {
	Outcome              string   `json:"outcome"`
	Category             string   `json:"category"`
	Summary              string   `json:"summary"`
	ExitCode             int      `json:"exitCode,omitempty"`
	Signal               string   `json:"signal,omitempty"`
	Cause                string   `json:"cause,omitempty"`
	StdoutError          string   `json:"stdoutError,omitempty"`
	Errors               []string `json:"errors,omitempty"`
	Warnings             []string `json:"warnings,omitempty"`
	StderrTail           string   `json:"stderrTail,omitempty"`
	StderrTruncated      bool     `json:"stderrTruncated,omitempty"`
	RecoveryAttempted    bool     `json:"recoveryAttempted,omitempty"`
	RecoveryResult       string   `json:"recoveryResult,omitempty"`
	TerminalEventDeliver bool     `json:"terminalEventDelivered,omitempty"`
	DeliveryError        string   `json:"deliveryError,omitempty"`
	OpenCodeVersion      string   `json:"opencodeVersion,omitempty"`
	Provider             string   `json:"provider,omitempty"`
	Model                string   `json:"model,omitempty"`
	ProviderCause        string   `json:"providerCause,omitempty"`
	BillingURL           string   `json:"billingUrl,omitempty"`
}

// classifyProviderError recognizes a provider insufficient-balance failure
// from narrow structured provider evidence. See Cortex equivalent for the
// exact accepted evidence.
func classifyProviderError(msg, code string, statusCode int) bool {
	lower := strings.ToLower(strings.TrimSpace(msg))
	codeLower := strings.ToLower(strings.TrimSpace(code))
	switch codeLower {
	case "insufficient_balance", "insufficient balance", "account_balance_insufficient", "billing_insufficient_balance":
		return true
	}
	if statusCode == 402 {
		return true
	}
	return strings.Contains(lower, "insufficient balance")
}

// sanitizeBillingURL validates a provider-supplied billing URL strictly:
// https, exact hostname opencode.ai, no userinfo, no port, no query/fragment,
// and a /workspace/... path.
func sanitizeBillingURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 512 {
		return ""
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	if u.Hostname() != "opencode.ai" {
		return ""
	}
	if u.Path == "" || !strings.HasPrefix(u.Path, "/workspace/") {
		return ""
	}
	return u.String()
}

// extractBillingURL pulls a candidate https billing URL out of a provider
// error message for later validation.
func extractBillingURL(msg string) string {
	i := strings.Index(msg, "https://")
	if i < 0 {
		return ""
	}
	rest := msg[i:]
	end := len(rest)
	for j, r := range rest {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != ':' && r != '/' && r != '.' && r != '-' && r != '_' && r != '?' && r != '=' && r != '&' {
			end = j
			break
		}
	}
	return rest[:end]
}

// insufficientBalanceMessage returns the concise, transcript-safe message.
func insufficientBalanceMessage(billingURL string) (string, bool) {
	return "The provider could not run this request because the account has insufficient credit. Add credit or choose another configured provider, then try again.", billingURL != ""
}
