package server

import (
	"io"
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
	sealed   bool
}

// runStateSnapshot is a consistent view of the machine used by the classifier.
type runStateSnapshot struct {
	cause    runCause
	errSeq   uint64
	causeSeq uint64
	sealed   bool
}

func newRunState() *runState { return &runState{} }

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
	return runStateSnapshot{cause: s.cause, errSeq: s.errSeq, causeSeq: s.causeSeq, sealed: s.sealed}
}

// exitStatus describes the raw process termination facts.
type exitStatus struct {
	exited   bool
	exitCode int
	signaled bool
	signal   string
}

// classifyRun applies the authoritative outcome precedence.
func classifyRun(state runStateSnapshot, stdoutError bool, validStop bool, exit exitStatus) runOutcome {
	if stdoutError && (state.cause == causeNone || (state.errSeq > 0 && state.causeSeq > 0 && state.errSeq < state.causeSeq)) {
		return outcomeFailed
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
	if exit.exited && exit.exitCode != 0 && validStop && !stdoutError {
		return outcomeCompletedWError
	}
	if exit.exited && exit.exitCode != 0 {
		return outcomeFailed
	}
	if exit.exited && exit.exitCode == 0 && validStop && !stdoutError {
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
}
