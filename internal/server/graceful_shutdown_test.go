package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestGracefulShutdownKillsCompleteProcessGroup proves that stopActiveRuns (the
// shutdown path) kills the entire Setpgid agent process group, including a
// grandchild the immediate child spawned, rather than orphaning it.
func TestGracefulShutdownKillsCompleteProcessGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX process groups")
	}
	a := &app{activeRuns: map[string]*activeRun{}}
	dir := t.TempDir()
	childPID := filepath.Join(dir, "child.pid")
	grandPID := filepath.Join(dir, "grand.pid")
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", fmt.Sprintf(`echo $$ > %s; (sleep 300 & echo $! > %s); wait`, wardenQuote(childPID), wardenQuote(grandPID)))
	configureAgentProcess(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child, grand := wardenWaitPIDs(t, childPID, grandPID)
	if !wardenAlive(child) || !wardenAlive(grand) {
		t.Fatalf("processes not running before shutdown: child=%d grand=%d", child, grand)
	}
	a.runMu.Lock()
	a.activeRuns["run-graceful"] = newActiveRun("acct-1", cancel)
	a.runMu.Unlock()
	go func() { _ = cmd.Wait(); a.activeRuns["run-graceful"].finished() }()
	a.stopActiveRuns()
	// A freshly killed process can momentarily exist as a zombie until its
	// parent reaps it, so poll for disappearance rather than checking once.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !wardenAlive(child) && !wardenAlive(grand) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("process group survived shutdown: child=%d grand=%d", child, grand)
}

func wardenQuote(path string) string { return "'" + strings.ReplaceAll(path, "'", "'\\''") + "'" }

func wardenWaitPIDs(t *testing.T, childPath, grandPath string) (int, int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c := wardenReadPID(childPath)
		g := wardenReadPID(grandPath)
		if c > 0 && g > 0 {
			return c, g
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("child or grandchild pid file never appeared")
	return 0, 0
}

func wardenReadPID(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0
	}
	return pid
}

func wardenAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }
