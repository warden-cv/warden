//go:build !windows

package server

import (
	"os/exec"
	"syscall"
)

// configureAgentProcess runs the OpenCode child in its own process group and
// kills the whole group on context cancellation, matching Cortex.
func configureAgentProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// processExitStatus extracts the process termination facts after Wait.
func processExitStatus(cmd *exec.Cmd) exitStatus {
	ps := cmd.ProcessState
	if ps == nil {
		return exitStatus{}
	}
	out := exitStatus{exited: ps.Exited(), exitCode: ps.ExitCode()}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		out.signaled = true
		out.signal = ws.Signal().String()
	}
	return out
}
