//go:build windows

package server

import "os/exec"

func configureAgentProcess(cmd *exec.Cmd) {}

// processExitStatus extracts the process termination facts after Wait.
func processExitStatus(cmd *exec.Cmd) exitStatus {
	ps := cmd.ProcessState
	if ps == nil {
		return exitStatus{}
	}
	return exitStatus{exited: ps.Exited(), exitCode: ps.ExitCode()}
}
