//go:build windows

package dockerapp

import "os/exec"

func detachProcess(*exec.Cmd) {}

func stopProcess(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	_ = command.Process.Kill()
}
