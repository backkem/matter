//go:build unix

package framework

import (
	"os/exec"
	"syscall"
)

// setProcessGroup runs cmd in its own process group so the binary started by
// `go run` can be signalled together with the go wrapper.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// signalProcessGroup sends sig to cmd's whole process group.
func signalProcessGroup(cmd *exec.Cmd, sig syscall.Signal) error {
	return syscall.Kill(-cmd.Process.Pid, sig)
}
