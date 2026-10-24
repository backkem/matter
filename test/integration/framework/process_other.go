//go:build !unix

package framework

import (
	"os/exec"
	"syscall"
)

func setProcessGroup(cmd *exec.Cmd) {}

// signalProcessGroup falls back to killing the direct child, as process
// groups are not available.
func signalProcessGroup(cmd *exec.Cmd, sig syscall.Signal) error {
	return cmd.Process.Kill()
}
