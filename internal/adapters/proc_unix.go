//go:build !windows

package adapters

import (
	"os/exec"
	"syscall"
)

// killTree makes cancellation kill the tool's whole process group (nikto/msfconsole spawn children).
func killTree(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
