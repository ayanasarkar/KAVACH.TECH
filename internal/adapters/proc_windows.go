//go:build windows

package adapters

import (
	"os/exec"
	"strconv"
)

// killTree makes cancellation kill the tool's whole process tree via taskkill /T.
func killTree(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		_ = exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
		return cmd.Process.Kill()
	}
}
