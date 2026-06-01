//go:build linux

package runtime

import (
	"os/exec"
	"syscall"
)

// setLinuxContainmentSysProcAttr sets the process group so the whole
// containment tree can be signalled via -pgid on Linux.
func setLinuxContainmentSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
