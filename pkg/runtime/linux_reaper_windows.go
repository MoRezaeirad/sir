//go:build windows

package runtime

import (
	"os/exec"
	"time"
)

func enableLinuxContainmentSubreaper() error { return nil }

func reapLinuxContainmentChildren(_ []int, _ time.Duration) error { return nil }

func linuxTerminateAdoptedChildren(time.Duration) error { return nil }

func terminateLinuxContainmentTree(cmd *exec.Cmd, _ int) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}
