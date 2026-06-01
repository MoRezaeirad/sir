//go:build unix

package runtime

import (
	"fmt"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestTerminateLinuxContainment_KillsForkedChild(t *testing.T) {
	pidFile := t.TempDir() + "/child.pid"
	cmd := exec.Command("sh", "-c", fmt.Sprintf("sleep 30 & echo $! > %s; wait", shellQuote(pidFile)))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper process group: %v", err)
	}

	childPID, err := waitForLinuxNamespacePID(pidFile, cmd.Process.Pid, time.Second)
	if err != nil {
		terminateLinuxContainment(cmd, 0)
		t.Fatalf("discover forked child pid: %v", err)
	}

	terminateLinuxContainment(cmd, childPID)

	deadline := time.Now().Add(time.Second)
	for {
		if err := syscall.Kill(childPID, syscall.Signal(0)); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("forked child pid %d survived containment cleanup", childPID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
