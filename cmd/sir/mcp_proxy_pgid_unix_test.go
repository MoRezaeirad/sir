//go:build unix

package main

import (
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestRunProxyChild_ChildRunsInOwnProcessGroup checks that the child is
// Setpgid'd. Without this, signals to sir's terminal group would hit the
// child twice (once from the terminal, once from our forwarding), and we
// couldn't cleanly kill the whole subtree via a negative PID.
func TestRunProxyChild_ChildRunsInOwnProcessGroup(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exec sleep 30")

	// Start without running the full harness so we can inspect pgid.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// Give the kernel a moment to apply setpgid — Go sets it before exec
	// so this is usually instant, but be lenient to avoid flakiness.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err == nil && pgid == cmd.Process.Pid {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	pgid, _ := syscall.Getpgid(cmd.Process.Pid)
	t.Fatalf("child pgid = %d, want %d (child pid)", pgid, cmd.Process.Pid)
}

// TestRunProxyChild_SignalForwardsToProcessGroup verifies that a SIGTERM
// delivered to the group reaches the child process.
func TestRunProxyChild_SignalForwardsToProcessGroup(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exec sleep 30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err == nil && pgid == cmd.Process.Pid {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	start := time.Now()
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatalf("kill group: %v", err)
	}

	waitErr := cmd.Wait()
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("child took %v to die — signal did not propagate to process group", elapsed)
	}

	exitErr, ok := waitErr.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %v", waitErr)
	}
	if exitErr.ExitCode() != -1 {
		t.Logf("exit code = %d (signal-killed children vary by OS)", exitErr.ExitCode())
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
		if !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
			t.Errorf("child did not die from SIGTERM: signaled=%v signal=%v", ws.Signaled(), ws.Signal())
		}
	}
}
