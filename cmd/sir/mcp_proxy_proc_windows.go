//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

func setMCPProxyProcessGroup(_ *exec.Cmd) {}

func mcpProxyTermSignals() []os.Signal {
	return []os.Signal{syscall.SIGTERM, syscall.SIGINT}
}

// killProcessGroup on Windows cannot address a process group — send a
// best-effort signal to the direct child process only.
func killProcessGroup(_ int, _ syscall.Signal) error {
	return nil
}

// cleanupMCPProxyGroup is a no-op on Windows (no POSIX process groups).
func cleanupMCPProxyGroup(_ int) {}
