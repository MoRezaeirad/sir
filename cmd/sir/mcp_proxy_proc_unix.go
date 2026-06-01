//go:build unix

package main

import (
	"os"
	"os/exec"
	"syscall"
)

func setMCPProxyProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

func mcpProxyTermSignals() []os.Signal {
	return []os.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP}
}

func killProcessGroup(pgid int, sig syscall.Signal) error {
	return syscall.Kill(-pgid, sig)
}

func cleanupMCPProxyGroup(pgid int) {
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
}
