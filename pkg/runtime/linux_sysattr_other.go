//go:build !linux

package runtime

import "os/exec"

func setLinuxContainmentSysProcAttr(_ *exec.Cmd) {}
