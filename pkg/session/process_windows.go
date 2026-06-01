//go:build windows

package session

import "syscall"

// PROCESS_QUERY_LIMITED_INFORMATION requires only minimal access and works
// even for processes owned by other users.
const processQueryLimitedInformation = 0x1000

// STILL_ACTIVE is the value GetExitCodeProcess returns for a running process.
const stillActive = 259

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h) //nolint:errcheck
	var exitCode uint32
	if err := syscall.GetExitCodeProcess(h, &exitCode); err != nil {
		return false
	}
	return exitCode == stillActive
}
