//go:build !unix && !windows

package session

func pidAlive(pid int) bool {
	return false
}
