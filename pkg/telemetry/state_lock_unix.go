//go:build unix

package telemetry

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func withHealthLock(projectRoot string, fn func() error) error {
	healthPath := HealthPath(projectRoot)
	if err := os.MkdirAll(filepath.Dir(healthPath), 0o700); err != nil {
		return err
	}
	lockPath := healthPath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open telemetry health lock: %w", err)
	}
	defer func() { _ = lockFile.Close() }()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire telemetry health lock: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) //nolint:errcheck
	return fn()
}
