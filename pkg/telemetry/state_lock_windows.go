//go:build windows

package telemetry

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	modkernel32               = syscall.NewLazyDLL("kernel32.dll")
	procTelemetryLockFileEx   = modkernel32.NewProc("LockFileEx")
	procTelemetryUnlockFileEx = modkernel32.NewProc("UnlockFileEx")
)

const lockfileExFlagExclusive = 0x00000002

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
	ol := new(syscall.Overlapped)
	r, _, lockErr := procTelemetryLockFileEx.Call(
		uintptr(lockFile.Fd()),
		uintptr(lockfileExFlagExclusive),
		0, 1, 0,
		uintptr(unsafe.Pointer(ol)),
	)
	if r == 0 {
		if lockErr != nil {
			return fmt.Errorf("acquire telemetry health lock: %w", lockErr)
		}
		return fmt.Errorf("acquire telemetry health lock: %w", syscall.EINVAL)
	}
	defer func() {
		ol2 := new(syscall.Overlapped)
		procTelemetryUnlockFileEx.Call(uintptr(lockFile.Fd()), 0, 1, 0, uintptr(unsafe.Pointer(ol2))) //nolint:errcheck
	}()
	return fn()
}
