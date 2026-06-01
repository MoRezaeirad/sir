//go:build windows

package ledger

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	modkernel32            = syscall.NewLazyDLL("kernel32.dll")
	procLedgerLockFileEx   = modkernel32.NewProc("LockFileEx")
	procLedgerUnlockFileEx = modkernel32.NewProc("UnlockFileEx")
)

const lockfileExFlagExclusive = 0x00000002

func ledgerLockFile(f *os.File, exclusive bool) error {
	flags := uint32(0)
	if exclusive {
		flags = lockfileExFlagExclusive
	}
	ol := new(syscall.Overlapped)
	r, _, err := procLedgerLockFileEx.Call(
		uintptr(f.Fd()),
		uintptr(flags),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(ol)),
	)
	if r == 0 {
		if err != nil {
			return err
		}
		return syscall.EINVAL
	}
	return nil
}

func ledgerUnlockFile(f *os.File) error {
	ol := new(syscall.Overlapped)
	r, _, err := procLedgerUnlockFileEx.Call(
		uintptr(f.Fd()),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(ol)),
	)
	if r == 0 {
		if err != nil {
			return err
		}
		return syscall.EINVAL
	}
	return nil
}

func withLedgerLock(ledgerPath string, fn func() error) error {
	lockPath := ledgerPath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer func() { _ = lockFile.Close() }()
	if err := ledgerLockFile(lockFile, true); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer ledgerUnlockFile(lockFile) //nolint:errcheck
	return fn()
}

func withLedgerReadLock(ledgerPath string, fn func() error) error {
	lockPath := ledgerPath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer func() { _ = lockFile.Close() }()
	if err := ledgerLockFile(lockFile, false); err != nil {
		return fmt.Errorf("acquire read lock: %w", err)
	}
	defer ledgerUnlockFile(lockFile) //nolint:errcheck
	return fn()
}
