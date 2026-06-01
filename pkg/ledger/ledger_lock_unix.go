//go:build unix

package ledger

import (
	"fmt"
	"os"
	"syscall"
)

// withLedgerLockMode acquires a file lock on ledgerPath+".lock", calls fn, and
// releases the lock afterward. Exclusive locks serialize writers, while shared
// locks keep readers from observing partially written JSON lines.
func withLedgerLockMode(ledgerPath string, mode int, fn func() error) error {
	lockPath := ledgerPath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer func() { _ = lockFile.Close() }()
	if err := syscall.Flock(int(lockFile.Fd()), mode); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) //nolint:errcheck
	return fn()
}

func withLedgerLock(ledgerPath string, fn func() error) error {
	return withLedgerLockMode(ledgerPath, syscall.LOCK_EX, fn)
}

func withLedgerReadLock(ledgerPath string, fn func() error) error {
	return withLedgerLockMode(ledgerPath, syscall.LOCK_SH, fn)
}
