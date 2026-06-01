//go:build windows

package session

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	modkernel32      = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = modkernel32.NewProc("LockFileEx")
	procUnlockFileEx = modkernel32.NewProc("UnlockFileEx")
)

// lockfileExFlagExclusive is LOCKFILE_EXCLUSIVE_LOCK.
// Without LOCKFILE_FAIL_IMMEDIATELY (0x1), LockFileEx blocks until acquired.
const lockfileExFlagExclusive = 0x00000002

func lockFileBlocking(f *os.File) error {
	ol := new(syscall.Overlapped)
	r, _, err := procLockFileEx.Call(
		uintptr(f.Fd()),
		uintptr(lockfileExFlagExclusive),
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

func unlockFileHandle(f *os.File) error {
	ol := new(syscall.Overlapped)
	r, _, err := procUnlockFileEx.Call(
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

// WithSessionLock acquires an exclusive file lock on session.json.lock,
// calls fn, then releases the lock.
func WithSessionLock(projectRoot string, fn func() error) error {
	dir := StateDir(projectRoot)
	lockPath := StatePath(projectRoot) + ".lock"
	return withSessionLockPath(dir, lockPath, fn)
}

// WithSessionLockUnder is WithSessionLock for an explicit sir state home.
func WithSessionLockUnder(home, projectRoot string, fn func() error) error {
	dir := StateDirUnder(home, projectRoot)
	lockPath := StatePathUnder(home, projectRoot) + ".lock"
	return withSessionLockPath(dir, lockPath, fn)
}

func withSessionLockPath(dir, lockPath string, fn func() error) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open session lock: %w", err)
	}
	defer func() { _ = lockFile.Close() }()
	if err := lockFileBlocking(lockFile); err != nil {
		return fmt.Errorf("acquire session lock: %w", err)
	}
	defer unlockFileHandle(lockFile) //nolint:errcheck
	return fn()
}

// LoadLocked reads session state from disk while holding the session file lock.
// The returned unlock function MUST be called after Save to release the lock.
// This ensures the Load→Mutate→Save pipeline is atomic.
func LoadLocked(projectRoot string) (unlock func(), state *State, err error) {
	dir := StateDir(projectRoot)
	if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
		return func() {}, nil, mkErr
	}
	lockPath := StatePath(projectRoot) + ".lock"
	lockFile, openErr := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if openErr != nil {
		return func() {}, nil, fmt.Errorf("open session lock: %w", openErr)
	}
	if flockErr := lockFileBlocking(lockFile); flockErr != nil {
		_ = lockFile.Close()
		return func() {}, nil, fmt.Errorf("acquire session lock: %w", flockErr)
	}
	releaseFn := func() {
		_ = unlockFileHandle(lockFile)
		_ = lockFile.Close()
	}

	s, loadErr := Load(projectRoot)
	if loadErr != nil {
		releaseFn()
		return func() {}, nil, loadErr
	}
	return releaseFn, s, nil
}
