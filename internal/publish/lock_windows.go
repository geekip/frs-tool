//go:build windows

package publish

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
	errorLockViolation      = syscall.Errno(33)
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

// Lock 持有由操作系统管理的目标排他锁。
type Lock struct {
	file       *os.File
	overlapped syscall.Overlapped
}

// Acquire 非阻塞获取规范化 output 的排他锁。
func Acquire(output string) (*Lock, error) {
	path := lockPath(output)
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, publishError(CodeOutputLock, "output lock is a symbolic link", nil)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, publishError(CodeOutputLock, "cannot inspect output lock", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, publishError(CodeOutputLock, "cannot open output lock", err)
	}
	lock := &Lock{file: file}
	result, _, callErr := procLockFileEx.Call(
		file.Fd(), uintptr(lockfileExclusiveLock|lockfileFailImmediately), 0, 1, 0,
		uintptr(unsafe.Pointer(&lock.overlapped)),
	)
	if result == 0 {
		_ = file.Close()
		if errors.Is(callErr, errorLockViolation) {
			return nil, publishError(CodeOutputLocked, "output is locked by another build", callErr)
		}
		return nil, publishError(CodeOutputLock, "cannot acquire output lock", callErr)
	}
	return lock, nil
}

// Release 释放锁和文件句柄；锁文件可安全保留供后续运行复用。
func (l *Lock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	result, _, callErr := procUnlockFileEx.Call(
		l.file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&l.overlapped)),
	)
	closeErr := l.file.Close()
	l.file = nil
	if result == 0 {
		return publishError(CodeOutputLock, "cannot release output lock", callErr)
	}
	if closeErr != nil {
		return publishError(CodeOutputLock, "cannot close output lock", closeErr)
	}
	return nil
}
