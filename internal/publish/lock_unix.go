//go:build linux || darwin || freebsd

package publish

import (
	"errors"
	"os"
	"syscall"
)

// Lock 持有由操作系统管理的目标排他锁。
type Lock struct {
	file *os.File
}

// Acquire 非阻塞获取规范化 output 的排他锁。
func Acquire(output string) (*Lock, error) {
	path := lockPath(output)
	descriptor, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, publishError(CodeOutputLock, "cannot open output lock", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, publishError(CodeOutputLock, "cannot own output lock", nil)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, publishError(CodeOutputLock, "output lock is not a regular file", err)
	}
	if err := syscall.Flock(descriptor, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, publishError(CodeOutputLocked, "output is locked by another build", err)
		}
		return nil, publishError(CodeOutputLock, "cannot acquire output lock", err)
	}
	return &Lock{file: file}, nil
}

// Release 释放锁和文件句柄；锁文件可安全保留供后续运行复用。
func (l *Lock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	descriptor := int(l.file.Fd())
	unlockErr := syscall.Flock(descriptor, syscall.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return publishError(CodeOutputLock, "cannot release output lock", unlockErr)
	}
	if closeErr != nil {
		return publishError(CodeOutputLock, "cannot close output lock", closeErr)
	}
	return nil
}
