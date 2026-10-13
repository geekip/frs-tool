//go:build windows

package publish

import (
	"syscall"
	"unsafe"
)

const (
	movefileReplaceExisting = 0x00000001
	movefileWriteThrough    = 0x00000008
)

var procMoveFileEx = kernel32.NewProc("MoveFileExW")

// Commit 使用 Windows write-through 替换，不通过先删除目标伪造替换。
func Commit(candidate, output string) (CommitResult, error) {
	from, err := syscall.UTF16PtrFromString(candidate)
	if err != nil {
		return CommitResult{}, publishError(CodeRename, "candidate path is invalid", err)
	}
	to, err := syscall.UTF16PtrFromString(output)
	if err != nil {
		return CommitResult{}, publishError(CodeRename, "output path is invalid", err)
	}
	result, _, callErr := procMoveFileEx.Call(
		uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)),
		uintptr(movefileReplaceExisting|movefileWriteThrough),
	)
	if result == 0 {
		return CommitResult{}, publishError(CodeRename, "cannot replace output", callErr)
	}
	return CommitResult{Committed: true, Durable: true}, nil
}
