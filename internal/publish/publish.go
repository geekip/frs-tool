package publish

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	CodeOutputInvalid = "OUTPUT_INVALID"
	CodeOutputLocked  = "OUTPUT_LOCKED"
	CodeOutputLock    = "OUTPUT_LOCK"
	CodeCleanup       = "OUTPUT_CLEANUP"
	CodeCreate        = "OUTPUT_CREATE"
	CodeRename        = "OUTPUT_RENAME"
	CodeDirSync       = "OUTPUT_DIR_SYNC"
)

// Error 是发布边界的稳定分类错误。
type Error struct {
	Code    string
	Message string
	Err     error
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Message
}

func (e *Error) Unwrap() error {
	return e.Err
}

func publishError(code, message string, err error) *Error {
	return &Error{Code: code, Message: message, Err: err}
}

// ErrorCode 返回发布错误的稳定代码。
func ErrorCode(err error) string {
	var value *Error
	if errors.As(err, &value) {
		return value.Code
	}
	return ""
}

// NormalizeOutput 解析父目录符号链接并拒绝最终目标符号链接或特殊文件。
func NormalizeOutput(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", publishError(CodeOutputInvalid, "output path is empty", nil)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", publishError(CodeOutputInvalid, "cannot resolve output path", err)
	}
	absolute = filepath.Clean(absolute)
	base := filepath.Base(absolute)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return "", publishError(CodeOutputInvalid, "output must name a file", nil)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", publishError(CodeOutputInvalid, "output directory is unavailable", err)
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return "", publishError(CodeOutputInvalid, "output parent is not a directory", err)
	}
	normalized := filepath.Join(parent, base)
	if target, err := os.Lstat(normalized); err == nil {
		if target.Mode()&os.ModeSymlink != 0 || !target.Mode().IsRegular() {
			return "", publishError(CodeOutputInvalid, "output is not a regular file", nil)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", publishError(CodeOutputInvalid, "cannot inspect output", err)
	}
	return normalized, nil
}

// TargetID 是只用于锁与候选所有权命名的目标身份。
func TargetID(output string) string {
	if runtime.GOOS == "windows" {
		output = strings.ToLower(output)
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(output)))
}

func lockPath(output string) string {
	return filepath.Join(filepath.Dir(output), ".frs-lock-"+TargetID(output)+".lock")
}

func candidatePattern(output string) string {
	return ".frs-candidate-" + TargetID(output) + "-*.tmp"
}

func candidatePrefix(output string) string {
	return ".frs-candidate-" + TargetID(output) + "-"
}

// CleanupStale 删除同一目标的历史普通候选文件，不跟随符号链接。
func CleanupStale(output string) error {
	parent := filepath.Dir(output)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return publishError(CodeCleanup, "cannot scan output directory", err)
	}
	prefix := candidatePrefix(output)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".tmp") || len(name) <= len(prefix)+4 {
			continue
		}
		path := filepath.Join(parent, name)
		info, err := os.Lstat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return publishError(CodeCleanup, "cannot inspect stale candidate", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if err := os.Remove(path); err != nil {
			return publishError(CodeCleanup, "cannot remove stale candidate", err)
		}
	}
	return nil
}

// CreateCandidate 在 output 同目录创建只属于本次运行的候选文件。
func CreateCandidate(output string) (*os.File, error) {
	file, err := os.CreateTemp(filepath.Dir(output), candidatePattern(output))
	if err != nil {
		return nil, publishError(CodeCreate, "cannot create output candidate", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, publishError(CodeCreate, "cannot secure output candidate", err)
	}
	return file, nil
}

// RemoveCandidate 删除尚未提交的候选；不存在视为已清理。
func RemoveCandidate(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return publishError(CodeCleanup, "cannot remove output candidate", err)
	}
	return nil
}

// CommitResult 区分提交前失败和可能已越过替换边界的失败。
type CommitResult struct {
	Committed bool
	Durable   bool
}
