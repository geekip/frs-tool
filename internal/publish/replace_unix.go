//go:build linux || darwin || freebsd

package publish

import (
	"os"
	"path/filepath"
)

// Commit 原子替换目标，并同步父目录以确认目录项持久化。
func Commit(candidate, output string) (CommitResult, error) {
	if err := os.Rename(candidate, output); err != nil {
		return CommitResult{}, publishError(CodeRename, "cannot replace output", err)
	}
	result := CommitResult{Committed: true}
	directory, err := os.Open(filepath.Dir(output))
	if err != nil {
		return result, publishError(CodeDirSync, "cannot open output directory for sync", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return result, publishError(CodeDirSync, "cannot sync output directory", syncErr)
	}
	if closeErr != nil {
		return result, publishError(CodeDirSync, "cannot close output directory", closeErr)
	}
	result.Durable = true
	return result, nil
}
