package publish

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNormalizeOutputResolvesParentAliasesAndRejectsSpecialTargets(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realDir, alias); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symbolic links are unavailable: %v", err)
		}
		t.Fatal(err)
	}
	direct, err := NormalizeOutput(filepath.Join(realDir, "rules.frs"))
	if err != nil {
		t.Fatal(err)
	}
	throughAlias, err := NormalizeOutput(filepath.Join(alias, ".", "rules.frs"))
	if err != nil {
		t.Fatal(err)
	}
	if direct != throughAlias {
		t.Fatalf("normalized identities differ: %q != %q", direct, throughAlias)
	}
	link := filepath.Join(realDir, "link.frs")
	if err := os.Symlink(filepath.Join(realDir, "elsewhere.frs"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeOutput(link); ErrorCode(err) != CodeOutputInvalid {
		t.Fatalf("symlink output error = %v", err)
	}
}

func TestLockIsNonBlockingAndPersistentMarkerIsNotAnActiveLock(t *testing.T) {
	t.Parallel()
	output, err := NormalizeOutput(filepath.Join(t.TempDir(), "rules.frs"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := Acquire(output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(output); ErrorCode(err) != CodeOutputLocked {
		_ = first.Release()
		t.Fatalf("second lock error = %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lockPath(output)); err != nil {
		t.Fatalf("persistent marker is missing: %v", err)
	}
	second, err := Acquire(output)
	if err != nil {
		t.Fatalf("persistent marker caused a false lock: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestLockIOFailureIsNotReportedAsConflict(t *testing.T) {
	t.Parallel()
	output, err := NormalizeOutput(filepath.Join(t.TempDir(), "rules.frs"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(lockPath(output), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(output); ErrorCode(err) != CodeOutputLock {
		t.Fatalf("lock error = %v", err)
	}
}

func TestStaleCleanupIsTargetScopedAndDoesNotFollowLinks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	first, err := NormalizeOutput(filepath.Join(root, "first.frs"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NormalizeOutput(filepath.Join(root, "second.frs"))
	if err != nil {
		t.Fatal(err)
	}
	stale, err := CreateCandidate(first)
	if err != nil {
		t.Fatal(err)
	}
	stalePath := stale.Name()
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := CreateCandidate(second)
	if err != nil {
		t.Fatal(err)
	}
	otherPath := other.Name()
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	userFile := filepath.Join(root, candidatePrefix(first)+"user")
	if err := os.WriteFile(userFile, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkTarget := filepath.Join(root, "owned-by-user")
	if err := os.WriteFile(linkTarget, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, candidatePrefix(first)+"link.tmp")
	if err := os.Symlink(linkTarget, link); err != nil && runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	if err := CleanupStale(first); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stalePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale candidate still exists: %v", err)
	}
	for _, path := range []string{otherPath, userFile, linkTarget} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("protected path %q was removed: %v", path, err)
		}
	}
}

func TestCommitReplacesOnlyAfterCandidateIsComplete(t *testing.T) {
	t.Parallel()
	output, err := NormalizeOutput(filepath.Join(t.TempDir(), "rules.frs"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate, err := CreateCandidate(output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidate.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := Commit(candidate.Name(), output)
	if err != nil || !result.Committed || !result.Durable {
		t.Fatalf("commit = %+v, %v", result, err)
	}
	data, err := os.ReadFile(output)
	if err != nil || string(data) != "new" {
		t.Fatalf("output = %q, %v", data, err)
	}
}
