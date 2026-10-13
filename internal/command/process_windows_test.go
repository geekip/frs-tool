//go:build windows

package command

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"frs-tool/internal/publish"
)

func TestRealProcessLockConflictAndCrashRelease(t *testing.T) {
	var requests atomic.Int32
	entered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-request.Context().Done()
	}))
	defer server.Close()

	directory := t.TempDir()
	manifest := filepath.Join(directory, "config.json")
	output := filepath.Join(directory, "rules.frs")
	mustWriteCommand(t, manifest, []byte(fmt.Sprintf(`{"download":{"retries":0},"groups":[{"name":"main","sources":[%q]}]}`, server.URL)))
	first := helperCommand(t, manifest)
	var firstOutput bytes.Buffer
	first.Stdout = &firstOutput
	first.Stderr = &firstOutput
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		_ = first.Process.Kill()
		t.Fatal("first process did not reach source acquisition")
	}
	secondOutput, err := helperCommand(t, manifest).CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || !strings.Contains(string(secondOutput), publish.CodeOutputLocked) || requests.Load() != 1 {
		_ = first.Process.Kill()
		t.Fatalf("second err=%v output=%q requests=%d", err, secondOutput, requests.Load())
	}
	if err := first.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = first.Wait()
	lock, err := publish.Acquire(output)
	if err != nil {
		t.Fatalf("lock was not released after process exit: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestCommandHelperProcess(t *testing.T) {
	if os.Getenv("FRS_HELPER_PROCESS") != "1" {
		return
	}
	code := Run(context.Background(), []string{"-c", os.Getenv("FRS_HELPER_CONFIG")}, os.Stdout, os.Stderr, os.Args[0])
	os.Exit(code)
}

func helperCommand(t *testing.T, manifest string) *exec.Cmd {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestCommandHelperProcess$")
	command.Env = append(os.Environ(), "FRS_HELPER_PROCESS=1", "FRS_HELPER_CONFIG="+manifest)
	return command
}
