//go:build linux || darwin || freebsd

package command

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"frs-tool/internal/publish"
)

func TestRealProcessLockConflictAndSIGINTCleanup(t *testing.T) {
	var requests atomic.Int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-request.Context().Done():
		}
		_, _ = writer.Write([]byte("1.2.3.4\n"))
	}))
	defer server.Close()
	defer close(release)

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
	case <-time.After(5 * time.Second):
		_ = first.Process.Kill()
		t.Fatal("first process did not reach source acquisition")
	}

	second := helperCommand(t, manifest)
	secondOutput, err := second.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
		_ = first.Process.Kill()
		t.Fatalf("second process err=%v output=%q", err, secondOutput)
	}
	if !strings.Contains(string(secondOutput), publish.CodeOutputLocked) || requests.Load() != 1 {
		_ = first.Process.Kill()
		t.Fatalf("second output=%q requests=%d", secondOutput, requests.Load())
	}
	assertNoProcessCandidates(t, directory)

	if err := first.Process.Signal(os.Interrupt); err != nil {
		_ = first.Process.Kill()
		t.Fatal(err)
	}
	if err := first.Wait(); err == nil {
		t.Fatal("interrupted process unexpectedly succeeded")
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 130 {
		t.Fatalf("first process err=%v output=%q", err, firstOutput.String())
	}
	if !strings.Contains(firstOutput.String(), "BUILD_CANCELED") {
		t.Fatalf("first output=%q", firstOutput.String())
	}
	assertNoProcessCandidates(t, directory)
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("interrupted build published output: %v", err)
	}

	lock, err := publish.Acquire(output)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestInspectUsesOneOpenedViewDuringAtomicReplacement(t *testing.T) {
	directory := t.TempDir()
	makeOutput := func(name, label, rule string) []byte {
		sourcePath := filepath.Join(directory, name+".txt")
		manifestPath := filepath.Join(directory, name+".json")
		outputPath := filepath.Join(directory, name+".frs")
		mustWriteCommand(t, sourcePath, []byte(rule+"\n"))
		mustWriteCommand(t, manifestPath, []byte(fmt.Sprintf(`{"output":%q,"groups":[{"name":%q,"sources":[%q]}]}`, filepath.Base(outputPath), label, filepath.Base(sourcePath))))
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), []string{"-c", manifestPath}, &stdout, &stderr, ""); code != 0 {
			t.Fatalf("fixture build failed: %d %q %q", code, stdout.String(), stderr.String())
		}
		data, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	first := makeOutput("first", "alpha", "1.2.3.4")
	second := makeOutput("second", "beta", "DOMAIN,example.com")
	target := filepath.Join(directory, "changing.frs")
	mustWriteCommand(t, target, first)

	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		defer close(done)
		for iteration := 0; ; iteration++ {
			select {
			case <-stop:
				return
			default:
			}
			data := first
			if iteration%2 != 0 {
				data = second
			}
			temporary := filepath.Join(directory, fmt.Sprintf("replacement-%d.tmp", iteration%2))
			if err := os.WriteFile(temporary, data, 0o600); err != nil {
				done <- err
				return
			}
			if err := os.Rename(temporary, target); err != nil {
				done <- err
				return
			}
		}
	}()
	for iteration := 0; iteration < 100; iteration++ {
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), []string{"inspect", "--json", target}, &stdout, &stderr, ""); code != 0 {
			close(stop)
			<-done
			t.Fatalf("inspect failed: %d %q %q", code, stdout.String(), stderr.String())
		}
		var result inspectResult
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Summary == nil || len(result.Summary.Sets) != 1 {
			close(stop)
			<-done
			t.Fatalf("inspect result=%+v err=%v", result, err)
		}
		label := result.Summary.Sets[0].Label
		if label != "alpha" && label != "beta" {
			close(stop)
			<-done
			t.Fatalf("mixed summary label %q", label)
		}
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCommandHelperProcess(t *testing.T) {
	if os.Getenv("FRS_HELPER_PROCESS") != "1" {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	code := Run(ctx, []string{"-c", os.Getenv("FRS_HELPER_CONFIG")}, os.Stdout, os.Stderr, os.Args[0])
	os.Exit(code)
}

func helperCommand(t *testing.T, manifest string) *exec.Cmd {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestCommandHelperProcess$")
	command.Env = append(os.Environ(), "FRS_HELPER_PROCESS=1", "FRS_HELPER_CONFIG="+manifest)
	return command
}

func assertNoProcessCandidates(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".frs-candidate-") {
			t.Fatalf("candidate remains: %s", entry.Name())
		}
	}
}
