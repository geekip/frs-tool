package command

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionTextAndJSON(t *testing.T) {
	for _, jsonMode := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		args := []string{"version"}
		if jsonMode {
			args = append(args, "--json")
		}
		if code := Run(context.Background(), args, &stdout, &stderr, ""); code != 0 {
			t.Fatalf("exit = %d", code)
		}
		if stderr.Len() != 0 || !strings.Contains(stdout.String(), "dev") || !strings.Contains(stdout.String(), "1") {
			t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
		if jsonMode {
			assertSingleJSONLine(t, stdout.Bytes())
		}
	}
}

func TestJSONUsageWritesOneObjectOnly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"verify", "--json"}, &stdout, &stderr, ""); code != 2 {
		t.Fatalf("exit = %d", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
	assertSingleJSONLine(t, stdout.Bytes())
	var result usageResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Error == nil || result.Error.Code != "CLI_USAGE" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestBuildVerifyInspectAndWarningStreams(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "rules.txt")
	manifest := filepath.Join(directory, "config.json")
	output := filepath.Join(directory, "rules.frs")
	mustWriteCommand(t, input, []byte("DOMAIN,secret-canary.example\nDOMAIN-REGEX,^hidden$\n"))
	mustWriteCommand(t, manifest, []byte(`{"groups":[{"name":"main","sources":["rules.txt"]}]}`))

	var buildOut, buildErr bytes.Buffer
	if code := Run(context.Background(), []string{"-c", manifest}, &buildOut, &buildErr, ""); code != 0 {
		t.Fatalf("build exit=%d stdout=%q stderr=%q", code, buildOut.String(), buildErr.String())
	}
	if !strings.Contains(buildOut.String(), "status: success_with_warnings") || !strings.Contains(buildErr.String(), "WARN RULE_UNSUPPORTED") {
		t.Fatalf("stdout=%q stderr=%q", buildOut.String(), buildErr.String())
	}

	var verifyOut, verifyErr bytes.Buffer
	if code := Run(context.Background(), []string{"verify", "--json", output}, &verifyOut, &verifyErr, ""); code != 0 {
		t.Fatalf("verify exit=%d", code)
	}
	if verifyErr.Len() != 0 {
		t.Fatalf("verify stderr=%q", verifyErr.String())
	}
	assertSingleJSONLine(t, verifyOut.Bytes())

	var inspectOut, inspectErr bytes.Buffer
	if code := Run(context.Background(), []string{"inspect", output, "--json"}, &inspectOut, &inspectErr, ""); code != 0 {
		t.Fatalf("inspect exit=%d", code)
	}
	if inspectErr.Len() != 0 || strings.Contains(inspectOut.String(), "secret-canary.example") || strings.Contains(inspectOut.String(), "hidden") {
		t.Fatalf("inspect stdout=%q stderr=%q", inspectOut.String(), inspectErr.String())
	}
	assertSingleJSONLine(t, inspectOut.Bytes())
	var inspected inspectResult
	if err := json.Unmarshal(inspectOut.Bytes(), &inspected); err != nil || inspected.Summary == nil || len(inspected.Summary.Sets) != 1 {
		t.Fatalf("inspect=%+v err=%v", inspected, err)
	}
}

func TestDefaultConfigUsesResolvedExecutableDirectory(t *testing.T) {
	realDirectory := t.TempDir()
	linkDirectory := t.TempDir()
	executable := filepath.Join(realDirectory, "frs")
	link := filepath.Join(linkDirectory, "frs-link")
	mustWriteCommand(t, executable, []byte("placeholder"))
	if err := os.Symlink(executable, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	mustWriteCommand(t, filepath.Join(realDirectory, "rules.txt"), []byte("1.2.3.4\n"))
	mustWriteCommand(t, filepath.Join(realDirectory, "config.json"), []byte(`{"groups":[{"name":"main","sources":["rules.txt"]}]}`))

	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"--json"}, &stdout, &stderr, link); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr=%q", stderr.String())
	}
	assertSingleJSONLine(t, stdout.Bytes())
	if _, err := os.Stat(filepath.Join(realDirectory, "rules.frs")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(linkDirectory, "rules.frs")); !os.IsNotExist(err) {
		t.Fatalf("output incorrectly used link directory: %v", err)
	}
}

func TestControlledFailuresAndCanceledExitCodes(t *testing.T) {
	directory := t.TempDir()
	broken := filepath.Join(directory, "broken.frs")
	mustWriteCommand(t, broken, []byte("broken"))

	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"inspect", "--json", broken}, &stdout, &stderr, ""); code != 1 {
		t.Fatalf("inspect exit=%d", code)
	}
	if stderr.Len() != 0 || strings.Contains(stdout.String(), "summary") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	assertSingleJSONLine(t, stdout.Bytes())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"-c", filepath.Join(directory, "missing.json"), "--json"}, &stdout, &stderr, ""); code != 130 {
		t.Fatalf("canceled exit=%d stdout=%q", code, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr=%q", stderr.String())
	}
	assertSingleJSONLine(t, stdout.Bytes())
}

func TestAuxiliaryCommandsRejectBuildFlag(t *testing.T) {
	for _, commandName := range []string{"verify", "inspect", "version"} {
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), []string{commandName, "-c", "config.json"}, &stdout, &stderr, ""); code != 2 {
			t.Fatalf("%s exit=%d", commandName, code)
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "CLI_USAGE") {
			t.Fatalf("%s stdout=%q stderr=%q", commandName, stdout.String(), stderr.String())
		}
	}
}

func assertSingleJSONLine(t *testing.T, data []byte) {
	t.Helper()
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 || !json.Valid(bytes.TrimSuffix(data, []byte{'\n'})) {
		t.Fatalf("not one newline-terminated JSON object: %q", data)
	}
}

func mustWriteCommand(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
