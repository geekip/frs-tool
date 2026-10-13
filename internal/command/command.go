// Package command 实现 frs 的稳定命令行契约与输出流边界。
package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	buildrun "frs-tool/internal/build"
	frsformat "frs-tool/internal/format"
	"frs-tool/internal/frs"
	toolversion "frs-tool/internal/version"
)

const (
	exitSuccess = 0
	exitFailure = 1
	exitUsage   = 2
	exitSIGINT  = 130
)

// Run 执行命令并返回稳定进程退出码。
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, executable string) int {
	cleaned, jsonMode, err := extractJSONFlag(args)
	if err != nil {
		return renderUsage(jsonMode, stdout, stderr, err.Error())
	}
	if len(cleaned) > 0 {
		switch cleaned[0] {
		case "verify":
			return runVerify(ctx, cleaned[1:], jsonMode, stdout, stderr)
		case "inspect":
			return runInspect(ctx, cleaned[1:], jsonMode, stdout, stderr)
		case "version":
			return runVersion(cleaned[1:], jsonMode, stdout, stderr)
		case "help", "-h", "--help":
			if len(cleaned) != 1 {
				return renderUsage(jsonMode, stdout, stderr, "help accepts no arguments")
			}
			return renderHelp(jsonMode, stdout, stderr)
		}
	}
	return runBuild(ctx, cleaned, jsonMode, stdout, stderr, executable)
}

func runBuild(ctx context.Context, args []string, jsonMode bool, stdout, stderr io.Writer, executable string) int {
	manifest, err := buildManifestPath(args, executable)
	if err != nil {
		return renderUsage(jsonMode, stdout, stderr, err.Error())
	}
	report := buildrun.New().Run(ctx, manifest)
	if err := renderBuild(report, jsonMode, stdout, stderr); err != nil {
		return exitFailure
	}
	if report.Error != nil && report.Error.Code == buildrun.CodeCanceled {
		return exitSIGINT
	}
	if report.Status == buildrun.StatusError {
		return exitFailure
	}
	return exitSuccess
}

func runVerify(ctx context.Context, args []string, jsonMode bool, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		return renderUsage(jsonMode, stdout, stderr, "verify requires exactly one file")
	}
	summary, controlled := readAndVerify(ctx, args[0])
	result := verifyResult{Status: statusError, Path: args[0]}
	if controlled == nil {
		valid := true
		result.Status = statusSuccess
		result.Format = &formatResult{Major: summary.Major, Minor: summary.Minor}
		result.Bytes = &summary.FileBytes
		result.Checksum = &summary.Checksum
		result.ChecksumValid = &valid
	} else {
		result.Error = controlled
	}
	if err := renderVerify(result, jsonMode, stdout, stderr); err != nil {
		return exitFailure
	}
	if controlled != nil {
		if controlled.Code == buildrun.CodeCanceled {
			return exitSIGINT
		}
		return exitFailure
	}
	return exitSuccess
}

func runInspect(ctx context.Context, args []string, jsonMode bool, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		return renderUsage(jsonMode, stdout, stderr, "inspect requires exactly one file")
	}
	summary, controlled := readAndVerify(ctx, args[0])
	result := inspectResult{Status: statusError, Path: args[0]}
	if controlled == nil {
		value := makeInspectSummary(summary)
		result.Status = statusSuccess
		result.Summary = &value
	} else {
		result.Error = controlled
	}
	if err := renderInspect(result, jsonMode, stdout, stderr); err != nil {
		return exitFailure
	}
	if controlled != nil {
		if controlled.Code == buildrun.CodeCanceled {
			return exitSIGINT
		}
		return exitFailure
	}
	return exitSuccess
}

func runVersion(args []string, jsonMode bool, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		return renderUsage(jsonMode, stdout, stderr, "version accepts no arguments")
	}
	result := versionResult{
		Status: statusSuccess, Version: toolversion.Version,
		Format: formatResult{Major: frsformat.VersionMajor, Minor: frsformat.VersionMinor},
	}
	if jsonMode {
		if err := writeJSON(stdout, result); err != nil {
			return exitFailure
		}
		return exitSuccess
	}
	if _, err := fmt.Fprintf(stdout, "frs %s\nFRS %d.%d\n", result.Version, result.Format.Major, result.Format.Minor); err != nil {
		return exitFailure
	}
	return exitSuccess
}

func readAndVerify(ctx context.Context, path string) (frs.Summary, *commandError) {
	if err := ctx.Err(); err != nil {
		return frs.Summary{}, &commandError{Code: buildrun.CodeCanceled, Stage: "read", Message: "operation canceled"}
	}
	file, err := os.Open(path)
	if err != nil {
		return frs.Summary{}, &commandError{Code: "FILE_OPEN", Stage: "read", Message: "cannot open FRS file"}
	}
	data, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil {
		return frs.Summary{}, &commandError{Code: "FILE_READ", Stage: "read", Message: "cannot read FRS file"}
	}
	if closeErr != nil {
		return frs.Summary{}, &commandError{Code: "FILE_CLOSE", Stage: "read", Message: "cannot close FRS file"}
	}
	if err := ctx.Err(); err != nil {
		return frs.Summary{}, &commandError{Code: buildrun.CodeCanceled, Stage: "verify", Message: "operation canceled"}
	}
	summary, err := frs.Verify(data)
	if err != nil {
		code := frs.ErrorCode(err)
		if code == "" {
			code = "FRS_VERIFY"
		}
		return frs.Summary{}, &commandError{Code: code, Stage: "verify", Message: "FRS verification failed"}
	}
	return summary, nil
}

func extractJSONFlag(args []string) ([]string, bool, error) {
	cleaned := make([]string, 0, len(args))
	jsonMode := false
	for _, arg := range args {
		if arg == "--json" {
			if jsonMode {
				return nil, true, errors.New("--json may only be specified once")
			}
			jsonMode = true
			continue
		}
		cleaned = append(cleaned, arg)
	}
	return cleaned, jsonMode, nil
}

func buildManifestPath(args []string, executable string) (string, error) {
	if len(args) == 0 {
		return defaultManifestPath(executable)
	}
	if len(args) == 2 && args[0] == "-c" && strings.TrimSpace(args[1]) != "" {
		return args[1], nil
	}
	if len(args) == 1 && strings.HasPrefix(args[0], "-c=") && strings.TrimSpace(strings.TrimPrefix(args[0], "-c=")) != "" {
		return strings.TrimPrefix(args[0], "-c="), nil
	}
	return "", errors.New("build accepts only -c <config.json>")
}

func defaultManifestPath(executable string) (string, error) {
	path := executable
	var err error
	if path == "" {
		path, err = os.Executable()
		if err != nil {
			return "", errors.New("cannot locate executable")
		}
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", errors.New("cannot resolve executable path")
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", errors.New("cannot resolve executable path")
	}
	return filepath.Join(filepath.Dir(path), "config.json"), nil
}

func renderUsage(jsonMode bool, stdout, stderr io.Writer, message string) int {
	value := usageResult{Status: statusError, Error: &commandError{Code: "CLI_USAGE", Stage: "cli", Message: message}}
	if jsonMode {
		if err := writeJSON(stdout, value); err != nil {
			return exitUsage
		}
		return exitUsage
	}
	_, _ = fmt.Fprintf(stderr, "ERROR CLI_USAGE: %s\n", message)
	return exitUsage
}

func renderHelp(jsonMode bool, stdout, stderr io.Writer) int {
	if jsonMode {
		value := struct {
			Status string `json:"status"`
			Usage  string `json:"usage"`
		}{Status: statusSuccess, Usage: "frs [-c config.json] | verify file | inspect file | version"}
		if err := writeJSON(stdout, value); err != nil {
			return exitFailure
		}
		return exitSuccess
	}
	if _, err := io.WriteString(stdout, "Usage: frs [-c config.json]\n       frs verify <file.frs>\n       frs inspect <file.frs>\n       frs version\n"); err != nil {
		return exitFailure
	}
	return exitSuccess
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
