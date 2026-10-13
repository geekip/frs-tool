package build

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"frs-tool/internal/config"
	"frs-tool/internal/extract"
	"frs-tool/internal/frs"
	"frs-tool/internal/merge"
	"frs-tool/internal/model"
	"frs-tool/internal/pipeline"
	"frs-tool/internal/publish"
	"frs-tool/internal/source"
)

func TestBuildPublishesVerifiedFileAndReportsFacts(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "rules.txt")
	manifest := filepath.Join(directory, "config.json")
	output := filepath.Join(directory, "out.frs")
	mustWrite(t, input, []byte("1.2.3.4\nDOMAIN,example.com\n"))
	mustWrite(t, output, []byte("old"))
	mustWrite(t, manifest, []byte(`{"output":"out.frs","groups":[{"name":"main","sources":["rules.txt"]}]}`))

	report := New().Run(context.Background(), manifest)
	if report.Status != StatusSuccess || report.PublishState != PublishPublished || report.Error != nil {
		t.Fatalf("report = %+v", report)
	}
	if report.Sources.References != 1 || report.Sources.Physical != 1 || report.Sources.Success != 1 ||
		report.Rules.Accepted != 2 || report.Rules.UniqueRecords != 2 || report.Sets.IPv4 != 1 || report.Sets.Domain != 1 {
		t.Fatalf("unexpected counters: %+v", report)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := frs.Verify(data)
	if err != nil {
		t.Fatal(err)
	}
	if report.File == nil || report.File.Bytes != summary.FileBytes || report.File.Checksum != summary.Checksum {
		t.Fatalf("file report = %+v, summary = %+v", report.File, summary)
	}
	assertNoCandidates(t, output)
}

func TestBuildAllEmptyPreservesOldOutput(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "empty.txt")
	manifest := filepath.Join(directory, "config.json")
	output := filepath.Join(directory, "rules.frs")
	old := []byte("old-output")
	mustWrite(t, input, []byte("# comments only\n"))
	mustWrite(t, output, old)
	mustWrite(t, manifest, []byte(`{"groups":[{"name":"empty","sources":["empty.txt"]}]}`))

	report := New().Run(context.Background(), manifest)
	if report.Status != StatusError || report.PublishState != PublishNotPublished || report.Error == nil || report.Error.Code != CodeEmpty || report.File != nil {
		t.Fatalf("report = %+v", report)
	}
	if actual, err := os.ReadFile(output); err != nil || !bytes.Equal(actual, old) {
		t.Fatalf("old output changed: %q, %v", actual, err)
	}
	if report.Sources.Empty != 1 || report.Warnings.ByCode["SOURCE_EMPTY"] != 1 || report.Warnings.ByCode["GROUP_EMPTY"] != 1 {
		t.Fatalf("warning report = %+v", report.Warnings)
	}
	assertNoCandidates(t, output)
}

func TestBuildPublishesWithSourceAndRuleWarningsUsingBoundedDetails(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "rules.txt")
	manifest := filepath.Join(directory, "config.json")
	mustWrite(t, input, []byte("1.2.3.4\nDOMAIN-REGEX,^one$\nDOMAIN-REGEX,^two$\n"))
	mustWrite(t, manifest, []byte(`{"build":{"max-diagnostics":1},"groups":[{"name":"main","sources":["rules.txt","missing.txt"]}]}`))

	report := New().Run(context.Background(), manifest)
	if report.Status != StatusSuccessWithWarnings || report.PublishState != PublishPublished || report.Error != nil {
		t.Fatalf("report = %+v", report)
	}
	if report.Sources.References != 2 || report.Sources.Physical != 2 || report.Sources.Success != 1 || report.Sources.Failed != 1 || report.Sources.Empty != 0 {
		t.Fatalf("sources = %+v", report.Sources)
	}
	if report.Warnings.Total != 3 || report.Warnings.Expanded != 1 || report.Warnings.Truncated != 2 || len(report.Warnings.Details) != 1 {
		t.Fatalf("warnings = %+v", report.Warnings)
	}
	if report.Warnings.ByCode["RULE_UNSUPPORTED"] != 2 || report.Warnings.ByCode["SOURCE_OPEN"] != 1 {
		t.Fatalf("warning codes = %+v", report.Warnings.ByCode)
	}
}

func TestBuildConfigurationFailureHasNoProductFacts(t *testing.T) {
	report := New().Run(context.Background(), filepath.Join(t.TempDir(), "missing.json"))
	if report.Status != StatusError || report.PublishState != PublishNotPublished || report.Error == nil ||
		report.Error.Code != "CONFIG_READ" || report.Output != "" || report.File != nil || report.Sources.Physical != 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestBuildRejectsOutputSourceConflictBeforeRead(t *testing.T) {
	directory := t.TempDir()
	manifest := filepath.Join(directory, "config.json")
	output := filepath.Join(directory, "same.txt")
	old := []byte("1.2.3.4\n")
	mustWrite(t, output, old)
	mustWrite(t, manifest, []byte(`{"output":"same.txt","groups":[{"name":"main","sources":["same.txt"]}]}`))

	report := New().Run(context.Background(), manifest)
	if report.Error == nil || report.Error.Code != CodeConflict || report.PublishState != PublishNotPublished {
		t.Fatalf("report = %+v", report)
	}
	if actual, err := os.ReadFile(output); err != nil || !bytes.Equal(actual, old) {
		t.Fatalf("source/output changed: %q, %v", actual, err)
	}
}

func TestBuildLockConflictIsImmediateAndDoesNotRunPipeline(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "rules.frs")
	services := successfulServices(t, output)
	called := false
	services.RunPipeline = func(context.Context, config.Config, source.Index) (pipeline.Result, error) {
		called = true
		return pipeline.Result{}, nil
	}
	lock, err := publish.Acquire(output)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()

	report := NewWithServices(services).Run(context.Background(), "unused")
	if report.Error == nil || report.Error.Code != publish.CodeOutputLocked || called {
		t.Fatalf("report = %+v, pipeline called = %v", report, called)
	}
}

func TestBuildCancellationAfterVerificationCleansCandidate(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "rules.frs")
	old := []byte("old")
	mustWrite(t, output, old)
	services := successfulServices(t, output)
	ctx, cancel := context.WithCancel(context.Background())
	verify := services.Verify
	services.Verify = func(data []byte) (frs.Summary, error) {
		summary, err := verify(data)
		cancel()
		return summary, err
	}

	report := NewWithServices(services).Run(ctx, "unused")
	if report.Error == nil || report.Error.Code != CodeCanceled || report.PublishState != PublishNotPublished || report.File == nil {
		t.Fatalf("report = %+v", report)
	}
	if actual, err := os.ReadFile(output); err != nil || !bytes.Equal(actual, old) {
		t.Fatalf("old output changed: %q, %v", actual, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".tmp" {
			t.Fatalf("candidate remains: %s", entry.Name())
		}
	}
}

func TestBuildCandidateAndCommitFailures(t *testing.T) {
	tests := []struct {
		name         string
		configure    func(*Services, *faultCandidate)
		code         string
		publishState string
		fileInfo     bool
	}{
		{name: "write", code: CodeWrite, publishState: PublishNotPublished, configure: func(services *Services, file *faultCandidate) {
			services.Encode = func([]merge.Set) ([]byte, error) { return make([]byte, 128*1024), nil }
			file.writeErr = errors.New("write")
		}},
		{name: "flush", code: CodeFlush, publishState: PublishNotPublished, configure: func(_ *Services, file *faultCandidate) { file.writeErr = errors.New("flush") }},
		{name: "sync", code: CodeSync, publishState: PublishNotPublished, configure: func(_ *Services, file *faultCandidate) { file.syncErr = errors.New("sync") }},
		{name: "close", code: CodeClose, publishState: PublishNotPublished, configure: func(_ *Services, file *faultCandidate) { file.closeErr = errors.New("close") }},
		{name: "verify", code: "FRS_CHECKSUM", publishState: PublishNotPublished, configure: func(services *Services, _ *faultCandidate) {
			services.Verify = func([]byte) (frs.Summary, error) {
				return frs.Summary{}, &frs.Error{Code: "FRS_CHECKSUM", Message: "bad"}
			}
		}},
		{name: "rename", code: publish.CodeRename, publishState: PublishNotPublished, fileInfo: true, configure: func(services *Services, _ *faultCandidate) {
			services.Commit = func(string, string) (publish.CommitResult, error) {
				return publish.CommitResult{}, errors.New("rename")
			}
		}},
		{name: "directory sync", code: publish.CodeDirSync, publishState: PublishUncertain, fileInfo: true, configure: func(services *Services, _ *faultCandidate) {
			services.Commit = func(string, string) (publish.CommitResult, error) {
				return publish.CommitResult{Committed: true}, &publish.Error{Code: publish.CodeDirSync, Message: "sync"}
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			output := filepath.Join(directory, "rules.frs")
			old := []byte("old")
			mustWrite(t, output, old)
			services := successfulServices(t, output)
			var candidateFile *faultCandidate
			services.CreateCandidate = func(output string) (candidate, error) {
				file, err := os.CreateTemp(filepath.Dir(output), ".candidate-*.tmp")
				if err != nil {
					return nil, err
				}
				candidateFile = &faultCandidate{File: file}
				return candidateFile, nil
			}
			test.configure(&services, candidateFilePlaceholder(&candidateFile))
			// 创建后才能给候选对象设置故障，因此由工厂复制预设值。
			preset := candidateFilePlaceholder(&candidateFile)
			services.CreateCandidate = func(output string) (candidate, error) {
				file, err := os.CreateTemp(filepath.Dir(output), ".candidate-*.tmp")
				if err != nil {
					return nil, err
				}
				candidateFile = &faultCandidate{File: file, writeErr: preset.writeErr, syncErr: preset.syncErr, closeErr: preset.closeErr}
				return candidateFile, nil
			}

			report := NewWithServices(services).Run(context.Background(), "unused")
			if report.Error == nil || report.Error.Code != test.code || report.PublishState != test.publishState || (report.File != nil) != test.fileInfo {
				t.Fatalf("report = %+v", report)
			}
			if test.publishState != PublishUncertain {
				if actual, err := os.ReadFile(output); err != nil || !bytes.Equal(actual, old) {
					t.Fatalf("old output changed: %q, %v", actual, err)
				}
			}
			if candidateFile != nil && test.publishState != PublishUncertain {
				if _, err := os.Stat(candidateFile.Name()); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("candidate remains: %v", err)
				}
			}
		})
	}
}

type faultCandidate struct {
	*os.File
	writeErr error
	syncErr  error
	closeErr error
}

func (f *faultCandidate) Write(data []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.File.Write(data)
}

func (f *faultCandidate) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.Sync()
}

func (f *faultCandidate) Close() error {
	err := f.File.Close()
	if f.closeErr != nil {
		return f.closeErr
	}
	return err
}

func candidateFilePlaceholder(target **faultCandidate) *faultCandidate {
	if *target == nil {
		*target = &faultCandidate{}
	}
	return *target
}

func successfulServices(t *testing.T, output string) Services {
	t.Helper()
	services := DefaultServices()
	services.LoadConfig = func(string) (config.Config, error) {
		return config.Config{
			BaseDir: filepath.Dir(output), Output: output,
			Download: config.DownloadConfig{Concurrency: 1}, Extract: config.ExtractConfig{Concurrency: 1},
			Build:  config.BuildConfig{MaxLineSize: 1024, MaxDiagnostics: 10},
			Groups: []config.Group{{Name: "main", Sources: []string{"input.txt"}}},
		}, nil
	}
	services.RunPipeline = func(context.Context, config.Config, source.Index) (pipeline.Result, error) {
		return pipeline.Result{Sources: []extract.SourceResult{{
			SourceID: 1, Location: "input.txt", Status: extract.StatusSuccess,
			IPv4:  []model.Record{{Kind: model.RuleIPv4, Prefix: netip.MustParsePrefix("1.2.3.4/32")}},
			Stats: extract.Stats{Accepted: 1, Retained: 1}, DiagnosticCount: map[string]uint64{},
		}}}, nil
	}
	return services
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertNoCandidates(t *testing.T, output string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(output))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if len(entry.Name()) >= len(".frs-candidate-") && entry.Name()[:len(".frs-candidate-")] == ".frs-candidate-" {
			t.Fatalf("candidate remains: %s", entry.Name())
		}
	}
}
