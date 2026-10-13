package build

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"frs-tool/internal/config"
	"frs-tool/internal/extract"
	"frs-tool/internal/frs"
	"frs-tool/internal/merge"
	"frs-tool/internal/pipeline"
	"frs-tool/internal/publish"
	"frs-tool/internal/source"
)

const (
	CodeCanceled = "BUILD_CANCELED"
	CodePipeline = "BUILD_PIPELINE"
	CodeMerge    = "BUILD_MERGE"
	CodeEmpty    = "EMPTY_RESULT"
	CodeEncode   = "BUILD_ENCODE"
	CodeWrite    = "OUTPUT_WRITE"
	CodeFlush    = "OUTPUT_FLUSH"
	CodeSync     = "OUTPUT_SYNC"
	CodeClose    = "OUTPUT_CLOSE"
	CodeRead     = "OUTPUT_READ"
	CodeVerify   = "OUTPUT_VERIFY"
	CodeConflict = "OUTPUT_SOURCE_CONFLICT"
	CodeInternal = "BUILD_INTERNAL"
)

type candidate interface {
	io.Writer
	Name() string
	Sync() error
	Close() error
}

type locker interface {
	Release() error
}

// Services 暴露文件系统与流水线故障注入边界。
type Services struct {
	LoadConfig      func(string) (config.Config, error)
	NormalizeOutput func(string) (string, error)
	AcquireLock     func(string) (locker, error)
	CleanupStale    func(string) error
	CreateCandidate func(string) (candidate, error)
	RemoveCandidate func(string) error
	ReadFile        func(string) ([]byte, error)
	Commit          func(string, string) (publish.CommitResult, error)
	RunPipeline     func(context.Context, config.Config, source.Index) (pipeline.Result, error)
	Merge           func([]config.Group, []source.SourceBinding, []extract.SourceResult) ([]merge.Set, merge.Stats, error)
	Encode          func([]merge.Set) ([]byte, error)
	Verify          func([]byte) (frs.Summary, error)
}

// DefaultServices 返回生产构建使用的标准服务集合。
func DefaultServices() Services {
	return Services{
		LoadConfig:      config.Load,
		NormalizeOutput: publish.NormalizeOutput,
		AcquireLock: func(output string) (locker, error) {
			return publish.Acquire(output)
		},
		CleanupStale: publish.CleanupStale,
		CreateCandidate: func(output string) (candidate, error) {
			return publish.CreateCandidate(output)
		},
		RemoveCandidate: publish.RemoveCandidate,
		ReadFile:        os.ReadFile,
		Commit:          publish.Commit,
		RunPipeline:     runPipeline,
		Merge:           merge.Build,
		Encode:          frs.Encode,
		Verify:          frs.Verify,
	}
}

// Builder 编排从严格 manifest 到单文件原子发布的完整构建。
type Builder struct {
	services Services
}

// New 使用生产服务创建 Builder。
func New() *Builder {
	return NewWithServices(DefaultServices())
}

// NewWithServices 创建可做故障注入的 Builder。
func NewWithServices(services Services) *Builder {
	return &Builder{services: services}
}

// Run 执行一次构建，并始终返回可渲染的最终报告。
func (b *Builder) Run(ctx context.Context, manifestPath string) Report {
	started := time.Now()
	report := newReport()
	finish := func() Report {
		report.DurationMS = max(0, time.Since(started).Milliseconds())
		return report
	}
	fail := func(code, stage, message string) Report {
		report.Status = StatusError
		report.Error = &ErrorInfo{Code: code, Stage: stage, Message: message}
		return finish()
	}

	if err := b.valid(); err != nil {
		return fail(CodeInternal, "initialize", "build services are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return fail(CodeCanceled, "initialize", "build canceled")
	}
	cfg, err := b.services.LoadConfig(manifestPath)
	if err != nil {
		code := config.ErrorCode(err)
		if code == "" {
			code = "CONFIG_INVALID"
		}
		return fail(code, "config", "configuration is invalid")
	}
	output, err := b.services.NormalizeOutput(cfg.Output)
	if err != nil {
		return fail(errorCode(err, publish.CodeOutputInvalid), "output", "output path is invalid")
	}
	report.Output = output

	lock, err := b.services.AcquireLock(output)
	if err != nil {
		return fail(errorCode(err, publish.CodeOutputLock), "lock", "cannot acquire output lock")
	}
	lockHeld := true
	release := func() error {
		if !lockHeld {
			return nil
		}
		lockHeld = false
		return lock.Release()
	}
	finishLocked := func(result Report) Report {
		if err := release(); err != nil {
			report = result
			report.Status = StatusError
			report.Error = &ErrorInfo{Code: errorCode(err, publish.CodeOutputLock), Stage: "lock_release", Message: "cannot release output lock"}
			return finish()
		}
		return result
	}

	if err := b.services.CleanupStale(output); err != nil {
		return finishLocked(fail(errorCode(err, publish.CodeCleanup), "cleanup", "cannot clean stale candidates"))
	}
	if err := ctx.Err(); err != nil {
		return finishLocked(fail(CodeCanceled, "collect", "build canceled"))
	}
	flat := source.Flatten(cfg)
	for _, physical := range flat.Sources {
		if physical.Kind == source.KindLocal && samePath(physical.LocalPath, output) {
			return finishLocked(fail(CodeConflict, "collect", "output path is also a local source"))
		}
	}
	run, err := b.services.RunPipeline(ctx, cfg, flat)
	if err != nil {
		if ctx.Err() != nil {
			return finishLocked(fail(CodeCanceled, "collect", "build canceled"))
		}
		return finishLocked(fail(CodePipeline, "collect", "source pipeline failed"))
	}
	sets, stats, err := b.services.Merge(cfg.Groups, flat.Bindings, run.Sources)
	if err != nil {
		return finishLocked(fail(CodeMerge, "merge", "cannot merge source results"))
	}
	groupNames := make([]string, len(cfg.Groups))
	for position := range cfg.Groups {
		groupNames[position] = cfg.Groups[position].Name
	}
	fillStats(&report, groupNames, flat.Bindings, run.Sources, stats, cfg.Build.MaxDiagnostics)
	b.addEmptyGroupWarnings(&report, cfg, sets)
	if len(sets) == 0 || stats.UniqueRecords == 0 {
		return finishLocked(fail(CodeEmpty, "merge", "no usable rules were produced"))
	}
	if err := ctx.Err(); err != nil {
		return finishLocked(fail(CodeCanceled, "encode", "build canceled"))
	}
	encoded, err := b.services.Encode(sets)
	if err != nil {
		return finishLocked(fail(errorCode(err, CodeEncode), "encode", "cannot encode FRS data"))
	}

	file, err := b.services.CreateCandidate(output)
	if err != nil {
		return finishLocked(fail(errorCode(err, publish.CodeCreate), "candidate_create", "cannot create output candidate"))
	}
	candidatePath := file.Name()
	closed := false
	cleanup := func() error {
		if !closed {
			_ = file.Close()
			closed = true
		}
		return b.services.RemoveCandidate(candidatePath)
	}
	failCandidate := func(code, stage, message string) Report {
		if cleanupErr := cleanup(); cleanupErr != nil {
			return finishLocked(fail(errorCode(cleanupErr, publish.CodeCleanup), "cleanup", "cannot remove output candidate"))
		}
		return finishLocked(fail(code, stage, message))
	}

	buffered := bufio.NewWriterSize(file, 64*1024)
	if err := writeAll(buffered, encoded); err != nil {
		return failCandidate(CodeWrite, "candidate_write", "cannot write output candidate")
	}
	if err := buffered.Flush(); err != nil {
		return failCandidate(CodeFlush, "candidate_flush", "cannot flush output candidate")
	}
	if err := file.Sync(); err != nil {
		return failCandidate(CodeSync, "candidate_sync", "cannot sync output candidate")
	}
	if err := file.Close(); err != nil {
		closed = true
		return failCandidate(CodeClose, "candidate_close", "cannot close output candidate")
	}
	closed = true
	data, err := b.services.ReadFile(candidatePath)
	if err != nil {
		return failCandidate(CodeRead, "verify", "cannot read output candidate")
	}
	summary, err := b.services.Verify(data)
	if err != nil {
		return failCandidate(errorCode(err, CodeVerify), "verify", "output candidate failed strict verification")
	}
	report.File = &FileInfo{Bytes: summary.FileBytes, Checksum: summary.Checksum}
	if err := ctx.Err(); err != nil {
		return failCandidate(CodeCanceled, "publish", "build canceled")
	}
	commit, err := b.services.Commit(candidatePath, output)
	if err != nil {
		if commit.Committed {
			report.PublishState = PublishUncertain
			candidatePath = ""
			return finishLocked(fail(errorCode(err, publish.CodeDirSync), "publish", "output replacement durability is uncertain"))
		}
		return failCandidate(errorCode(err, publish.CodeRename), "publish", "cannot replace output")
	}
	if !commit.Committed || !commit.Durable {
		report.PublishState = PublishUncertain
		candidatePath = ""
		return finishLocked(fail(CodeInternal, "publish", "output commit returned an invalid state"))
	}
	candidatePath = ""
	report.PublishState = PublishPublished
	report.Error = nil
	if report.Warnings.Total == 0 {
		report.Status = StatusSuccess
	} else {
		report.Status = StatusSuccessWithWarnings
	}
	return finishLocked(finish())
}

func samePath(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func (b *Builder) valid() error {
	services := b.services
	if services.LoadConfig == nil || services.NormalizeOutput == nil || services.AcquireLock == nil ||
		services.CleanupStale == nil || services.CreateCandidate == nil || services.RemoveCandidate == nil ||
		services.ReadFile == nil || services.Commit == nil || services.RunPipeline == nil || services.Merge == nil ||
		services.Encode == nil || services.Verify == nil {
		return errors.New("incomplete build services")
	}
	return nil
}

func (b *Builder) addEmptyGroupWarnings(report *Report, cfg config.Config, sets []merge.Set) {
	present := make(map[string]struct{}, len(sets))
	for _, set := range sets {
		present[set.Label] = struct{}{}
	}
	for _, group := range cfg.Groups {
		if _, exists := present[group.Name]; exists {
			continue
		}
		addWarning(report, "GROUP_EMPTY", 1)
		if len(report.Warnings.Details) < cfg.Build.MaxDiagnostics {
			report.Warnings.Details = append(report.Warnings.Details, Warning{Code: "GROUP_EMPTY", Group: group.Name, Message: "group contained no usable rules"})
			report.Warnings.Expanded++
		}
	}
	if report.Warnings.Total > report.Warnings.Expanded {
		report.Warnings.Truncated = report.Warnings.Total - report.Warnings.Expanded
	}
}

func runPipeline(ctx context.Context, cfg config.Config, flat source.Index) (pipeline.Result, error) {
	acquirer := source.NewHTTPAcquirer(cfg.Download)
	extractor := extract.New(extract.Config{MaxLineSize: cfg.Build.MaxLineSize, MaxDiagnostics: cfg.Build.MaxDiagnostics})
	runner := pipeline.New(pipeline.Config{
		DownloadConcurrency: cfg.Download.Concurrency,
		ExtractConcurrency:  cfg.Extract.Concurrency,
		ReadyCapacity:       cfg.Extract.Concurrency,
		MaxDiagnostics:      cfg.Build.MaxDiagnostics,
	}, acquirer, extractor)
	return runner.Run(ctx, flat.Sources)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if count < 0 || count > len(data) {
			return io.ErrShortWrite
		}
		data = data[count:]
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func errorCode(err error, fallback string) string {
	for _, code := range []string{config.ErrorCode(err), publish.ErrorCode(err), frs.ErrorCode(err)} {
		if code != "" {
			return code
		}
	}
	return fallback
}
