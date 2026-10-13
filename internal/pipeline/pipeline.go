package pipeline

import (
	"context"
	"errors"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"

	"frs-tool/internal/extract"
	"frs-tool/internal/source"
)

// RemoteAcquirer 只在完整快照提交边界后返回 FileRef。
type RemoteAcquirer interface {
	Acquire(context.Context, source.PhysicalSource) (source.FileRef, error)
}

// FileExtractor 完整读取 FileRef 后返回互斥终态。
type FileExtractor interface {
	Extract(context.Context, source.FileRef) extract.SourceResult
}

// Config 定义全局池与有界就绪队列。
type Config struct {
	DownloadConcurrency int
	ExtractConcurrency  int
	ReadyCapacity       int
	MaxDiagnostics      int
}

// Metrics 是一次运行的工作池水位。
type Metrics struct {
	DownloadWorkers int
	ExtractWorkers  int
	ReadyCapacity   int
	MaxDownloading  int
	MaxExtracting   int
	ReadyHighWater  int
}

// Result 按物理来源 ID 返回稳定结果。
type Result struct {
	Sources []extract.SourceResult
	Metrics Metrics
}

// Runner 连接全局远程下载池、就绪队列和文件提取池。
type Runner struct {
	config    Config
	acquirer  RemoteAcquirer
	extractor FileExtractor
}

// New 创建固定工作池流水线。
func New(config Config, acquirer RemoteAcquirer, extractor FileExtractor) *Runner {
	if config.DownloadConcurrency < 1 {
		config.DownloadConcurrency = 1
	}
	if config.ExtractConcurrency < 1 {
		config.ExtractConcurrency = 1
	}
	if config.ReadyCapacity < 1 {
		config.ReadyCapacity = config.ExtractConcurrency
	}
	if config.MaxDiagnostics < 0 {
		config.MaxDiagnostics = 0
	}
	return &Runner{config: config, acquirer: acquirer, extractor: extractor}
}

// Run 处理全部物理来源；取消时等待已启动 worker 收敛。
func (r *Runner) Run(ctx context.Context, physical []source.PhysicalSource) (Result, error) {
	if r.acquirer == nil || r.extractor == nil {
		return Result{}, errors.New("pipeline dependencies are nil")
	}
	if len(physical) == 0 {
		return Result{}, nil
	}

	var remotes []source.PhysicalSource
	var locals []source.PhysicalSource
	for _, item := range physical {
		if item.Kind == source.KindRemote {
			remotes = append(remotes, item)
		} else {
			locals = append(locals, item)
		}
	}

	downloadWorkers := min(r.config.DownloadConcurrency, len(remotes))
	extractLimit := min(r.config.ExtractConcurrency, max(1, runtime.GOMAXPROCS(0)))
	extractWorkers := min(extractLimit, len(physical))
	readyCapacity := r.config.ReadyCapacity

	ready := make(chan source.FileRef, readyCapacity)
	results := make(chan extract.SourceResult, max(1, downloadWorkers+extractWorkers+1))
	remoteJobs := make(chan source.PhysicalSource)
	var producers sync.WaitGroup
	var extractors sync.WaitGroup
	var downloading activity
	var extracting activity
	var readyHighWater atomic.Int64

	for worker := 0; worker < extractWorkers; worker++ {
		extractors.Add(1)
		go func() {
			defer extractors.Done()
			for ref := range ready {
				extracting.enter()
				result := r.extractor.Extract(ctx, ref)
				extracting.leave()
				if !sendResult(ctx, results, result) {
					return
				}
			}
		}()
	}

	if len(locals) > 0 {
		producers.Add(1)
		go func() {
			defer producers.Done()
			for _, item := range locals {
				if item.Kind == source.KindInvalid {
					issue := source.AsError(item.Issue())
					if !sendResult(ctx, results, extract.FailedResult(item.ID, item.Location, issue.Code, issue.Message)) {
						return
					}
					continue
				}
				if !sendReady(ctx, ready, source.LocalRef(item), &readyHighWater) {
					return
				}
			}
		}()
	}

	for worker := 0; worker < downloadWorkers; worker++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			for item := range remoteJobs {
				downloading.enter()
				ref, err := r.acquirer.Acquire(ctx, item)
				downloading.leave()
				if err != nil {
					issue := source.AsError(err)
					if !sendResult(ctx, results, extract.FailedResult(item.ID, item.Location, issue.Code, issue.Message)) {
						return
					}
					continue
				}
				if !sendReady(ctx, ready, ref, &readyHighWater) {
					return
				}
			}
		}()
	}

	go func() {
		defer close(remoteJobs)
		for _, item := range remotes {
			select {
			case remoteJobs <- item:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		producers.Wait()
		close(ready)
		extractors.Wait()
		close(results)
	}()

	collected := make([]extract.SourceResult, 0, len(physical))
	for result := range results {
		collected = append(collected, result)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if len(collected) != len(physical) {
		return Result{}, errors.New("pipeline did not produce one result per physical source")
	}
	sort.Slice(collected, func(i, j int) bool {
		return collected[i].SourceID < collected[j].SourceID
	})
	limitDiagnostics(collected, r.config.MaxDiagnostics)
	return Result{
		Sources: collected,
		Metrics: Metrics{
			DownloadWorkers: downloadWorkers,
			ExtractWorkers:  extractWorkers,
			ReadyCapacity:   readyCapacity,
			MaxDownloading:  downloading.maximum(),
			MaxExtracting:   extracting.maximum(),
			ReadyHighWater:  int(readyHighWater.Load()),
		},
	}, nil
}

func limitDiagnostics(results []extract.SourceResult, limit int) {
	remaining := limit
	for index := range results {
		details := results[index].Diagnostics
		if len(details) <= remaining {
			remaining -= len(details)
			continue
		}
		results[index].Truncated += uint64(len(details) - remaining)
		results[index].Diagnostics = details[:remaining]
		remaining = 0
	}
}

func sendReady(ctx context.Context, ready chan<- source.FileRef, ref source.FileRef, highWater *atomic.Int64) bool {
	select {
	case ready <- ref:
		updateMaximum(highWater, int64(len(ready)))
		return true
	case <-ctx.Done():
		return false
	}
}

func sendResult(ctx context.Context, results chan<- extract.SourceResult, result extract.SourceResult) bool {
	select {
	case results <- result:
		return true
	case <-ctx.Done():
		return false
	}
}

type activity struct {
	current      atomic.Int64
	maximumValue atomic.Int64
}

func (a *activity) enter() {
	current := a.current.Add(1)
	updateMaximum(&a.maximumValue, current)
}

func (a *activity) leave() {
	a.current.Add(-1)
}

func (a *activity) maximum() int {
	return int(a.maximumValue.Load())
}

func updateMaximum(target *atomic.Int64, value int64) {
	for {
		current := target.Load()
		if value <= current || target.CompareAndSwap(current, value) {
			return
		}
	}
}
