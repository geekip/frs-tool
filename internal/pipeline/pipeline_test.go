package pipeline

import (
	"context"
	"net/url"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"frs-tool/internal/extract"
	"frs-tool/internal/model"
	"frs-tool/internal/source"
)

func TestPipelineGlobalLimitsOrderingAndBackpressure(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)

	physical := make([]source.PhysicalSource, 18)
	for index := range physical {
		physical[index] = pipelineRemote(uint32(index + 1))
	}
	acquirer := &countingAcquirer{delay: 3 * time.Millisecond}
	extractor := &countingExtractor{delay: 4 * time.Millisecond}
	runner := New(Config{
		DownloadConcurrency: 4,
		ExtractConcurrency:  7,
		ReadyCapacity:       2,
		MaxDiagnostics:      10,
	}, acquirer, extractor)
	result, err := runner.Run(context.Background(), physical)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sources) != len(physical) {
		t.Fatalf("results = %d", len(result.Sources))
	}
	for index, item := range result.Sources {
		if item.SourceID != uint32(index+1) {
			t.Fatalf("result order at %d = %d", index, item.SourceID)
		}
		if acquirer.calls(item.SourceID) != 1 || extractor.calls(item.SourceID) != 1 {
			t.Fatalf("source %d calls acquire=%d extract=%d", item.SourceID, acquirer.calls(item.SourceID), extractor.calls(item.SourceID))
		}
	}
	if result.Metrics.DownloadWorkers != 4 || result.Metrics.ExtractWorkers != 4 ||
		result.Metrics.MaxDownloading > 4 || result.Metrics.MaxExtracting > 4 ||
		result.Metrics.ReadyHighWater > 2 || result.Metrics.ReadyCapacity != 2 {
		t.Fatalf("metrics = %+v", result.Metrics)
	}
}

func TestPipelineDefaultConcurrencyBoundariesAreReachable(t *testing.T) {
	previous := runtime.GOMAXPROCS(8)
	defer runtime.GOMAXPROCS(previous)

	physical := make([]source.PhysicalSource, 50)
	for index := range physical {
		physical[index] = pipelineRemote(uint32(index + 1))
	}
	runner := New(Config{
		DownloadConcurrency: 10,
		ExtractConcurrency:  5,
		ReadyCapacity:       5,
		MaxDiagnostics:      0,
	}, &countingAcquirer{delay: 10 * time.Millisecond}, &countingExtractor{delay: 10 * time.Millisecond})
	result, err := runner.Run(context.Background(), physical)
	if err != nil {
		t.Fatal(err)
	}
	if result.Metrics.DownloadWorkers != 10 || result.Metrics.ExtractWorkers != 5 ||
		result.Metrics.MaxDownloading != 10 || result.Metrics.MaxExtracting != 5 {
		t.Fatalf("default concurrency was not reached: %+v", result.Metrics)
	}
}

func TestPipelineBackpressureStopsRemoteJobConsumption(t *testing.T) {
	physical := make([]source.PhysicalSource, 20)
	for index := range physical {
		physical[index] = pipelineRemote(uint32(index + 1))
	}
	acquirer := &totalCountingAcquirer{}
	release := make(chan struct{})
	started := make(chan struct{})
	extractor := &releaseExtractor{started: started, release: release}
	runner := New(Config{
		DownloadConcurrency: 2,
		ExtractConcurrency:  1,
		ReadyCapacity:       1,
		MaxDiagnostics:      0,
	}, acquirer, extractor)
	done := make(chan error, 1)
	go func() {
		_, err := runner.Run(context.Background(), physical)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("extractor did not start")
	}
	deadline := time.Now().Add(time.Second)
	for acquirer.calls.Load() < 4 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	first := acquirer.calls.Load()
	time.Sleep(20 * time.Millisecond)
	second := acquirer.calls.Load()
	if first != 4 || second != first {
		t.Fatalf("downloads passed bounded queue: first=%d second=%d, want stable 4", first, second)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("pipeline did not finish after releasing extractor")
	}
}

func TestPipelineOverlapsReadyLocalExtractionWithRemoteAcquisition(t *testing.T) {
	block := make(chan struct{})
	started := make(chan struct{})
	acquirer := &blockingAcquirer{started: started, release: block}
	extracted := make(chan uint32, 2)
	extractor := extractorFunc(func(ctx context.Context, ref source.FileRef) extract.SourceResult {
		extracted <- ref.SourceID
		return extract.SourceResult{SourceID: ref.SourceID, Location: ref.Location, Status: extract.StatusEmpty}
	})
	physical := []source.PhysicalSource{
		pipelineRemote(1),
		{ID: 2, Kind: source.KindLocal, Location: "local", LocalPath: "unused"},
	}
	runner := New(Config{
		DownloadConcurrency: 1,
		ExtractConcurrency:  1,
		ReadyCapacity:       1,
		MaxDiagnostics:      10,
	}, acquirer, extractor)
	done := make(chan error, 1)
	go func() {
		_, err := runner.Run(context.Background(), physical)
		done <- err
	}()
	<-started
	select {
	case id := <-extracted:
		if id != 2 {
			t.Fatalf("remote source extracted before complete snapshot: %d", id)
		}
	case <-time.After(time.Second):
		t.Fatal("ready local source did not overlap remote acquisition")
	}
	close(block)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("pipeline did not finish")
	}
}

func TestPipelineAppliesGlobalDiagnosticLimitInSourceOrder(t *testing.T) {
	physical := []source.PhysicalSource{
		{ID: 1, Kind: source.KindLocal, Location: "one", LocalPath: "unused"},
		{ID: 2, Kind: source.KindLocal, Location: "two", LocalPath: "unused"},
		{ID: 3, Kind: source.KindLocal, Location: "three", LocalPath: "unused"},
	}
	extractor := extractorFunc(func(ctx context.Context, ref source.FileRef) extract.SourceResult {
		return extract.SourceResult{
			SourceID: ref.SourceID,
			Location: ref.Location,
			Status:   extract.StatusEmpty,
			Diagnostics: []model.Diagnostic{
				{Code: "A", Position: model.SourcePosition{SourceID: ref.SourceID, Line: 1}},
				{Code: "B", Position: model.SourcePosition{SourceID: ref.SourceID, Line: 2}},
			},
			DiagnosticCount: map[string]uint64{"A": 1, "B": 1},
		}
	})
	runner := New(Config{
		DownloadConcurrency: 1,
		ExtractConcurrency:  3,
		ReadyCapacity:       1,
		MaxDiagnostics:      3,
	}, &countingAcquirer{}, extractor)
	result, err := runner.Run(context.Background(), physical)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sources[0].Diagnostics) != 2 ||
		len(result.Sources[1].Diagnostics) != 1 ||
		len(result.Sources[2].Diagnostics) != 0 {
		t.Fatalf("diagnostic allocation = %d/%d/%d",
			len(result.Sources[0].Diagnostics),
			len(result.Sources[1].Diagnostics),
			len(result.Sources[2].Diagnostics))
	}
	if result.Sources[1].Truncated != 1 || result.Sources[2].Truncated != 2 {
		t.Fatalf("truncated counts = %d/%d", result.Sources[1].Truncated, result.Sources[2].Truncated)
	}
	if result.Sources[2].DiagnosticCount["A"] != 1 {
		t.Fatal("aggregate counts were truncated")
	}
}

func TestPipelineCancellationConverges(t *testing.T) {
	acquirer := &blockingAcquirer{started: make(chan struct{}), release: make(chan struct{})}
	runner := New(Config{
		DownloadConcurrency: 1,
		ExtractConcurrency:  1,
		ReadyCapacity:       1,
		MaxDiagnostics:      1,
	}, acquirer, &countingExtractor{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := runner.Run(ctx, []source.PhysicalSource{pipelineRemote(1)})
		done <- err
	}()
	<-acquirer.started
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled pipeline succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled pipeline did not converge")
	}
}

func TestPipelineResultsDoNotDependOnWorkerCounts(t *testing.T) {
	t.Parallel()
	physical := make([]source.PhysicalSource, 12)
	for index := range physical {
		physical[index] = pipelineRemote(uint32(index + 1))
	}
	fileExtractor := extract.New(extract.Config{MaxLineSize: 1024, MaxDiagnostics: 10})
	var baseline []extract.SourceResult
	for _, workers := range []int{1, 2, 5, 10} {
		runner := New(Config{
			DownloadConcurrency: workers,
			ExtractConcurrency:  workers,
			ReadyCapacity:       2,
			MaxDiagnostics:      10,
		}, &countingAcquirer{}, fileExtractor)
		result, err := runner.Run(context.Background(), physical)
		if err != nil {
			t.Fatal(err)
		}
		if baseline == nil {
			baseline = result.Sources
			continue
		}
		if !reflect.DeepEqual(baseline, result.Sources) {
			t.Fatalf("source results changed with %d workers", workers)
		}
	}
}

func BenchmarkPipeline(b *testing.B) {
	physical := make([]source.PhysicalSource, 100)
	for index := range physical {
		physical[index] = pipelineRemote(uint32(index + 1))
	}
	for _, workers := range []int{1, 5, 10} {
		b.Run("workers-"+strconv.Itoa(workers), func(b *testing.B) {
			for iteration := 0; iteration < b.N; iteration++ {
				runner := New(Config{
					DownloadConcurrency: workers,
					ExtractConcurrency:  workers,
					ReadyCapacity:       workers,
					MaxDiagnostics:      0,
				}, &countingAcquirer{}, &countingExtractor{})
				if _, err := runner.Run(context.Background(), physical); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

type countingAcquirer struct {
	delay     time.Duration
	mu        sync.Mutex
	callCount map[uint32]int
}

func (a *countingAcquirer) Acquire(ctx context.Context, item source.PhysicalSource) (source.FileRef, error) {
	a.mu.Lock()
	if a.callCount == nil {
		a.callCount = make(map[uint32]int)
	}
	a.callCount[item.ID]++
	a.mu.Unlock()
	if a.delay > 0 {
		timer := time.NewTimer(a.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return source.FileRef{}, ctx.Err()
		case <-timer.C:
		}
	}
	return source.MemoryRef(item.ID, item.Location, []byte("example.com")), nil
}

func (a *countingAcquirer) calls(id uint32) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.callCount[id]
}

type countingExtractor struct {
	delay     time.Duration
	mu        sync.Mutex
	callCount map[uint32]int
	active    atomic.Int64
}

func (e *countingExtractor) Extract(ctx context.Context, ref source.FileRef) extract.SourceResult {
	e.active.Add(1)
	defer e.active.Add(-1)
	e.mu.Lock()
	if e.callCount == nil {
		e.callCount = make(map[uint32]int)
	}
	e.callCount[ref.SourceID]++
	e.mu.Unlock()
	if e.delay > 0 {
		timer := time.NewTimer(e.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return extract.FailedResult(ref.SourceID, ref.Location, "SOURCE_CANCELED", "canceled")
		case <-timer.C:
		}
	}
	return extract.SourceResult{SourceID: ref.SourceID, Location: ref.Location, Status: extract.StatusEmpty}
}

func (e *countingExtractor) calls(id uint32) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.callCount[id]
}

type blockingAcquirer struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type totalCountingAcquirer struct {
	calls atomic.Int64
}

func (a *totalCountingAcquirer) Acquire(_ context.Context, item source.PhysicalSource) (source.FileRef, error) {
	a.calls.Add(1)
	return source.MemoryRef(item.ID, item.Location, []byte("example.com")), nil
}

type releaseExtractor struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (e *releaseExtractor) Extract(ctx context.Context, ref source.FileRef) extract.SourceResult {
	e.once.Do(func() { close(e.started) })
	select {
	case <-ctx.Done():
		return extract.FailedResult(ref.SourceID, ref.Location, "SOURCE_CANCELED", "canceled")
	case <-e.release:
		return extract.SourceResult{SourceID: ref.SourceID, Location: ref.Location, Status: extract.StatusEmpty}
	}
}

func (a *blockingAcquirer) Acquire(ctx context.Context, item source.PhysicalSource) (source.FileRef, error) {
	a.once.Do(func() { close(a.started) })
	select {
	case <-ctx.Done():
		return source.FileRef{}, ctx.Err()
	case <-a.release:
		return source.MemoryRef(item.ID, item.Location, []byte("remote.example")), nil
	}
}

type extractorFunc func(context.Context, source.FileRef) extract.SourceResult

func (function extractorFunc) Extract(ctx context.Context, ref source.FileRef) extract.SourceResult {
	return function(ctx, ref)
}

func pipelineRemote(id uint32) source.PhysicalSource {
	value, _ := url.Parse("http://example.test/" + time.Duration(id).String())
	return source.NewRemoteSource(id, value)
}
