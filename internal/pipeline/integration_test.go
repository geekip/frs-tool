package pipeline_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"frs-tool/internal/config"
	"frs-tool/internal/extract"
	"frs-tool/internal/merge"
	"frs-tool/internal/pipeline"
	"frs-tool/internal/source"
)

func TestLocalRemotePipelineSourceReuseAndMerge(t *testing.T) {
	t.Parallel()
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		_, _ = writer.Write([]byte("DOMAIN-SUFFIX,shared.example"))
	}))
	defer server.Close()

	base := t.TempDir()
	localPath := filepath.Join(base, "local.txt")
	if err := os.WriteFile(localPath, []byte("10.0.0.0/24"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		BaseDir: base,
		Download: config.DownloadConfig{
			Concurrency:        10,
			PerHostConcurrency: 3,
			Timeout:            2 * time.Second,
			ConnectTimeout:     time.Second,
			Retries:            0,
		},
		Extract: config.ExtractConfig{Concurrency: 5},
		Build: config.BuildConfig{
			MaxLineSize:    16 * 1024,
			MaxDiagnostics: 100,
		},
		Groups: []config.Group{
			{Name: "alpha", Sources: []string{"local.txt", server.URL}},
			{Name: "beta", Sources: []string{server.URL, server.URL}},
		},
	}
	flat := source.Flatten(cfg)
	if len(flat.Sources) != 2 || len(flat.Bindings) != 4 {
		t.Fatalf("flat index = %+v", flat)
	}
	acquirer := source.NewHTTPAcquirer(cfg.Download)
	fileExtractor := extract.New(extract.Config{
		MaxLineSize:    cfg.Build.MaxLineSize,
		MaxDiagnostics: cfg.Build.MaxDiagnostics,
	})
	runner := pipeline.New(pipeline.Config{
		DownloadConcurrency: cfg.Download.Concurrency,
		ExtractConcurrency:  cfg.Extract.Concurrency,
		ReadyCapacity:       cfg.Extract.Concurrency,
		MaxDiagnostics:      cfg.Build.MaxDiagnostics,
	}, acquirer, fileExtractor)
	run, err := runner.Run(context.Background(), flat.Sources)
	if err != nil {
		t.Fatal(err)
	}
	sets, stats, err := merge.Build(cfg.Groups, flat.Bindings, run.Sources)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("shared remote source downloaded %d times", requests.Load())
	}
	if len(sets) != 3 ||
		sets[0].Kind != merge.SetIPv4 || sets[0].Label != "alpha" ||
		sets[1].Kind != merge.SetDomain || sets[1].Label != "alpha" ||
		sets[2].Kind != merge.SetDomain || sets[2].Label != "beta" {
		t.Fatalf("sets = %+v", sets)
	}
	if stats.InputRecords != 4 || stats.UniqueRecords != 3 {
		t.Fatalf("stats = %+v", stats)
	}

	secondRun, err := runner.Run(context.Background(), flat.Sources)
	if err != nil {
		t.Fatal(err)
	}
	secondSets, secondStats, err := merge.Build(cfg.Groups, flat.Bindings, secondRun.Sources)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sets, secondSets) || stats != secondStats {
		t.Fatal("pipeline completion order changed merged output")
	}
}
