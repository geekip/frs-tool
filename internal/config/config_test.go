package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimalManifest = `{"groups":[{"name":"base","sources":["./rules.txt"]}]}`

func TestLoadDefaultsAndRealManifestDirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(realDir, "config.json")
	writeManifest(t, manifestPath, minimalManifest)
	linkPath := filepath.Join(root, "config-link.json")
	if err := os.Symlink(manifestPath, linkPath); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ManifestPath != manifestPath {
		t.Errorf("ManifestPath = %q, want %q", cfg.ManifestPath, manifestPath)
	}
	if cfg.Output != filepath.Join(realDir, "rules.frs") {
		t.Errorf("Output = %q", cfg.Output)
	}
	if cfg.Download.Concurrency != 10 || cfg.Download.PerHostConcurrency != 3 ||
		cfg.Download.Timeout != 120*time.Second || cfg.Download.ConnectTimeout != 10*time.Second ||
		cfg.Download.Retries != 3 || cfg.Extract.Concurrency != 5 ||
		cfg.Build.MaxLineSize != 16*1024 || cfg.Build.MaxDiagnostics != 1000 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestPublicExampleConfigLoads(t *testing.T) {
	t.Parallel()
	cfg, err := Load(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Download.Concurrency != DefaultDownloadConcurrency || cfg.Download.PerHostConcurrency != DefaultPerHostConcurrency ||
		cfg.Extract.Concurrency != DefaultExtractConcurrency || cfg.Build.MaxLineSize != DefaultMaxLineSize ||
		cfg.Build.MaxDiagnostics != DefaultMaxDiagnostics || len(cfg.Groups) != 1 {
		t.Fatalf("example config = %+v", cfg)
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Parallel()
	manifest := `{
		"output":"dist/custom.frs",
		"ipv6":false,
		"download":{
			"concurrency":4,
			"per-host-concurrency":2,
			"timeout":"30s",
			"connect-timeout":"2s",
			"retries":0,
			"proxy":{"enable":true,"url":"https://user:pass@proxy.example:8443"}
		},
		"extract":{"concurrency":2},
		"build":{"max-line-size":"32KiB","max-diagnostics":0},
		"groups":[{"name":"　媒体 规则　","sources":["　./list.txt　"]}]
	}`
	path := filepath.Join(t.TempDir(), "config.json")
	writeManifest(t, path, manifest)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Output != filepath.Join(filepath.Dir(path), "dist", "custom.frs") {
		t.Errorf("Output = %q", cfg.Output)
	}
	if cfg.Download.Concurrency != 4 || cfg.Download.PerHostConcurrency != 2 ||
		cfg.Download.Timeout != 30*time.Second || cfg.Download.ConnectTimeout != 2*time.Second ||
		cfg.Download.Retries != 0 || cfg.Extract.Concurrency != 2 ||
		cfg.Build.MaxLineSize != 32*1024 || cfg.Build.MaxDiagnostics != 0 {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if !cfg.Download.Proxy.Enabled || cfg.Download.Proxy.URL == nil {
		t.Fatal("proxy was not parsed")
	}
	if cfg.Groups[0].Name != "媒体 规则" || cfg.Groups[0].Sources[0] != "./list.txt" {
		t.Fatalf("fixed whitespace was not trimmed: %+v", cfg.Groups[0])
	}
}

func TestLoadRejectsStrictJSONViolations(t *testing.T) {
	t.Parallel()
	backslash := string(byte(92))
	tests := []struct {
		name string
		data []byte
		code string
	}{
		{"unknown", []byte(`{"version":1,"groups":[]}`), "CONFIG_UNKNOWN_FIELD"},
		{"renamed output", []byte(`{"output-dir":".","groups":[]}`), "CONFIG_UNKNOWN_FIELD"},
		{"case changed key", []byte(`{"Groups":[]}`), "CONFIG_UNKNOWN_FIELD"},
		{"source object", []byte(`{"groups":[{"name":"a","sources":[{"url":"https://example.test","header":{"Authorization":"x"}}]}]}`), "CONFIG_SCHEMA"},
		{"download headers", []byte(`{"download":{"headers":{"Authorization":"x"}},"groups":[]}`), "CONFIG_UNKNOWN_FIELD"},
		{"proxy username", []byte(`{"download":{"proxy":{"username":"x"}},"groups":[]}`), "CONFIG_UNKNOWN_FIELD"},
		{"memory limit", []byte(`{"build":{"max-memory":"200MiB"},"groups":[]}`), "CONFIG_UNKNOWN_FIELD"},
		{"source size limit", []byte(`{"build":{"max-source-size":"64MiB"},"groups":[]}`), "CONFIG_UNKNOWN_FIELD"},
		{"staging limit", []byte(`{"build":{"max-staging-size":"64MiB"},"groups":[]}`), "CONFIG_UNKNOWN_FIELD"},
		{"record limit", []byte(`{"build":{"max-record-bytes":"64MiB"},"groups":[]}`), "CONFIG_UNKNOWN_FIELD"},
		{"output size limit", []byte(`{"build":{"max-output-size":"64MiB"},"groups":[]}`), "CONFIG_UNKNOWN_FIELD"},
		{"duplicate decoded key", []byte(`{"groups":[],"gr` + backslash + `u006fups":[]}`), "CONFIG_JSON"},
		{"trailing value", []byte(`{"groups":[]} {}`), "CONFIG_JSON"},
		{"null", []byte(`{"download":null,"groups":[]}`), "CONFIG_JSON"},
		{"unpaired surrogate", []byte(`{"groups":[{"name":"` + backslash + `ud800","sources":["a"]}]}`), "CONFIG_ENCODING"},
		{"invalid UTF-8", append([]byte(`{"groups":[{"name":"`), 0xff), "CONFIG_ENCODING"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("Load unexpectedly succeeded")
			}
			if code := ErrorCode(err); code != test.code {
				t.Fatalf("ErrorCode = %q, want %q; err=%v", code, test.code, err)
			}
		})
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	t.Parallel()
	controlLabel := `{"groups":[{"name":"a` + string(rune(0x80)) + `b","sources":["x"]}]}`
	leadingTabLabel := `{"groups":[{"name":"` + string(byte(92)) + `tname","sources":["x"]}]}`
	tests := map[string]string{
		"ipv6":              `{"ipv6":true,"groups":[{"name":"a","sources":["x"]}]}`,
		"empty groups":      `{"groups":[]}`,
		"empty source":      `{"groups":[{"name":"a","sources":["　"]}]}`,
		"duplicate label":   `{"groups":[{"name":"a","sources":["x"]},{"name":"a","sources":["y"]}]}`,
		"comma label":       `{"groups":[{"name":"a,b","sources":["x"]}]}`,
		"control label":     controlLabel,
		"leading tab label": leadingTabLabel,
		"zero concurrency":  `{"extract":{"concurrency":0},"groups":[{"name":"a","sources":["x"]}]}`,
		"negative retries":  `{"download":{"retries":-1},"groups":[{"name":"a","sources":["x"]}]}`,
		"bad duration":      `{"download":{"timeout":"0s"},"groups":[{"name":"a","sources":["x"]}]}`,
		"bad line size":     `{"build":{"max-line-size":"16KB"},"groups":[{"name":"a","sources":["x"]}]}`,
		"enabled no proxy":  `{"download":{"proxy":{"enable":true}},"groups":[{"name":"a","sources":["x"]}]}`,
		"unsupported proxy": `{"download":{"proxy":{"url":"socks5://localhost:1080"}},"groups":[{"name":"a","sources":["x"]}]}`,
	}
	for name, manifest := range tests {
		name, manifest := name, manifest
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "config.json")
			writeManifest(t, path, manifest)
			if _, err := Load(path); err == nil {
				t.Fatal("Load unexpectedly succeeded")
			}
		})
	}
}

func TestLoadAcceptsSingleBOMAndUnicodeLabels(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.json")
	data := append([]byte{0xef, 0xbb, 0xbf}, []byte(`{"groups":[{"name":"国内👨‍👩‍👧","sources":["x"]}]}`)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg.Groups[0].Name, "国内") {
		t.Fatalf("unicode label changed: %q", cfg.Groups[0].Name)
	}

	doubleBOMPath := filepath.Join(t.TempDir(), "config.json")
	doubleBOM := append([]byte{0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf}, []byte(minimalManifest)...)
	if err := os.WriteFile(doubleBOMPath, doubleBOM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(doubleBOMPath); err == nil {
		t.Fatal("two UTF-8 BOMs were accepted")
	}
}

func writeManifest(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
