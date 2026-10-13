package source

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"frs-tool/internal/config"
)

func TestFlattenDeduplicatesPhysicalSourcesAndKeepsBindings(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	localPath := filepath.Join(base, "rules.txt")
	if err := os.WriteFile(localPath, []byte("example.com"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileURLPath := filepath.ToSlash(localPath)
	if runtime.GOOS == "windows" {
		fileURLPath = "/" + fileURLPath
	}
	fileURL := (&url.URL{Scheme: "file", Path: fileURLPath}).String()
	cfg := config.Config{
		BaseDir: base,
		Download: config.DownloadConfig{
			Proxy: config.ProxyConfig{},
		},
		Groups: []config.Group{
			{Name: "one", Sources: []string{"rules.txt", fileURL, "https://user:secret@example.test/list?q=1"}},
			{Name: "two", Sources: []string{"https://user:secret@example.test/list?q=1"}},
		},
	}

	index := Flatten(cfg)
	if len(index.Sources) != 2 {
		t.Fatalf("physical sources = %d, want 2", len(index.Sources))
	}
	if len(index.Bindings) != 4 {
		t.Fatalf("bindings = %d, want 4", len(index.Bindings))
	}
	if index.Bindings[0].PhysicalID != index.Bindings[1].PhysicalID {
		t.Fatal("local path and equivalent file URL were not deduplicated")
	}
	if index.Bindings[2].PhysicalID != index.Bindings[3].PhysicalID {
		t.Fatal("shared remote source was not deduplicated")
	}
	remote := index.Sources[1]
	for _, visible := range []string{remote.Location, remote.KeyID} {
		if strings.Contains(visible, "user") || strings.Contains(visible, "secret") {
			t.Fatalf("credential leaked through public source field: %q", visible)
		}
	}
	if visible := fmt.Sprintf("%+v", remote); strings.Contains(visible, "user") || strings.Contains(visible, "secret") {
		t.Fatalf("credential leaked through source formatting: %q", visible)
	}
	encoded, err := json.Marshal(remote)
	if err != nil {
		t.Fatal(err)
	}
	if visible := string(encoded); strings.Contains(visible, "user") || strings.Contains(visible, "secret") {
		t.Fatalf("credential leaked through source JSON: %q", visible)
	}
	if remote.Location != "https://example.test/list?q=1" {
		t.Fatalf("redacted location = %q", remote.Location)
	}
}

func TestFlattenAcquisitionKeyIncludesQueryAuthAndProxy(t *testing.T) {
	t.Parallel()
	base := config.Config{
		BaseDir: t.TempDir(),
		Download: config.DownloadConfig{
			Proxy: config.ProxyConfig{},
		},
		Groups: []config.Group{{
			Name: "one",
			Sources: []string{
				"https://one:secret@example.test/list?q=1",
				"https://two:secret@example.test/list?q=1",
				"https://one:secret@example.test/list?q=2",
			},
		}},
	}
	index := Flatten(base)
	if len(index.Sources) != 3 {
		t.Fatalf("distinct query/auth sources merged: %d", len(index.Sources))
	}

	proxyURL, err := url.Parse("http://proxy-user:proxy-secret@proxy.test:8080")
	if err != nil {
		t.Fatal(err)
	}
	withProxy := base
	withProxy.Download.Proxy = config.ProxyConfig{Enabled: true, URL: proxyURL}
	proxied := Flatten(withProxy)
	if index.Sources[0].KeyID == proxied.Sources[0].KeyID {
		t.Fatal("proxy identity is absent from acquisition key")
	}
	if strings.Contains(proxied.Sources[0].KeyID, "proxy-secret") {
		t.Fatal("key ID exposes proxy credentials")
	}
}

func TestFlattenRejectsUnsupportedAndNonLocalFileURLs(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		BaseDir: t.TempDir(),
		Groups: []config.Group{{
			Name:    "one",
			Sources: []string{"ftp://user:secret@example.test/list", "file://remotehost/path"},
		}},
	}
	index := Flatten(cfg)
	if len(index.Sources) != 2 {
		t.Fatalf("sources = %d", len(index.Sources))
	}
	for _, physical := range index.Sources {
		if physical.Kind != KindInvalid || physical.Issue() == nil {
			t.Fatalf("invalid source was accepted: %+v", physical)
		}
		if strings.Contains(physical.Location, "user") || strings.Contains(physical.Location, "secret") {
			t.Fatalf("invalid source location leaked credentials: %q", physical.Location)
		}
	}
}

func TestMemoryRefCopiesInput(t *testing.T) {
	t.Parallel()
	data := []byte("example.com")
	ref := MemoryRef(1, "memory", data)
	data[0] = 'X'
	reader, err := ref.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	buffer := make([]byte, len(data))
	if _, err := reader.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "example.com" {
		t.Fatalf("snapshot mutated: %q", buffer)
	}
}
