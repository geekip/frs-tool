package build

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// BenchmarkBuildRealFixture 使用完整 HTTP、提取、归并、自检和发布路径。
func BenchmarkBuildRealFixture(b *testing.B) {
	const sourceCount = 12
	const rulesPerSource = 2000
	contents := make(map[string][]byte, sourceCount)
	for sourceIndex := 0; sourceIndex < sourceCount; sourceIndex++ {
		var content strings.Builder
		for line := 0; line < rulesPerSource; line++ {
			if line%2 == 0 {
				value := uint32(0x0a000000) + uint32(sourceIndex*rulesPerSource+line)
				address := netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
				content.WriteString(address.String())
			} else {
				fmt.Fprintf(&content, "DOMAIN,rule-%d-%d.example.com", sourceIndex, line)
			}
			content.WriteByte('\n')
		}
		contents["/source-"+strconv.Itoa(sourceIndex)] = []byte(content.String())
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		data, exists := contents[request.URL.Path]
		if !exists {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = writer.Write(data)
	}))
	b.Cleanup(server.Close)

	directory := b.TempDir()
	var sources strings.Builder
	for sourceIndex := 0; sourceIndex < sourceCount; sourceIndex++ {
		if sourceIndex > 0 {
			sources.WriteByte(',')
		}
		sources.WriteString(strconv.Quote(server.URL + "/source-" + strconv.Itoa(sourceIndex)))
	}
	manifest := filepath.Join(directory, "config.json")
	configuration := fmt.Sprintf(`{"output":"rules.frs","download":{"retries":0},"groups":[{"name":"benchmark","sources":[%s]}]}`, sources.String())
	if err := os.WriteFile(manifest, []byte(configuration), 0o600); err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(sourceCount*rulesPerSource, "rules/op")
	b.SetBytes(int64(totalBytes(contents)))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		report := New().Run(context.Background(), manifest)
		if report.Status != StatusSuccess || report.PublishState != PublishPublished || report.Rules.Accepted != sourceCount*rulesPerSource {
			b.Fatalf("report = %+v", report)
		}
	}
}

func totalBytes(values map[string][]byte) int {
	total := 0
	for _, value := range values {
		total += len(value)
	}
	return total
}
