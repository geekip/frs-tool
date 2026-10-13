package extract

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"frs-tool/internal/model"
	"frs-tool/internal/source"
)

func TestExtractClassifiesAndDeduplicatesOnePass(t *testing.T) {
	t.Parallel()
	text := strings.Join([]string{
		"IP-CIDR,192.168.1.7/24",
		"192.168.1.0/24",
		"DOMAIN,Exact.Example",
		"domain:Suffix.Example",
		"keyword:Media",
		"2001:db8::1",
		"DOMAIN-REGEX,unsupported",
	}, "\r\n")
	extractor := New(Config{MaxLineSize: 16 * 1024, MaxDiagnostics: 10})
	result := extractor.Extract(context.Background(), source.MemoryRef(7, "fixture", []byte(text)))
	if result.Status != StatusSuccess {
		t.Fatalf("status = %q, error=%s", result.Status, result.ErrorCode)
	}
	if len(result.IPv4) != 1 || result.IPv4[0].Prefix.String() != "192.168.1.0/24" {
		t.Fatalf("IPv4 records = %+v", result.IPv4)
	}
	if len(result.Domains) != 3 {
		t.Fatalf("domain records = %+v", result.Domains)
	}
	if result.Stats.Accepted != 5 || result.Stats.Retained != 4 ||
		result.Stats.FilteredIPv6 != 1 || result.Stats.Skipped != 1 {
		t.Fatalf("stats = %+v", result.Stats)
	}
	if result.DiagnosticCount["RULE_UNSUPPORTED"] != 1 {
		t.Fatalf("diagnostic counts = %+v", result.DiagnosticCount)
	}
	for _, record := range append(append([]model.Record(nil), result.IPv4...), result.Domains...) {
		if record.Position.SourceID != 7 || record.Position.Location != "fixture" {
			t.Fatalf("record lost source position: %+v", record)
		}
	}
}

func TestExtractRecoversOverlongTerminatedLine(t *testing.T) {
	t.Parallel()
	text := "123456789" + string(byte(10)) + "a.com" + string(byte(10))
	extractor := New(Config{MaxLineSize: 8, MaxDiagnostics: 1})
	result := extractor.Extract(context.Background(), source.MemoryRef(1, "long", []byte(text)))
	if result.Status != StatusSuccess || len(result.Domains) != 1 || result.Domains[0].Value != "a.com" {
		t.Fatalf("result = %+v", result)
	}
	if result.DiagnosticCount["RULE_LINE_TOO_LONG"] != 1 || len(result.Diagnostics) != 1 {
		t.Fatalf("line warning = %+v", result)
	}
}

func TestExtractDiscardsAllRecordsOnUnrecoverableBoundaryOrReadFailure(t *testing.T) {
	t.Parallel()
	extractor := New(Config{MaxLineSize: 8, MaxDiagnostics: 10})
	unrecoverable := "a.com" + string(byte(10)) + "123456789"
	result := extractor.Extract(context.Background(), source.MemoryRef(1, "boundary", []byte(unrecoverable)))
	if result.Status != StatusFailed || result.ErrorCode != "SOURCE_LINE_BOUNDARY" ||
		len(result.IPv4)+len(result.Domains) != 0 {
		t.Fatalf("unrecoverable result = %+v", result)
	}

	ref := source.ReaderRef(2, "broken", func() (io.ReadCloser, error) {
		return io.NopCloser(&failAfterReader{data: []byte("a.com" + string(byte(10)))}), nil
	})
	result = extractor.Extract(context.Background(), ref)
	if result.Status != StatusFailed || result.ErrorCode != "SOURCE_READ" ||
		len(result.IPv4)+len(result.Domains) != 0 {
		t.Fatalf("read failure result = %+v", result)
	}
}

func TestExtractRejectsInvalidTextAndContainers(t *testing.T) {
	t.Parallel()
	extractor := New(Config{MaxLineSize: 1024, MaxDiagnostics: 10})
	tests := [][]byte{
		{0xff, byte(10)},
		[]byte("<html>" + string(byte(10)) + "example.com"),
		{0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf, 'a'},
		{'a', 0, 'b'},
		{'P', 'K', 0x03, 0x04, 'a'},
	}
	for _, data := range tests {
		result := extractor.Extract(context.Background(), source.MemoryRef(1, "invalid", data))
		if result.Status != StatusFailed || len(result.IPv4)+len(result.Domains) != 0 {
			t.Errorf("invalid source accepted: %+v", result)
		}
	}
}

func TestExtractHandlesSingleTypeAndLargeSourcesWithoutProductCapacityLimit(t *testing.T) {
	t.Parallel()
	extractor := New(Config{MaxLineSize: 1024, MaxDiagnostics: 10})
	cases := []struct {
		name       string
		body       string
		wantIPv4   int
		wantDomain int
	}{
		{name: "IP only", body: strings.Repeat("10.0.0.0/24\n", 20000), wantIPv4: 1},
		{name: "domain only", body: strings.Repeat("large.example\n", 20000), wantDomain: 1},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := extractor.Extract(context.Background(), source.MemoryRef(1, test.name, []byte(test.body)))
			if result.Status != StatusSuccess || len(result.IPv4) != test.wantIPv4 || len(result.Domains) != test.wantDomain {
				t.Fatalf("large single-type result = %+v", result)
			}
			if result.Stats.Accepted != 20000 {
				t.Fatalf("accepted = %d, want 20000", result.Stats.Accepted)
			}
		})
	}
}

func TestExtractBoundsDetailedDiagnosticsWithoutLosingCounts(t *testing.T) {
	t.Parallel()
	text := strings.Join([]string{"UNKNOWN,one", "UNKNOWN,two", "*.bad.example"}, string(byte(10)))
	extractor := New(Config{MaxLineSize: 1024, MaxDiagnostics: 1})
	result := extractor.Extract(context.Background(), source.MemoryRef(1, "warnings", []byte(text)))
	if result.Status != StatusEmpty {
		t.Fatalf("status = %q", result.Status)
	}
	if len(result.Diagnostics) != 1 || result.Truncated != 2 || result.Stats.Skipped != 3 {
		t.Fatalf("bounded diagnostics = %+v", result)
	}
	if result.DiagnosticCount["RULE_UNSUPPORTED"] != 2 ||
		result.DiagnosticCount["RULE_WILDCARD"] != 1 {
		t.Fatalf("diagnostic aggregation = %+v", result.DiagnosticCount)
	}
}

func TestExtractCloseFailureDiscardsRecords(t *testing.T) {
	t.Parallel()
	ref := source.ReaderRef(1, "close", func() (io.ReadCloser, error) {
		return closeFailReader{Reader: strings.NewReader("a.com")}, nil
	})
	result := New(Config{MaxLineSize: 1024, MaxDiagnostics: 10}).Extract(context.Background(), ref)
	if result.Status != StatusFailed || result.ErrorCode != "SOURCE_CLOSE" ||
		len(result.IPv4)+len(result.Domains) != 0 {
		t.Fatalf("close failure result = %+v", result)
	}
}

type failAfterReader struct {
	data []byte
	done bool
}

func (r *failAfterReader) Read(buffer []byte) (int, error) {
	if len(r.data) > 0 {
		count := copy(buffer, r.data)
		r.data = r.data[count:]
		return count, nil
	}
	if !r.done {
		r.done = true
		return 0, errors.New("injected read failure")
	}
	return 0, io.EOF
}

type closeFailReader struct {
	io.Reader
}

func (closeFailReader) Close() error {
	return errors.New("injected close failure")
}
