package extract

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"sort"
	"strings"

	"frs-tool/internal/model"
	"frs-tool/internal/parser"
	"frs-tool/internal/source"
)

// Status 表示物理来源的互斥提取终态。
type Status string

const (
	StatusSuccess Status = "success"
	StatusEmpty   Status = "empty"
	StatusFailed  Status = "failed"
)

// Stats 保存不受诊断明细截断影响的来源计数。
type Stats struct {
	Accepted     uint64
	Retained     uint64
	Ignored      uint64
	FilteredIPv6 uint64
	Skipped      uint64
}

// SourceResult 只在完整读取成功后携带来源私有记录。
type SourceResult struct {
	SourceID        uint32
	Location        string
	Status          Status
	IPv4            []model.Record
	Domains         []model.Record
	Stats           Stats
	Diagnostics     []model.Diagnostic
	DiagnosticCount map[string]uint64
	Truncated       uint64
	ErrorCode       string
	ErrorMessage    string
}

// FailedResult 创建不携带任何部分记录的失败结果。
func FailedResult(sourceID uint32, location, code, message string) SourceResult {
	return SourceResult{
		SourceID:     sourceID,
		Location:     location,
		Status:       StatusFailed,
		ErrorCode:    code,
		ErrorMessage: message,
	}
}

// Config 控制逐文件读取边界和来源级诊断保留量。
type Config struct {
	MaxLineSize    int64
	MaxDiagnostics int
}

// Extractor 对一个来源执行单遍 IP/域名分类。
type Extractor struct {
	config Config
}

// New 创建文件级提取器。
func New(config Config) *Extractor {
	if config.MaxLineSize < 1 {
		config.MaxLineSize = 1
	}
	if config.MaxDiagnostics < 0 {
		config.MaxDiagnostics = 0
	}
	return &Extractor{config: config}
}

// Extract 完整扫描一个来源；任何读取失败都会丢弃此前的记录。
func (e *Extractor) Extract(ctx context.Context, ref source.FileRef) SourceResult {
	reader, err := ref.Open()
	if err != nil {
		return FailedResult(ref.SourceID, ref.Location, "SOURCE_OPEN", "cannot open source")
	}

	result := SourceResult{
		SourceID:        ref.SourceID,
		Location:        ref.Location,
		Status:          StatusEmpty,
		DiagnosticCount: make(map[string]uint64),
	}
	buffered := bufio.NewReaderSize(reader, 64*1024)
	lineNumber := uint64(0)
	checkedContainer := false
	for {
		if err := ctx.Err(); err != nil {
			_ = reader.Close()
			return FailedResult(ref.SourceID, ref.Location, "SOURCE_CANCELED", "source extraction canceled")
		}
		line, tooLong, terminated, readErr := readLine(buffered, e.config.MaxLineSize)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = reader.Close()
			return FailedResult(ref.SourceID, ref.Location, "SOURCE_READ", "cannot read complete source")
		}
		lineNumber++
		position := model.SourcePosition{
			SourceID: ref.SourceID,
			Location: ref.Location,
			Line:     lineNumber,
			Column:   1,
		}
		if tooLong {
			if !terminated {
				_ = reader.Close()
				return FailedResult(ref.SourceID, ref.Location, "SOURCE_LINE_BOUNDARY", "overlong line has no recoverable boundary")
			}
			result.Stats.Skipped++
			result.addDiagnostic(e.config.MaxDiagnostics, model.Diagnostic{
				Code:     "RULE_LINE_TOO_LONG",
				Message:  "line exceeds configured limit",
				Position: position,
			})
			continue
		}
		if lineNumber == 1 {
			if err := source.ValidateText(line); err != nil {
				_ = reader.Close()
				issue := source.AsError(err)
				return FailedResult(ref.SourceID, ref.Location, issue.Code, issue.Message)
			}
		}
		if bytes.IndexByte(line, 0) >= 0 {
			_ = reader.Close()
			return FailedResult(ref.SourceID, ref.Location, "SOURCE_INVALID_TEXT", "source is not plain text")
		}
		if lineNumber == 1 && bytes.HasPrefix(line, []byte{0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf}) {
			_ = reader.Close()
			return FailedResult(ref.SourceID, ref.Location, "SOURCE_INVALID_TEXT", "source has more than one UTF-8 BOM")
		}
		if !checkedContainer {
			trimmed := strings.TrimSpace(strings.TrimPrefix(string(line), string([]byte{0xef, 0xbb, 0xbf})))
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "//") {
				checkedContainer = true
				if unsupportedContainer(trimmed) {
					_ = reader.Close()
					return FailedResult(ref.SourceID, ref.Location, "SOURCE_UNSUPPORTED_DOCUMENT", "unsupported document container")
				}
			}
		}

		outcome := parser.ParseLine(line, position)
		switch outcome.Kind {
		case model.OutcomeIgnore:
			result.Stats.Ignored++
		case model.OutcomeAccept:
			result.Stats.Accepted += uint64(len(outcome.Records))
			for _, record := range outcome.Records {
				if record.Kind == model.RuleIPv4 {
					result.IPv4 = append(result.IPv4, record)
				} else {
					result.Domains = append(result.Domains, record)
				}
			}
		case model.OutcomeFilterIPv6:
			result.Stats.FilteredIPv6++
		case model.OutcomeWarnSkip:
			if outcome.Diagnostic != nil && outcome.Diagnostic.Code == parser.CodeInvalidUTF8 {
				_ = reader.Close()
				return FailedResult(ref.SourceID, ref.Location, "SOURCE_INVALID_TEXT", "source is not valid UTF-8")
			}
			result.Stats.Skipped++
			if outcome.Diagnostic != nil {
				result.addDiagnostic(e.config.MaxDiagnostics, *outcome.Diagnostic)
			}
		}
	}
	if err := reader.Close(); err != nil {
		return FailedResult(ref.SourceID, ref.Location, "SOURCE_CLOSE", "cannot close source")
	}

	result.IPv4 = deduplicateIPv4(result.IPv4)
	result.Domains = deduplicateDomains(result.Domains)
	result.Stats.Retained = uint64(len(result.IPv4) + len(result.Domains))
	if result.Stats.Retained > 0 {
		result.Status = StatusSuccess
	}
	return result
}

func (r *SourceResult) addDiagnostic(limit int, diagnostic model.Diagnostic) {
	r.DiagnosticCount[diagnostic.Code]++
	if len(r.Diagnostics) < limit {
		r.Diagnostics = append(r.Diagnostics, diagnostic)
		return
	}
	r.Truncated++
}

func readLine(reader *bufio.Reader, limit int64) ([]byte, bool, bool, error) {
	var line []byte
	var length int64
	tooLong := false
	for {
		fragment, err := reader.ReadSlice('\n')
		terminated := len(fragment) > 0 && fragment[len(fragment)-1] == '\n'
		content := fragment
		if terminated {
			content = content[:len(content)-1]
			if len(content) > 0 && content[len(content)-1] == '\r' {
				content = content[:len(content)-1]
			}
		}
		length += int64(len(content))
		if !tooLong && length <= limit {
			line = append(line, content...)
		} else {
			tooLong = true
			line = nil
		}

		switch {
		case err == nil:
			return line, tooLong, true, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(fragment) == 0 && length == 0 {
				return nil, false, false, io.EOF
			}
			return line, tooLong, false, nil
		default:
			return nil, false, false, err
		}
	}
}

func unsupportedContainer(value string) bool {
	lower := strings.ToLower(value)
	for _, prefix := range []string{"<!doctype", "<html", "<?xml", "{", "[", "payload:"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func deduplicateIPv4(records []model.Record) []model.Record {
	sort.Slice(records, func(i, j int) bool {
		left, right := records[i].Prefix, records[j].Prefix
		leftAddress, rightAddress := ipv4Number(left.Addr()), ipv4Number(right.Addr())
		if leftAddress != rightAddress {
			return leftAddress < rightAddress
		}
		return left.Bits() < right.Bits()
	})
	result := records[:0]
	var previous netip.Prefix
	for index, record := range records {
		if index == 0 || record.Prefix != previous {
			result = append(result, record)
			previous = record.Prefix
		}
	}
	return result
}

func deduplicateDomains(records []model.Record) []model.Record {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}
		return records[i].Value < records[j].Value
	})
	result := records[:0]
	var previousKind model.RuleKind
	var previousValue string
	for index, record := range records {
		if index == 0 || record.Kind != previousKind || record.Value != previousValue {
			result = append(result, record)
			previousKind = record.Kind
			previousValue = record.Value
		}
	}
	return result
}

func ipv4Number(address netip.Addr) uint32 {
	octets := address.As4()
	return uint32(octets[0])<<24 |
		uint32(octets[1])<<16 |
		uint32(octets[2])<<8 |
		uint32(octets[3])
}
