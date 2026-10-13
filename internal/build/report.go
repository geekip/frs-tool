package build

import (
	"sort"

	"frs-tool/internal/extract"
	frsformat "frs-tool/internal/format"
	"frs-tool/internal/merge"
	"frs-tool/internal/source"
)

const (
	StatusSuccess             = "success"
	StatusSuccessWithWarnings = "success_with_warnings"
	StatusError               = "error"
	PublishPublished          = "published"
	PublishNotPublished       = "not_published"
	PublishUncertain          = "uncertain"
)

// FormatInfo 描述本次构建的目标文件格式。
type FormatInfo struct {
	Major uint16 `json:"major"`
	Minor uint16 `json:"minor"`
}

// FileInfo 只描述本次运行已关闭且严格验证的候选或产物。
type FileInfo struct {
	Bytes    uint64 `json:"bytes"`
	Checksum uint64 `json:"checksum"`
}

// SourceStats 区分配置引用与去重后的物理来源终态。
type SourceStats struct {
	References uint64 `json:"references"`
	Physical   uint64 `json:"physical"`
	Success    uint64 `json:"success"`
	Failed     uint64 `json:"failed"`
	Empty      uint64 `json:"empty"`
}

// RuleStats 汇总来源解析和集合归并事实。
type RuleStats struct {
	Accepted      uint64            `json:"accepted"`
	Retained      uint64            `json:"retained"`
	Skipped       uint64            `json:"skipped"`
	FilteredIPv6  uint64            `json:"filtered_ipv6"`
	InputRecords  uint64            `json:"input_records"`
	UniqueRecords uint64            `json:"unique_records"`
	IPv4Prefixes  uint64            `json:"ipv4_prefixes"`
	IPv4Ranges    uint64            `json:"ipv4_ranges"`
	SkippedByCode map[string]uint64 `json:"skipped_by_code"`
}

// SetStats 汇总最终集合类型和被省略的空组。
type SetStats struct {
	OmittedGroups uint64 `json:"omitted_groups"`
	IPv4          uint64 `json:"ipv4"`
	Domain        uint64 `json:"domain"`
}

// Warning 是有界、脱敏且可定位的最终诊断。
type Warning struct {
	Code     string `json:"code"`
	Group    string `json:"group,omitempty"`
	SourceID uint32 `json:"source_id,omitempty"`
	Location string `json:"location,omitempty"`
	Line     uint64 `json:"line,omitempty"`
	Message  string `json:"message"`
}

// WarningSummary 同时保留完整聚合计数和有界明细。
type WarningSummary struct {
	Total     uint64            `json:"total"`
	Expanded  uint64            `json:"expanded"`
	Truncated uint64            `json:"truncated"`
	ByCode    map[string]uint64 `json:"by_code"`
	Details   []Warning         `json:"details"`
}

// ErrorInfo 是稳定的受控失败结果。
type ErrorInfo struct {
	Code    string `json:"code"`
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

// Report 是构建命令的人读和 JSON 共享结果模型。
type Report struct {
	Status       string         `json:"status"`
	PublishState string         `json:"publish_state"`
	Output       string         `json:"output,omitempty"`
	Format       FormatInfo     `json:"format"`
	DurationMS   int64          `json:"duration_ms"`
	File         *FileInfo      `json:"file,omitempty"`
	Sources      SourceStats    `json:"sources"`
	Rules        RuleStats      `json:"rules"`
	Sets         SetStats       `json:"sets"`
	Warnings     WarningSummary `json:"warnings"`
	Error        *ErrorInfo     `json:"error,omitempty"`
}

func newReport() Report {
	return Report{
		Status:       StatusError,
		PublishState: PublishNotPublished,
		Format:       FormatInfo{Major: frsformat.VersionMajor, Minor: frsformat.VersionMinor},
		Rules:        RuleStats{SkippedByCode: make(map[string]uint64)},
		Warnings: WarningSummary{
			ByCode:  make(map[string]uint64),
			Details: []Warning{},
		},
	}
}

func fillStats(report *Report, groups []string, bindings []source.SourceBinding, results []extract.SourceResult, stats merge.Stats, detailLimit int) {
	report.Sources.References = uint64(len(bindings))
	report.Sources.Physical = uint64(len(results))
	groupBySource := make(map[uint32]string)
	for _, binding := range bindings {
		if _, exists := groupBySource[binding.PhysicalID]; !exists && binding.GroupID > 0 && int(binding.GroupID) <= len(groups) {
			groupBySource[binding.PhysicalID] = groups[binding.GroupID-1]
		}
	}
	var details []Warning
	for _, result := range results {
		switch result.Status {
		case extract.StatusSuccess:
			report.Sources.Success++
		case extract.StatusEmpty:
			report.Sources.Empty++
			addWarning(report, "SOURCE_EMPTY", 1)
			details = append(details, Warning{Code: "SOURCE_EMPTY", Group: groupBySource[result.SourceID], SourceID: result.SourceID, Location: result.Location, Message: "source contained no usable rules"})
		case extract.StatusFailed:
			report.Sources.Failed++
			code := result.ErrorCode
			if code == "" {
				code = "SOURCE_UNAVAILABLE"
			}
			addWarning(report, code, 1)
			details = append(details, Warning{Code: code, Group: groupBySource[result.SourceID], SourceID: result.SourceID, Location: result.Location, Message: result.ErrorMessage})
		}
		report.Rules.Accepted += result.Stats.Accepted
		report.Rules.Retained += result.Stats.Retained
		report.Rules.Skipped += result.Stats.Skipped
		report.Rules.FilteredIPv6 += result.Stats.FilteredIPv6
		for code, count := range result.DiagnosticCount {
			report.Rules.SkippedByCode[code] += count
			addWarning(report, code, count)
		}
		for _, diagnostic := range result.Diagnostics {
			details = append(details, Warning{
				Code: diagnostic.Code, Group: groupBySource[result.SourceID],
				SourceID: result.SourceID, Location: result.Location,
				Line: diagnostic.Position.Line, Message: diagnostic.Message,
			})
		}
	}
	report.Rules.InputRecords = stats.InputRecords
	report.Rules.UniqueRecords = stats.UniqueRecords
	report.Rules.IPv4Prefixes = stats.IPv4Prefixes
	report.Rules.IPv4Ranges = stats.IPv4Ranges
	report.Sets = SetStats{OmittedGroups: stats.OmittedGroups, IPv4: stats.IPv4Sets, Domain: stats.DomainSets}

	sort.SliceStable(details, func(i, j int) bool {
		left, right := details[i], details[j]
		if left.SourceID != right.SourceID {
			return left.SourceID < right.SourceID
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		return left.Group < right.Group
	})
	if detailLimit < 0 {
		detailLimit = 0
	}
	if len(details) > detailLimit {
		details = details[:detailLimit]
	}
	report.Warnings.Details = details
	report.Warnings.Expanded = uint64(len(details))
	if report.Warnings.Total > report.Warnings.Expanded {
		report.Warnings.Truncated = report.Warnings.Total - report.Warnings.Expanded
	}
}

func addWarning(report *Report, code string, count uint64) {
	if count == 0 {
		return
	}
	report.Warnings.Total += count
	report.Warnings.ByCode[code] += count
}
