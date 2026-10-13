package command

import (
	"fmt"
	"io"
	"sort"

	buildrun "frs-tool/internal/build"
)

func renderBuild(report buildrun.Report, jsonMode bool, stdout, stderr io.Writer) error {
	if jsonMode {
		return writeJSON(stdout, report)
	}
	for _, warning := range report.Warnings.Details {
		if _, err := fmt.Fprintf(stderr, "WARN %s group=%q source=%d line=%d location=%q: %s\n",
			warning.Code, warning.Group, warning.SourceID, warning.Line, warning.Location, warning.Message); err != nil {
			return err
		}
	}
	if report.Warnings.Truncated > 0 {
		if _, err := fmt.Fprintf(stderr, "WARN WARNINGS_TRUNCATED count=%d\n", report.Warnings.Truncated); err != nil {
			return err
		}
	}
	if report.Error != nil {
		if _, err := fmt.Fprintf(stderr, "ERROR %s stage=%s: %s\n", report.Error.Code, report.Error.Stage, report.Error.Message); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(stdout,
		"status: %s\npublish_state: %s\noutput: %s\nformat: %d.%d\nsources: references=%d physical=%d success=%d failed=%d empty=%d\nrules: accepted=%d retained=%d skipped=%d filtered_ipv6=%d input=%d unique=%d ipv4_prefixes=%d ipv4_ranges=%d\nsets: ipv4=%d domain=%d omitted_groups=%d\nwarnings: total=%d expanded=%d truncated=%d\nduration_ms: %d\n",
		report.Status, report.PublishState, report.Output, report.Format.Major, report.Format.Minor,
		report.Sources.References, report.Sources.Physical, report.Sources.Success, report.Sources.Failed, report.Sources.Empty,
		report.Rules.Accepted, report.Rules.Retained, report.Rules.Skipped, report.Rules.FilteredIPv6,
		report.Rules.InputRecords, report.Rules.UniqueRecords, report.Rules.IPv4Prefixes, report.Rules.IPv4Ranges,
		report.Sets.IPv4, report.Sets.Domain, report.Sets.OmittedGroups,
		report.Warnings.Total, report.Warnings.Expanded, report.Warnings.Truncated, report.DurationMS)
	if err != nil {
		return err
	}
	if report.File != nil {
		if _, err := fmt.Fprintf(stdout, "file: bytes=%d checksum=%d\n", report.File.Bytes, report.File.Checksum); err != nil {
			return err
		}
	}
	if len(report.Warnings.ByCode) > 0 {
		codes := make([]string, 0, len(report.Warnings.ByCode))
		for code := range report.Warnings.ByCode {
			codes = append(codes, code)
		}
		sort.Strings(codes)
		for _, code := range codes {
			if _, err := fmt.Fprintf(stdout, "warning_count: code=%s count=%d\n", code, report.Warnings.ByCode[code]); err != nil {
				return err
			}
		}
	}
	return nil
}

func renderVerify(result verifyResult, jsonMode bool, stdout, stderr io.Writer) error {
	if jsonMode {
		return writeJSON(stdout, result)
	}
	if result.Error != nil {
		_, err := fmt.Fprintf(stderr, "ERROR %s stage=%s: %s\n", result.Error.Code, result.Error.Stage, result.Error.Message)
		return err
	}
	_, err := fmt.Fprintf(stdout, "status: success\npath: %s\nformat: %d.%d\nbytes: %d\nchecksum: %d\nchecksum_valid: true\n",
		result.Path, result.Format.Major, result.Format.Minor, *result.Bytes, *result.Checksum)
	return err
}

func renderInspect(result inspectResult, jsonMode bool, stdout, stderr io.Writer) error {
	if jsonMode {
		return writeJSON(stdout, result)
	}
	if result.Error != nil {
		_, err := fmt.Fprintf(stderr, "ERROR %s stage=%s: %s\n", result.Error.Code, result.Error.Stage, result.Error.Message)
		return err
	}
	summary := result.Summary
	if _, err := fmt.Fprintf(stdout,
		"status: success\npath: %s\nformat: %d.%d\nbytes: %d\nchecksum: %d\nchecksum_valid: true\nrequired_features: %d\n",
		result.Path, summary.Format.Major, summary.Format.Minor, summary.Bytes, summary.Checksum, summary.RequiredFeatures); err != nil {
		return err
	}
	for _, section := range summary.Sections {
		if _, err := fmt.Fprintf(stdout, "section: type=%d flags=%d offset=%d length=%d count=%d stride=%d\n",
			section.Type, section.Flags, section.Offset, section.Length, section.Count, section.Stride); err != nil {
			return err
		}
	}
	for _, set := range summary.Sets {
		if _, err := fmt.Fprintf(stdout, "set: id=%d kind=%d label=%q records=%d\n", set.ID, set.Kind, set.Label, set.RecordCount); err != nil {
			return err
		}
	}
	return nil
}
