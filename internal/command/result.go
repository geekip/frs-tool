package command

import "frs-tool/internal/frs"

const (
	statusSuccess = "success"
	statusError   = "error"
)

type formatResult struct {
	Major uint16 `json:"major"`
	Minor uint16 `json:"minor"`
}

type commandError struct {
	Code    string `json:"code"`
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

type versionResult struct {
	Status  string       `json:"status"`
	Version string       `json:"version"`
	Format  formatResult `json:"format"`
}

type verifyResult struct {
	Status        string        `json:"status"`
	Path          string        `json:"path,omitempty"`
	Format        *formatResult `json:"format,omitempty"`
	Bytes         *uint64       `json:"bytes,omitempty"`
	Checksum      *uint64       `json:"checksum,omitempty"`
	ChecksumValid *bool         `json:"checksum_valid,omitempty"`
	Error         *commandError `json:"error,omitempty"`
}

type sectionResult struct {
	Type   uint32 `json:"type"`
	Flags  uint32 `json:"flags"`
	Offset uint64 `json:"offset"`
	Length uint64 `json:"length"`
	Count  uint64 `json:"count"`
	Stride uint32 `json:"stride"`
}

type setResult struct {
	ID          uint32 `json:"id"`
	Kind        uint16 `json:"kind"`
	Label       string `json:"label"`
	RecordCount uint64 `json:"record_count"`
}

type inspectSummary struct {
	Format           formatResult    `json:"format"`
	Bytes            uint64          `json:"bytes"`
	Checksum         uint64          `json:"checksum"`
	ChecksumValid    bool            `json:"checksum_valid"`
	RequiredFeatures uint32          `json:"required_features"`
	Sections         []sectionResult `json:"sections"`
	Sets             []setResult     `json:"sets"`
}

type inspectResult struct {
	Status  string          `json:"status"`
	Path    string          `json:"path,omitempty"`
	Summary *inspectSummary `json:"summary,omitempty"`
	Error   *commandError   `json:"error,omitempty"`
}

type usageResult struct {
	Status string        `json:"status"`
	Error  *commandError `json:"error"`
}

func makeInspectSummary(summary frs.Summary) inspectSummary {
	sections := make([]sectionResult, len(summary.Sections))
	for index, section := range summary.Sections {
		sections[index] = sectionResult{
			Type: section.Type, Flags: section.Flags, Offset: section.Offset,
			Length: section.Length, Count: section.Count, Stride: section.Stride,
		}
	}
	sets := make([]setResult, len(summary.Sets))
	for index, set := range summary.Sets {
		sets[index] = setResult{ID: set.ID, Kind: set.Kind, Label: set.Label, RecordCount: set.RecordCount}
	}
	return inspectSummary{
		Format: formatResult{Major: summary.Major, Minor: summary.Minor},
		Bytes:  summary.FileBytes, Checksum: summary.Checksum, ChecksumValid: true,
		RequiredFeatures: summary.RequiredFeatures, Sections: sections, Sets: sets,
	}
}
