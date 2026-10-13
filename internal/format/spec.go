package format

const (
	Magic         = "FTUNFRS\x00"
	VersionMajor  = uint16(1)
	VersionMinor  = uint16(0)
	HeaderBytes   = uint32(64)
	DirEntryBytes = uint32(40)
)

const (
	FeatureIPv4Ranges   = uint32(1 << 0)
	FeatureDomainTrie   = uint32(1 << 1)
	FeatureKeywords     = uint32(1 << 2)
	FeatureIPv6Reserved = uint32(1 << 3)
)

const SectionFlagMandatory = uint32(1 << 0)

const (
	SectionSets         = uint32(1)
	SectionStrings      = uint32(2)
	SectionIPv4Ranges   = uint32(3)
	SectionDomainNodes  = uint32(4)
	SectionDomainEdges  = uint32(5)
	SectionKeywords     = uint32(6)
	SectionIPv6Reserved = uint32(7)
)

const (
	SetRecordBytes        = uint32(64)
	StringRecordBytes     = uint32(1)
	IPv4RangeRecordBytes  = uint32(8)
	DomainNodeRecordBytes = uint32(16)
	DomainEdgeRecordBytes = uint32(16)
	KeywordRecordBytes    = uint32(16)
)

const (
	SetKindIPv4   = uint16(1)
	SetKindDomain = uint16(2)
)

const (
	EncodingIPv4Ranges         = uint32(1)
	EncodingDomainRadixKeyword = uint32(2)
)

const (
	DomainTerminalExact  = uint32(1 << 0)
	DomainTerminalSuffix = uint32(1 << 1)
)
