package frs

import (
	"bytes"
	"encoding/binary"
	"sort"

	frsformat "frs-tool/internal/format"
	"frs-tool/internal/index"
)

const metadataSectionBase = uint32(0x80000000)

type decodedSection struct {
	SectionSummary
	payload []byte
}

type stringReference struct {
	value  string
	offset uint64
}

type decodedSet struct {
	id             uint32
	kind           uint16
	label          string
	aStart, aCount uint32
	bStart, bCount uint32
	cStart, cCount uint32
	root, encoding uint32
}

// Verify 对整个 FRS 1.0 容器执行边界、安全与规范性验证。
// 只有全部验证成功后才会返回不含规则载荷的摘要。
func Verify(data []byte) (Summary, error) {
	if len(data) < int(frsformat.HeaderBytes) {
		return Summary{}, frsError(CodeInvalidHeader, "file is shorter than the FRS header", nil)
	}
	if string(data[0:8]) != frsformat.Magic {
		return Summary{}, frsError(CodeInvalidHeader, "magic does not identify an FRS file", nil)
	}
	major := readU16(data, 8)
	minor := readU16(data, 10)
	if major != frsformat.VersionMajor || minor != frsformat.VersionMinor {
		return Summary{}, frsError(CodeUnsupported, "FRS version is not supported", nil)
	}
	if readU32(data, 12) != frsformat.HeaderBytes || readU64(data, 32) != uint64(frsformat.HeaderBytes) ||
		!zeroBytes(data[40:48]) || !zeroBytes(data[56:64]) {
		return Summary{}, frsError(CodeInvalidHeader, "header layout or reserved bytes are invalid", nil)
	}
	if readU64(data, 24) != uint64(len(data)) {
		return Summary{}, frsError(CodeInvalidHeader, "header file length does not match input", nil)
	}
	features := readU32(data, 16)
	if features&frsformat.FeatureIPv6Reserved != 0 ||
		features&^(frsformat.FeatureIPv4Ranges|frsformat.FeatureDomainTrie|frsformat.FeatureKeywords) != 0 {
		return Summary{}, frsError(CodeUnsupported, "FRS requires unsupported features", nil)
	}
	storedChecksum := readU64(data, 48)
	if FileChecksum(data) != storedChecksum {
		return Summary{}, frsError(CodeChecksum, "file checksum does not match", nil)
	}

	sectionCount := readU32(data, 20)
	if sectionCount == 0 {
		return Summary{}, frsError(CodeDirectory, "section directory is empty", nil)
	}
	directoryBytes, err := checkedMultiply(uint64(sectionCount), uint64(frsformat.DirEntryBytes))
	if err != nil {
		return Summary{}, err
	}
	directoryEnd, err := checkedAdd(uint64(frsformat.HeaderBytes), directoryBytes)
	if err != nil || directoryEnd > uint64(len(data)) {
		return Summary{}, frsError(CodeDirectory, "section directory exceeds the file", err)
	}
	expectedOffset, err := align8(directoryEnd)
	if err != nil || expectedOffset > uint64(len(data)) {
		return Summary{}, frsError(CodeDirectory, "section payload alignment exceeds the file", err)
	}
	if !zeroRange(data, directoryEnd, expectedOffset) {
		return Summary{}, frsError(CodeNonCanonical, "directory padding is not zero", nil)
	}

	sections := make([]decodedSection, 0, sectionCount)
	byType := make(map[uint32]*decodedSection, sectionCount)
	var previousType uint32
	for position := uint32(0); position < sectionCount; position++ {
		base := int(frsformat.HeaderBytes) + int(position)*int(frsformat.DirEntryBytes)
		section := decodedSection{SectionSummary: SectionSummary{
			Type: readU32(data, base), Flags: readU32(data, base+4),
			Offset: readU64(data, base+8), Length: readU64(data, base+16),
			Count: readU64(data, base+24), Stride: readU32(data, base+32),
		}}
		if readU32(data, base+36) != 0 {
			return Summary{}, frsError(CodeDirectory, "section directory reserved field is not zero", nil)
		}
		if position > 0 && section.Type <= previousType {
			return Summary{}, frsError(CodeNonCanonical, "sections are not in strictly increasing type order", nil)
		}
		previousType = section.Type
		if section.Offset != expectedOffset || section.Offset&7 != 0 {
			return Summary{}, frsError(CodeNonCanonical, "section offset is not the canonical aligned offset", nil)
		}
		end, addErr := checkedAdd(section.Offset, section.Length)
		if addErr != nil || end > uint64(len(data)) {
			return Summary{}, frsError(CodeSection, "section exceeds the file", addErr)
		}
		if err := validateSectionLayout(section.SectionSummary); err != nil {
			return Summary{}, err
		}
		section.payload = data[int(section.Offset):int(end)]
		sections = append(sections, section)
		stored := &sections[len(sections)-1]
		byType[section.Type] = stored
		if position+1 < sectionCount {
			expectedOffset, err = align8(end)
			if err != nil || expectedOffset > uint64(len(data)) {
				return Summary{}, frsError(CodeSection, "section alignment exceeds the file", err)
			}
			if !zeroRange(data, end, expectedOffset) {
				return Summary{}, frsError(CodeNonCanonical, "section padding is not zero", nil)
			}
		} else {
			expectedOffset = end
		}
	}
	if expectedOffset != uint64(len(data)) {
		return Summary{}, frsError(CodeNonCanonical, "file has trailing bytes", nil)
	}
	setsSection := byType[frsformat.SectionSets]
	if setsSection == nil {
		return Summary{}, frsError(CodeDirectory, "SETS section is missing", nil)
	}
	stringsSection := byType[frsformat.SectionStrings]
	if setsSection.Count == 0 {
		if stringsSection != nil {
			return Summary{}, frsError(CodeNonCanonical, "empty container has a STRINGS section", nil)
		}
	} else if stringsSection == nil {
		return Summary{}, frsError(CodeSection, "sets require a STRINGS section", nil)
	}

	decodedSets, references, summaries, actualFeatures, err := decodeAndValidateSets(byType, setsSection, stringsSection)
	if err != nil {
		return Summary{}, err
	}
	_ = decodedSets
	if actualFeatures != features {
		return Summary{}, frsError(CodeSection, "required features do not match set contents", nil)
	}
	if err := validateCanonicalStrings(stringsSection, references); err != nil {
		return Summary{}, err
	}

	sectionSummaries := make([]SectionSummary, len(sections))
	for position := range sections {
		sectionSummaries[position] = sections[position].SectionSummary
	}
	return Summary{
		Major: major, Minor: minor, RequiredFeatures: features,
		FileBytes: uint64(len(data)), Checksum: storedChecksum,
		Sections: sectionSummaries, Sets: summaries,
	}, nil
}

func validateSectionLayout(section SectionSummary) error {
	stride := uint32(0)
	switch section.Type {
	case frsformat.SectionSets:
		stride = frsformat.SetRecordBytes
	case frsformat.SectionStrings:
		stride = frsformat.StringRecordBytes
	case frsformat.SectionIPv4Ranges:
		stride = frsformat.IPv4RangeRecordBytes
	case frsformat.SectionDomainNodes:
		stride = frsformat.DomainNodeRecordBytes
	case frsformat.SectionDomainEdges:
		stride = frsformat.DomainEdgeRecordBytes
	case frsformat.SectionKeywords:
		stride = frsformat.KeywordRecordBytes
	case frsformat.SectionIPv6Reserved:
		return frsError(CodeUnsupported, "reserved IPv6 section is not supported", nil)
	default:
		if section.Type < metadataSectionBase {
			return frsError(CodeUnsupported, "unknown semantic section is not supported", nil)
		}
		if section.Flags != 0 || section.Stride != 1 || section.Count != section.Length {
			return frsError(CodeSection, "metadata section layout is invalid", nil)
		}
		return nil
	}
	if section.Flags != frsformat.SectionFlagMandatory || section.Stride != stride {
		return frsError(CodeSection, "known section flags or stride are invalid", nil)
	}
	length, err := checkedMultiply(section.Count, uint64(stride))
	if err != nil || length != section.Length {
		return frsError(CodeSection, "section length does not match count and stride", err)
	}
	if section.Type != frsformat.SectionStrings && section.Count > uint64(^uint32(0)) {
		return frsError(CodeOverflow, "section record count exceeds uint32", nil)
	}
	if section.Type != frsformat.SectionSets && section.Count == 0 {
		return frsError(CodeNonCanonical, "empty semantic section must be omitted", nil)
	}
	return nil
}

func decodeAndValidateSets(byType map[uint32]*decodedSection, setsSection, stringsSection *decodedSection) ([]decodedSet, []stringReference, []SetSummary, uint32, error) {
	sets := make([]decodedSet, 0, setsSection.Count)
	summaries := make([]SetSummary, 0, setsSection.Count)
	refs := make([]stringReference, 0, setsSection.Count)
	var features uint32
	var rangeUsed, nodeUsed, edgeUsed, keywordUsed uint64
	var previous *decodedSet
	for position := uint64(0); position < setsSection.Count; position++ {
		base := int(position * uint64(frsformat.SetRecordBytes))
		record := setsSection.payload[base : base+int(frsformat.SetRecordBytes)]
		set := decodedSet{
			id: readU32(record, 0), kind: readU16(record, 4),
			aStart: readU32(record, 24), aCount: readU32(record, 28),
			bStart: readU32(record, 32), bCount: readU32(record, 36),
			cStart: readU32(record, 40), cCount: readU32(record, 44),
			root: readU32(record, 48), encoding: readU32(record, 52),
		}
		if set.id != uint32(position+1) || readU16(record, 6) != 0 || readU32(record, 20) != 0 || !zeroBytes(record[56:64]) {
			return nil, nil, nil, 0, frsError(CodeSet, "set identity, flags, or reserved fields are invalid", nil)
		}
		label, err := referencedString(stringsSection, readU64(record, 8), readU32(record, 16))
		if err != nil || !validSetLabel(label) {
			return nil, nil, nil, 0, frsError(CodeSet, "set label is invalid", err)
		}
		set.label = label
		refs = append(refs, stringReference{label, readU64(record, 8)})
		if previous != nil && (previous.kind > set.kind || previous.kind == set.kind && previous.label >= set.label) {
			return nil, nil, nil, 0, frsError(CodeNonCanonical, "sets are not strictly sorted by kind and label", nil)
		}

		var recordCount uint64
		switch set.kind {
		case frsformat.SetKindIPv4:
			features |= frsformat.FeatureIPv4Ranges
			if set.encoding != frsformat.EncodingIPv4Ranges || set.bStart != 0 || set.bCount != 0 ||
				set.cStart != 0 || set.cCount != 0 || set.root != 0 {
				return nil, nil, nil, 0, frsError(CodeSet, "IPv4 set fields are invalid", nil)
			}
			if !canonicalSpan(set.aStart, set.aCount, &rangeUsed) {
				return nil, nil, nil, 0, frsError(CodeNonCanonical, "IPv4 set spans are not contiguous", nil)
			}
			ipv4, err := decodeIPv4Index(byType[frsformat.SectionIPv4Ranges], set.aStart, set.aCount)
			if err != nil {
				return nil, nil, nil, 0, err
			}
			if err := validateIPv4Index(ipv4); err != nil {
				return nil, nil, nil, 0, err
			}
			recordCount = uint64(len(ipv4.Ranges))
		case frsformat.SetKindDomain:
			features |= frsformat.FeatureDomainTrie
			if set.encoding != frsformat.EncodingDomainRadixKeyword {
				return nil, nil, nil, 0, frsError(CodeSet, "domain set encoding is invalid", nil)
			}
			if !canonicalSpan(set.aStart, set.aCount, &nodeUsed) ||
				!canonicalSpan(set.bStart, set.bCount, &edgeUsed) ||
				!canonicalSpan(set.cStart, set.cCount, &keywordUsed) {
				return nil, nil, nil, 0, frsError(CodeNonCanonical, "domain set spans are not contiguous", nil)
			}
			if set.aCount == 0 && set.root != 0 || set.aCount != 0 && set.root != set.aStart {
				return nil, nil, nil, 0, frsError(CodeSet, "domain root does not match its node span", nil)
			}
			domain, domainRefs, err := decodeDomainIndex(byType, set)
			if err != nil {
				return nil, nil, nil, 0, err
			}
			if err := validateDomainIndex(domain); err != nil {
				return nil, nil, nil, 0, err
			}
			refs = append(refs, domainRefs...)
			recordCount = uint64(domain.RecordCount)
			if set.cCount != 0 {
				features |= frsformat.FeatureKeywords
			}
		default:
			return nil, nil, nil, 0, frsError(CodeSet, "set kind is not supported", nil)
		}
		sets = append(sets, set)
		summaries = append(summaries, SetSummary{ID: set.id, Kind: set.kind, Label: set.label, RecordCount: recordCount})
		previous = &sets[len(sets)-1]
	}
	if err := exactSectionUse(byType[frsformat.SectionIPv4Ranges], rangeUsed, "IPv4 ranges"); err != nil {
		return nil, nil, nil, 0, err
	}
	if err := exactSectionUse(byType[frsformat.SectionDomainNodes], nodeUsed, "domain nodes"); err != nil {
		return nil, nil, nil, 0, err
	}
	if err := exactSectionUse(byType[frsformat.SectionDomainEdges], edgeUsed, "domain edges"); err != nil {
		return nil, nil, nil, 0, err
	}
	if err := exactSectionUse(byType[frsformat.SectionKeywords], keywordUsed, "keywords"); err != nil {
		return nil, nil, nil, 0, err
	}
	return sets, refs, summaries, features, nil
}

func decodeIPv4Index(section *decodedSection, start, count uint32) (index.IPv4Index, error) {
	if err := spanInSection(section, start, count, "IPv4 range"); err != nil {
		return index.IPv4Index{}, err
	}
	result := index.IPv4Index{Ranges: make([]index.IPv4Range, 0, count), PrefixCount: int(count)}
	for position := uint32(0); position < count; position++ {
		base := (uint64(start-1) + uint64(position)) * uint64(frsformat.IPv4RangeRecordBytes)
		record := section.payload[int(base) : int(base)+int(frsformat.IPv4RangeRecordBytes)]
		result.Ranges = append(result.Ranges, index.IPv4Range{Lo: readU32(record, 0), Hi: readU32(record, 4)})
	}
	return result, nil
}

func decodeDomainIndex(byType map[uint32]*decodedSection, set decodedSet) (index.DomainIndex, []stringReference, error) {
	nodeSection := byType[frsformat.SectionDomainNodes]
	edgeSection := byType[frsformat.SectionDomainEdges]
	keywordSection := byType[frsformat.SectionKeywords]
	stringsSection := byType[frsformat.SectionStrings]
	if err := spanInSection(nodeSection, set.aStart, set.aCount, "domain node"); err != nil {
		return index.DomainIndex{}, nil, err
	}
	if err := spanInSection(edgeSection, set.bStart, set.bCount, "domain edge"); err != nil {
		return index.DomainIndex{}, nil, err
	}
	if err := spanInSection(keywordSection, set.cStart, set.cCount, "keyword"); err != nil {
		return index.DomainIndex{}, nil, err
	}
	result := index.DomainIndex{
		Nodes:    make([]index.DomainNode, 0, set.aCount),
		Edges:    make([]index.DomainEdge, 0, set.bCount),
		Keywords: make([]string, 0, set.cCount),
	}
	for position := uint32(0); position < set.aCount; position++ {
		base := (uint64(set.aStart-1) + uint64(position)) * uint64(frsformat.DomainNodeRecordBytes)
		record := nodeSection.payload[int(base) : int(base)+int(frsformat.DomainNodeRecordBytes)]
		if readU32(record, 12) != 0 {
			return index.DomainIndex{}, nil, frsError(CodeIndex, "domain node reserved field is not zero", nil)
		}
		node := index.DomainNode{EdgeStart: readU32(record, 0), EdgeCount: readU32(record, 4), TerminalFlags: readU32(record, 8)}
		if node.EdgeCount != 0 {
			if node.EdgeStart < set.bStart || uint64(node.EdgeStart-set.bStart)+uint64(node.EdgeCount) > uint64(set.bCount) {
				return index.DomainIndex{}, nil, frsError(CodeIndex, "domain node edge span leaves its set", nil)
			}
			node.EdgeStart = node.EdgeStart - set.bStart + 1
		}
		result.Nodes = append(result.Nodes, node)
	}
	refs := make([]stringReference, 0, int(set.bCount)+int(set.cCount))
	for position := uint32(0); position < set.bCount; position++ {
		base := (uint64(set.bStart-1) + uint64(position)) * uint64(frsformat.DomainEdgeRecordBytes)
		record := edgeSection.payload[int(base) : int(base)+int(frsformat.DomainEdgeRecordBytes)]
		offset := readU64(record, 0)
		label, err := referencedString(stringsSection, offset, readU32(record, 8))
		if err != nil {
			return index.DomainIndex{}, nil, frsError(CodeIndex, "domain edge label leaves STRINGS", err)
		}
		child := readU32(record, 12)
		if child < set.aStart || uint64(child-set.aStart) >= uint64(set.aCount) {
			return index.DomainIndex{}, nil, frsError(CodeIndex, "domain edge child leaves its set", nil)
		}
		result.Edges = append(result.Edges, index.DomainEdge{Label: label, Child: child - set.aStart + 1})
		refs = append(refs, stringReference{label, offset})
	}
	terminalCount := 0
	for _, node := range result.Nodes {
		terminalCount += boolInt(node.TerminalFlags&frsformat.DomainTerminalExact != 0)
		terminalCount += boolInt(node.TerminalFlags&frsformat.DomainTerminalSuffix != 0)
	}
	for position := uint32(0); position < set.cCount; position++ {
		base := (uint64(set.cStart-1) + uint64(position)) * uint64(frsformat.KeywordRecordBytes)
		record := keywordSection.payload[int(base) : int(base)+int(frsformat.KeywordRecordBytes)]
		if readU32(record, 12) != 0 {
			return index.DomainIndex{}, nil, frsError(CodeIndex, "keyword reserved field is not zero", nil)
		}
		offset := readU64(record, 0)
		keyword, err := referencedString(stringsSection, offset, readU32(record, 8))
		if err != nil {
			return index.DomainIndex{}, nil, frsError(CodeIndex, "keyword leaves STRINGS", err)
		}
		result.Keywords = append(result.Keywords, keyword)
		refs = append(refs, stringReference{keyword, offset})
	}
	result.RecordCount = terminalCount + len(result.Keywords)
	return result, refs, nil
}

func validateCanonicalStrings(section *decodedSection, refs []stringReference) error {
	if len(refs) == 0 {
		if section != nil {
			return frsError(CodeNonCanonical, "unused STRINGS section is present", nil)
		}
		return nil
	}
	if section == nil {
		return frsError(CodeStringPool, "STRINGS section is missing", nil)
	}
	unique := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		unique[ref.value] = struct{}{}
	}
	values := make([]string, 0, len(unique))
	for value := range unique {
		values = append(values, value)
	}
	sort.Strings(values)
	expected := make([]byte, 0, len(section.payload))
	offsets := make(map[string]uint64, len(values))
	for _, value := range values {
		offsets[value] = uint64(len(expected))
		expected = append(expected, value...)
	}
	if !bytes.Equal(expected, section.payload) {
		return frsError(CodeNonCanonical, "STRINGS is not the sorted exact-deduplicated pool", nil)
	}
	for _, ref := range refs {
		if offsets[ref.value] != ref.offset {
			return frsError(CodeNonCanonical, "string reference does not use its canonical offset", nil)
		}
	}
	return nil
}

func canonicalSpan(start, count uint32, used *uint64) bool {
	if count == 0 {
		return start == 0
	}
	if uint64(start) != *used+1 {
		return false
	}
	*used += uint64(count)
	return true
}

func spanInSection(section *decodedSection, start, count uint32, name string) error {
	if count == 0 {
		if start != 0 {
			return frsError(CodeIndex, name+" empty span has a non-zero start", nil)
		}
		return nil
	}
	if section == nil || start == 0 || uint64(start-1)+uint64(count) > section.Count {
		return frsError(CodeIndex, name+" span exceeds its section", nil)
	}
	return nil
}

func exactSectionUse(section *decodedSection, used uint64, name string) error {
	if used == 0 {
		if section != nil {
			return frsError(CodeNonCanonical, "unused "+name+" section is present", nil)
		}
		return nil
	}
	if section == nil || section.Count != used {
		return frsError(CodeNonCanonical, name+" section is not exactly covered by set spans", nil)
	}
	return nil
}

func referencedString(section *decodedSection, offset uint64, length uint32) (string, error) {
	if section == nil || offset > section.Length || uint64(length) > section.Length-offset {
		return "", frsError(CodeStringPool, "string reference exceeds STRINGS", nil)
	}
	return string(section.payload[int(offset) : int(offset)+int(length)]), nil
}

func zeroRange(data []byte, start, end uint64) bool {
	return start <= end && end <= uint64(len(data)) && zeroBytes(data[int(start):int(end)])
}

func zeroBytes(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func readU16(data []byte, offset int) uint16 {
	return binary.LittleEndian.Uint16(data[offset : offset+2])
}

func readU32(data []byte, offset int) uint32 {
	return binary.LittleEndian.Uint32(data[offset : offset+4])
}

func readU64(data []byte, offset int) uint64 {
	return binary.LittleEndian.Uint64(data[offset : offset+8])
}
