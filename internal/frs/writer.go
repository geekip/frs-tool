package frs

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	frsformat "frs-tool/internal/format"
	"frs-tool/internal/index"
	"frs-tool/internal/merge"
)

type setRecord struct {
	kind           uint16
	label          string
	aStart, aCount uint32
	bStart, bCount uint32
	cStart, cCount uint32
	root, encoding uint32
}

type sectionData struct {
	typeID  uint32
	stride  uint32
	count   uint64
	offset  uint64
	payload []byte
}

// Encode 把已归并索引编码为确定性的 FRS 1.0 容器。
func Encode(input []merge.Set) ([]byte, error) {
	sets := append([]merge.Set(nil), input...)
	sortSets(sets)
	if err := validateSets(sets); err != nil {
		return nil, err
	}
	for position := 1; position < len(sets); position++ {
		if sets[position-1].Kind == sets[position].Kind && sets[position-1].Label == sets[position].Label {
			return nil, frsError(CodeSet, fmt.Sprintf("duplicate set %d/%q", sets[position].Kind, sets[position].Label), nil)
		}
	}
	if _, err := uint32Size(len(sets), "set count"); err != nil {
		return nil, err
	}

	records, ranges, nodes, edges, keywords, features, err := flattenSets(sets)
	if err != nil {
		return nil, err
	}
	pool, offsets, err := makeStringPool(records, edges, keywords)
	if err != nil {
		return nil, err
	}

	setPayload, err := recordPayload(len(records), frsformat.SetRecordBytes, "SETS")
	if err != nil {
		return nil, err
	}
	for position, record := range records {
		labelLength, err := uint32Size(len(record.label), "set label length")
		if err != nil {
			return nil, err
		}
		base := position * int(frsformat.SetRecordBytes)
		putU32(setPayload, base, uint32(position+1))
		putU16(setPayload, base+4, record.kind)
		putU64(setPayload, base+8, offsets[record.label])
		putU32(setPayload, base+16, labelLength)
		putU32(setPayload, base+24, record.aStart)
		putU32(setPayload, base+28, record.aCount)
		putU32(setPayload, base+32, record.bStart)
		putU32(setPayload, base+36, record.bCount)
		putU32(setPayload, base+40, record.cStart)
		putU32(setPayload, base+44, record.cCount)
		putU32(setPayload, base+48, record.root)
		putU32(setPayload, base+52, record.encoding)
	}

	sections := []sectionData{{
		typeID:  frsformat.SectionSets,
		stride:  frsformat.SetRecordBytes,
		count:   uint64(len(records)),
		payload: setPayload,
	}}
	if len(records) > 0 {
		sections = append(sections, sectionData{
			typeID:  frsformat.SectionStrings,
			stride:  frsformat.StringRecordBytes,
			count:   uint64(len(pool)),
			payload: pool,
		})
	}
	if len(ranges) > 0 {
		payload, err := recordPayload(len(ranges), frsformat.IPv4RangeRecordBytes, "IPV4_RANGES")
		if err != nil {
			return nil, err
		}
		for position, value := range ranges {
			base := position * int(frsformat.IPv4RangeRecordBytes)
			putU32(payload, base, value.Lo)
			putU32(payload, base+4, value.Hi)
		}
		sections = append(sections, sectionData{frsformat.SectionIPv4Ranges, frsformat.IPv4RangeRecordBytes, uint64(len(ranges)), 0, payload})
	}
	if len(nodes) > 0 {
		payload, err := recordPayload(len(nodes), frsformat.DomainNodeRecordBytes, "DOMAIN_NODES")
		if err != nil {
			return nil, err
		}
		for position, value := range nodes {
			base := position * int(frsformat.DomainNodeRecordBytes)
			putU32(payload, base, value.EdgeStart)
			putU32(payload, base+4, value.EdgeCount)
			putU32(payload, base+8, value.TerminalFlags)
		}
		sections = append(sections, sectionData{frsformat.SectionDomainNodes, frsformat.DomainNodeRecordBytes, uint64(len(nodes)), 0, payload})
	}
	if len(edges) > 0 {
		payload, err := recordPayload(len(edges), frsformat.DomainEdgeRecordBytes, "DOMAIN_EDGES")
		if err != nil {
			return nil, err
		}
		for position, value := range edges {
			labelLength, err := uint32Size(len(value.Label), "domain edge label length")
			if err != nil {
				return nil, err
			}
			base := position * int(frsformat.DomainEdgeRecordBytes)
			putU64(payload, base, offsets[value.Label])
			putU32(payload, base+8, labelLength)
			putU32(payload, base+12, value.Child)
		}
		sections = append(sections, sectionData{frsformat.SectionDomainEdges, frsformat.DomainEdgeRecordBytes, uint64(len(edges)), 0, payload})
	}
	if len(keywords) > 0 {
		payload, err := recordPayload(len(keywords), frsformat.KeywordRecordBytes, "KEYWORDS")
		if err != nil {
			return nil, err
		}
		for position, value := range keywords {
			keywordLength, err := uint32Size(len(value), "keyword length")
			if err != nil {
				return nil, err
			}
			base := position * int(frsformat.KeywordRecordBytes)
			putU64(payload, base, offsets[value])
			putU32(payload, base+8, keywordLength)
		}
		sections = append(sections, sectionData{frsformat.SectionKeywords, frsformat.KeywordRecordBytes, uint64(len(keywords)), 0, payload})
	}

	directoryBytes, err := checkedMultiply(uint64(len(sections)), uint64(frsformat.DirEntryBytes))
	if err != nil {
		return nil, err
	}
	cursor, err := checkedAdd(uint64(frsformat.HeaderBytes), directoryBytes)
	if err != nil {
		return nil, err
	}
	cursor, err = align8(cursor)
	if err != nil {
		return nil, err
	}
	for position := range sections {
		sections[position].offset = cursor
		cursor, err = checkedAdd(cursor, uint64(len(sections[position].payload)))
		if err != nil {
			return nil, err
		}
		if position+1 < len(sections) {
			cursor, err = align8(cursor)
			if err != nil {
				return nil, err
			}
		}
	}
	fileSize, err := intSize(cursor)
	if err != nil {
		return nil, err
	}
	file := make([]byte, fileSize)
	copy(file[0:8], frsformat.Magic)
	putU16(file, 8, frsformat.VersionMajor)
	putU16(file, 10, frsformat.VersionMinor)
	putU32(file, 12, frsformat.HeaderBytes)
	putU32(file, 16, features)
	putU32(file, 20, uint32(len(sections)))
	putU64(file, 24, cursor)
	putU64(file, 32, uint64(frsformat.HeaderBytes))
	for position, section := range sections {
		base := int(frsformat.HeaderBytes) + position*int(frsformat.DirEntryBytes)
		putU32(file, base, section.typeID)
		putU32(file, base+4, frsformat.SectionFlagMandatory)
		putU64(file, base+8, section.offset)
		putU64(file, base+16, uint64(len(section.payload)))
		putU64(file, base+24, section.count)
		putU32(file, base+32, section.stride)
		copy(file[int(section.offset):], section.payload)
	}
	putU64(file, 48, FileChecksum(file))
	return file, nil
}

// Write 编码并完整写出 FRS；短写或无进展会返回稳定写入错误。
func Write(writer io.Writer, sets []merge.Set) (int64, error) {
	if writer == nil {
		return 0, frsError(CodeWrite, "writer is nil", nil)
	}
	data, err := Encode(sets)
	if err != nil {
		return 0, err
	}
	written := 0
	for written < len(data) {
		count, writeErr := writer.Write(data[written:])
		if count < 0 || count > len(data)-written {
			return int64(written), frsError(CodeWrite, "writer returned an invalid byte count", nil)
		}
		written += count
		if writeErr != nil {
			return int64(written), frsError(CodeWrite, "could not write FRS data", writeErr)
		}
		if count == 0 {
			return int64(written), frsError(CodeWrite, "writer made no progress", io.ErrShortWrite)
		}
	}
	return int64(written), nil
}

func flattenSets(sets []merge.Set) ([]setRecord, []index.IPv4Range, []index.DomainNode, []index.DomainEdge, []string, uint32, error) {
	records := make([]setRecord, 0, len(sets))
	var ranges []index.IPv4Range
	var nodes []index.DomainNode
	var edges []index.DomainEdge
	var keywords []string
	var features uint32
	for _, set := range sets {
		record := setRecord{kind: uint16(set.Kind), label: set.Label}
		switch set.Kind {
		case merge.SetIPv4:
			features |= frsformat.FeatureIPv4Ranges
			count, err := uint32Size(len(set.IPv4.Ranges), "IPv4 range count")
			if err != nil {
				return nil, nil, nil, nil, nil, 0, err
			}
			if count != 0 {
				start, err := uint32Size(len(ranges)+1, "IPv4 range start")
				if err != nil {
					return nil, nil, nil, nil, nil, 0, err
				}
				record.aStart, record.aCount = start, count
			}
			if err := tableSize(len(ranges), len(set.IPv4.Ranges), "IPv4 range table"); err != nil {
				return nil, nil, nil, nil, nil, 0, err
			}
			ranges = append(ranges, set.IPv4.Ranges...)
			record.encoding = frsformat.EncodingIPv4Ranges
		case merge.SetDomain:
			features |= frsformat.FeatureDomainTrie
			nodeBase, edgeBase, keywordBase := len(nodes), len(edges), len(keywords)
			nodeCount, err := uint32Size(len(set.Domain.Nodes), "domain node count")
			if err != nil {
				return nil, nil, nil, nil, nil, 0, err
			}
			edgeCount, err := uint32Size(len(set.Domain.Edges), "domain edge count")
			if err != nil {
				return nil, nil, nil, nil, nil, 0, err
			}
			keywordCount, err := uint32Size(len(set.Domain.Keywords), "keyword count")
			if err != nil {
				return nil, nil, nil, nil, nil, 0, err
			}
			if err := tableSize(nodeBase, len(set.Domain.Nodes), "domain node table"); err != nil {
				return nil, nil, nil, nil, nil, 0, err
			}
			if err := tableSize(edgeBase, len(set.Domain.Edges), "domain edge table"); err != nil {
				return nil, nil, nil, nil, nil, 0, err
			}
			if err := tableSize(keywordBase, len(set.Domain.Keywords), "keyword table"); err != nil {
				return nil, nil, nil, nil, nil, 0, err
			}
			if nodeCount != 0 {
				record.aStart, record.aCount = uint32(nodeBase+1), nodeCount
				record.root = record.aStart
			}
			if edgeCount != 0 {
				record.bStart, record.bCount = uint32(edgeBase+1), edgeCount
			}
			if keywordCount != 0 {
				features |= frsformat.FeatureKeywords
				record.cStart, record.cCount = uint32(keywordBase+1), keywordCount
			}
			for _, node := range set.Domain.Nodes {
				if node.EdgeCount != 0 {
					node.EdgeStart += uint32(edgeBase)
				}
				nodes = append(nodes, node)
			}
			for _, edge := range set.Domain.Edges {
				edge.Child += uint32(nodeBase)
				edges = append(edges, edge)
			}
			keywords = append(keywords, set.Domain.Keywords...)
			record.encoding = frsformat.EncodingDomainRadixKeyword
		}
		records = append(records, record)
	}
	return records, ranges, nodes, edges, keywords, features, nil
}

func makeStringPool(records []setRecord, edges []index.DomainEdge, keywords []string) ([]byte, map[string]uint64, error) {
	unique := make(map[string]struct{}, len(records)+len(edges)+len(keywords))
	for _, record := range records {
		unique[record.label] = struct{}{}
	}
	for _, edge := range edges {
		unique[edge.Label] = struct{}{}
	}
	for _, keyword := range keywords {
		unique[keyword] = struct{}{}
	}
	values := make([]string, 0, len(unique))
	for value := range unique {
		values = append(values, value)
	}
	sort.Strings(values)
	var total uint64
	for _, value := range values {
		var err error
		total, err = checkedAdd(total, uint64(len(value)))
		if err != nil {
			return nil, nil, err
		}
	}
	size, err := intSize(total)
	if err != nil {
		return nil, nil, err
	}
	pool := make([]byte, 0, size)
	offsets := make(map[string]uint64, len(values))
	for _, value := range values {
		offsets[value] = uint64(len(pool))
		pool = append(pool, value...)
	}
	return pool, offsets, nil
}

func recordPayload(count int, stride uint32, name string) ([]byte, error) {
	length, err := checkedMultiply(uint64(count), uint64(stride))
	if err != nil {
		return nil, err
	}
	size, err := intSize(length)
	if err != nil {
		return nil, frsError(CodeOverflow, name+" payload is too large", err)
	}
	return make([]byte, size), nil
}

func tableSize(current, added int, name string) error {
	total, err := checkedAdd(uint64(current), uint64(added))
	if err != nil {
		return err
	}
	if total > uint64(^uint32(0)) {
		return frsError(CodeOverflow, name+" exceeds uint32", nil)
	}
	return nil
}

func putU16(data []byte, offset int, value uint16) {
	binary.LittleEndian.PutUint16(data[offset:offset+2], value)
}

func putU32(data []byte, offset int, value uint32) {
	binary.LittleEndian.PutUint32(data[offset:offset+4], value)
}

func putU64(data []byte, offset int, value uint64) {
	binary.LittleEndian.PutUint64(data[offset:offset+8], value)
}
