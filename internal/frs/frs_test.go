package frs

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	frsformat "frs-tool/internal/format"
	"frs-tool/internal/index"
	"frs-tool/internal/merge"
	"frs-tool/internal/model"
)

func TestXXH64KnownVectorAndFileChecksum(t *testing.T) {
	t.Parallel()
	if actual := XXH64(nil); actual != 0xef46db3751d8e999 {
		t.Fatalf("XXH64(empty) = %016x", actual)
	}
	data := []byte("1234567890123456789012345678901234567890123456789012345678901234")
	copy(data[48:56], []byte("checksum"))
	cleared := append([]byte(nil), data...)
	clear(cleared[48:56])
	if FileChecksum(data) != XXH64(cleared) {
		t.Fatal("FileChecksum did not treat the checksum field as zero")
	}
}

func TestEncodeEmptyMatchesIndependentGolden(t *testing.T) {
	t.Parallel()
	want := readHexFixture(t, "../../testdata/frs/empty-v1.golden.hex")
	actual, err := Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, want) {
		t.Fatalf("empty FRS differs from golden\n got: %x\nwant: %x", actual, want)
	}
	summary, err := Verify(actual)
	if err != nil {
		t.Fatal(err)
	}
	if summary.FileBytes != 104 || len(summary.Sections) != 1 || summary.Sections[0].Type != frsformat.SectionSets || len(summary.Sets) != 0 {
		t.Fatalf("empty summary = %+v", summary)
	}
}

func TestEncodeVerifyIsDeterministicAndInspectSafe(t *testing.T) {
	t.Parallel()
	sets := comprehensiveSets(t)
	data, err := Encode(sets)
	if err != nil {
		t.Fatal(err)
	}
	reversed := append([]merge.Set(nil), sets...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	again, err := Encode(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, again) {
		t.Fatal("encoding depends on input set order")
	}
	original := append([]byte(nil), data...)
	summary, err := Verify(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, original) {
		t.Fatal("Verify modified its file view")
	}
	if summary.Major != 1 || summary.Minor != 0 || summary.FileBytes != uint64(len(data)) ||
		summary.RequiredFeatures != frsformat.FeatureIPv4Ranges|frsformat.FeatureDomainTrie|frsformat.FeatureKeywords || len(summary.Sets) != len(sets) {
		t.Fatalf("summary = %+v", summary)
	}
	for _, set := range summary.Sets {
		if strings.Contains(fmt.Sprintf("%+v", set), "255.255.255.255") || strings.Contains(fmt.Sprintf("%+v", set), "both.example") {
			t.Fatal("summary exposed rule payload")
		}
	}
}

func TestComprehensiveGoldenBytes(t *testing.T) {
	t.Parallel()
	want := readHexFixture(t, "../../testdata/frs/comprehensive-v1.golden.hex")
	actual, err := Encode(comprehensiveSets(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, want) {
		t.Fatalf("comprehensive FRS differs from golden\n got: %x\nwant: %x", actual, want)
	}
}

func TestVerifyRejectsCorruptionWithoutPartialSummary(t *testing.T) {
	t.Parallel()
	valid, err := Encode(comprehensiveSets(t))
	if err != nil {
		t.Fatal(err)
	}
	directory := directoryOffsets(valid)
	entries := directoryEntries(valid)
	setsOffset := directory[frsformat.SectionSets]
	stringsOffset := directory[frsformat.SectionStrings]
	rangesOffset := directory[frsformat.SectionIPv4Ranges]
	nodesOffset := directory[frsformat.SectionDomainNodes]
	keywordsOffset := directory[frsformat.SectionKeywords]
	stringsEntry := entries[frsformat.SectionStrings]
	rangesEntry := entries[frsformat.SectionIPv4Ranges]

	tests := []struct {
		name string
		code string
		edit func([]byte) []byte
	}{
		{"truncated", CodeInvalidHeader, func(data []byte) []byte { return data[:40] }},
		{"magic", CodeInvalidHeader, func(data []byte) []byte { data[0] ^= 1; return data }},
		{"checksum", CodeChecksum, func(data []byte) []byte { data[len(data)-1] ^= 1; return data }},
		{"header reserved", CodeInvalidHeader, resign(func(data []byte) { data[40] = 1 })},
		{"directory reserved", CodeDirectory, resign(func(data []byte) { data[64+36] = 1 })},
		{"directory stride", CodeSection, resign(func(data []byte) { binary.LittleEndian.PutUint32(data[64+32:64+36], 63) })},
		{"directory offset gap", CodeNonCanonical, resign(func(data []byte) {
			binary.LittleEndian.PutUint64(data[64+8:64+16], uint64(setsOffset+8))
		})},
		{"unknown semantic section", CodeUnsupported, resign(func(data []byte) {
			binary.LittleEndian.PutUint32(data[entries[frsformat.SectionKeywords]:entries[frsformat.SectionKeywords]+4], 7)
		})},
		{"nonzero alignment padding", CodeNonCanonical, resign(func(data []byte) {
			padding := stringsOffset + int(readU64(data, stringsEntry+16))
			if padding >= int(readU64(data, rangesEntry+8)) {
				t.Fatal("fixture has no STRINGS alignment padding")
			}
			data[padding] = 1
		})},
		{"set reserved", CodeSet, resign(func(data []byte) { data[setsOffset+20] = 1 })},
		{"set order", CodeNonCanonical, resign(func(data []byte) {
			copy(data[setsOffset+64+8:setsOffset+64+20], data[setsOffset+8:setsOffset+20])
		})},
		{"set span gap", CodeNonCanonical, resign(func(data []byte) {
			binary.LittleEndian.PutUint32(data[setsOffset+64+24:setsOffset+64+28], 2)
		})},
		{"range inverted", CodeIndex, resign(func(data []byte) {
			binary.LittleEndian.PutUint32(data[rangesOffset:rangesOffset+4], 10)
			binary.LittleEndian.PutUint32(data[rangesOffset+4:rangesOffset+8], 9)
		})},
		{"range adjacent", CodeNonCanonical, resign(func(data []byte) {
			previousHi := binary.LittleEndian.Uint32(data[rangesOffset+4 : rangesOffset+8])
			binary.LittleEndian.PutUint32(data[rangesOffset+8:rangesOffset+12], previousHi+1)
		})},
		{"node reserved", CodeIndex, resign(func(data []byte) { data[nodesOffset+12] = 1 })},
		{"noncanonical string pool", CodeNonCanonical, resign(func(data []byte) {
			sharedOffset := binary.LittleEndian.Uint64(data[setsOffset+64+8 : setsOffset+64+16])
			binary.LittleEndian.PutUint64(data[keywordsOffset:keywordsOffset+8], sharedOffset+2)
		})},
		{"feature mismatch", CodeSection, resign(func(data []byte) {
			binary.LittleEndian.PutUint32(data[16:20], frsformat.FeatureIPv4Ranges|frsformat.FeatureDomainTrie)
		})},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			data := test.edit(append([]byte(nil), valid...))
			summary, err := Verify(data)
			if err == nil || ErrorCode(err) != test.code {
				t.Fatalf("Verify error = %v (%q), want %q", err, ErrorCode(err), test.code)
			}
			if !reflect.DeepEqual(summary, Summary{}) {
				t.Fatalf("failure returned partial summary: %+v", summary)
			}
		})
	}
}

func TestWriterHandlesShortWritesAndFailures(t *testing.T) {
	t.Parallel()
	sets := comprehensiveSets(t)
	want, err := Encode(sets)
	if err != nil {
		t.Fatal(err)
	}
	short := &shortWriter{maximum: 7}
	written, err := Write(short, sets)
	if err != nil || written != int64(len(want)) || !bytes.Equal(short.data, want) {
		t.Fatalf("short write = %d, %v, %d bytes", written, err, len(short.data))
	}
	failing := &shortWriter{maximum: 11, failAfter: 33}
	written, err = Write(failing, sets)
	if err == nil || ErrorCode(err) != CodeWrite || written == 0 || written >= int64(len(want)) {
		t.Fatalf("failure = %d, %v", written, err)
	}
	written, err = Write(zeroWriter{}, sets)
	if written != 0 || !errors.Is(err, io.ErrShortWrite) || ErrorCode(err) != CodeWrite {
		t.Fatalf("zero writer = %d, %v", written, err)
	}
	if _, err := Write(nil, sets); ErrorCode(err) != CodeWrite {
		t.Fatalf("nil writer error = %v", err)
	}
}

func TestEncodeRejectsNonCanonicalIndexesAndSets(t *testing.T) {
	t.Parallel()
	badRanges := index.IPv4Index{Ranges: []index.IPv4Range{{Lo: 1, Hi: 3}, {Lo: 4, Hi: 8}}, PrefixCount: 2}
	badDomain := index.DomainIndex{Keywords: []string{"z", "a"}, RecordCount: 2}
	tests := []merge.Set{
		{Kind: merge.SetIPv4, Label: " bad", IPv4: &index.IPv4Index{}},
		{Kind: merge.SetIPv4, Label: "ip", IPv4: &badRanges},
		{Kind: merge.SetDomain, Label: "domain", Domain: &badDomain},
		{Kind: 99, Label: "unknown"},
	}
	for _, set := range tests {
		if _, err := Encode([]merge.Set{set}); err == nil {
			t.Fatalf("invalid set was accepted: %+v", set)
		}
	}
	valid := index.IPv4Index{}
	duplicate := []merge.Set{
		{Kind: merge.SetIPv4, Label: "same", IPv4: &valid},
		{Kind: merge.SetIPv4, Label: "same", IPv4: &valid},
	}
	if _, err := Encode(duplicate); ErrorCode(err) != CodeSet {
		t.Fatalf("duplicate set error = %v", err)
	}
}

func TestCheckedArithmeticAndWrappedErrorCode(t *testing.T) {
	t.Parallel()
	if _, err := checkedAdd(^uint64(0), 1); ErrorCode(err) != CodeOverflow {
		t.Fatalf("checkedAdd error = %v", err)
	}
	if _, err := checkedMultiply(^uint64(0), 2); ErrorCode(err) != CodeOverflow {
		t.Fatalf("checkedMultiply error = %v", err)
	}
	wrapped := fmt.Errorf("context: %w", frsError(CodeSection, "broken", nil))
	if ErrorCode(wrapped) != CodeSection {
		t.Fatalf("wrapped error code = %q", ErrorCode(wrapped))
	}
}

func FuzzVerifyNeverPanics(f *testing.F) {
	f.Add([]byte{})
	f.Add(readHexFixture(f, "../../testdata/frs/empty-v1.golden.hex"))
	data, err := Encode(comprehensiveSets(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Verify(input)
	})
}

func comprehensiveSets(t testing.TB) []merge.Set {
	t.Helper()
	ipRecords := []model.Record{
		{Kind: model.RuleIPv4, Prefix: netip.MustParsePrefix("10.0.0.0/25")},
		{Kind: model.RuleIPv4, Prefix: netip.MustParsePrefix("10.0.0.128/25")},
		{Kind: model.RuleIPv4, Prefix: netip.MustParsePrefix("192.0.2.1/32")},
		{Kind: model.RuleIPv4, Prefix: netip.MustParsePrefix("255.255.255.255/32")},
	}
	ip, err := index.BuildIPv4(ipRecords)
	if err != nil {
		t.Fatal(err)
	}
	domainRecords := []model.Record{
		{Kind: model.RuleDomainExact, Value: "both.example"},
		{Kind: model.RuleDomainSuffix, Value: "both.example"},
		{Kind: model.RuleDomainExact, Value: "only.example"},
		{Kind: model.RuleDomainKeyword, Value: "ads"},
	}
	domain, err := index.BuildDomain(domainRecords)
	if err != nil {
		t.Fatal(err)
	}
	emptyIP := index.IPv4Index{}
	emptyDomain := index.DomainIndex{}
	return []merge.Set{
		{Kind: merge.SetDomain, Label: "shared", Domain: &domain},
		{Kind: merge.SetIPv4, Label: "shared", IPv4: &ip},
		{Kind: merge.SetDomain, Label: "空域名", Domain: &emptyDomain},
		{Kind: merge.SetIPv4, Label: "empty-ip", IPv4: &emptyIP},
	}
}

func readHexFixture(t testing.TB, path string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func directoryOffsets(data []byte) map[uint32]int {
	result := make(map[uint32]int)
	for position := uint32(0); position < readU32(data, 20); position++ {
		base := 64 + int(position)*40
		result[readU32(data, base)] = int(readU64(data, base+8))
	}
	return result
}

func directoryEntries(data []byte) map[uint32]int {
	result := make(map[uint32]int)
	for position := uint32(0); position < readU32(data, 20); position++ {
		base := 64 + int(position)*40
		result[readU32(data, base)] = base
	}
	return result
}

func resign(edit func([]byte)) func([]byte) []byte {
	return func(data []byte) []byte {
		edit(data)
		binary.LittleEndian.PutUint64(data[48:56], FileChecksum(data))
		return data
	}
}

type shortWriter struct {
	data      []byte
	maximum   int
	failAfter int
}

func (w *shortWriter) Write(data []byte) (int, error) {
	if w.failAfter > 0 && len(w.data) >= w.failAfter {
		return 0, errors.New("injected write failure")
	}
	count := len(data)
	if count > w.maximum {
		count = w.maximum
	}
	if w.failAfter > 0 && len(w.data)+count > w.failAfter {
		count = w.failAfter - len(w.data)
	}
	w.data = append(w.data, data[:count]...)
	if w.failAfter > 0 && len(w.data) >= w.failAfter {
		return count, errors.New("injected write failure")
	}
	return count, nil
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
