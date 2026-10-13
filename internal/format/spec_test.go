package format_test

import (
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"os"
	"strings"
	"testing"

	frsformat "frs-tool/internal/format"
)

func TestFrozenConstants(t *testing.T) {
	t.Parallel()
	if frsformat.Magic != "FTUNFRS"+string(byte(0)) {
		t.Fatalf("magic = %q", frsformat.Magic)
	}
	if frsformat.VersionMajor != 1 || frsformat.VersionMinor != 0 ||
		frsformat.HeaderBytes != 64 || frsformat.DirEntryBytes != 40 {
		t.Fatal("file header constants differ from FRS 1.0")
	}
	if frsformat.SectionFlagMandatory != 1 ||
		frsformat.SetKindIPv4 != 1 || frsformat.SetKindDomain != 2 ||
		frsformat.EncodingIPv4Ranges != 1 || frsformat.EncodingDomainRadixKeyword != 2 ||
		frsformat.DomainTerminalExact != 1 || frsformat.DomainTerminalSuffix != 2 {
		t.Fatal("record flags, kinds, or encoding constants differ from FRS 1.0")
	}
	sections := []uint32{
		frsformat.SectionSets,
		frsformat.SectionStrings,
		frsformat.SectionIPv4Ranges,
		frsformat.SectionDomainNodes,
		frsformat.SectionDomainEdges,
		frsformat.SectionKeywords,
		frsformat.SectionIPv6Reserved,
	}
	for index, section := range sections {
		if section != uint32(index+1) {
			t.Fatalf("section[%d] = %d", index, section)
		}
	}
	strides := []uint32{
		frsformat.SetRecordBytes,
		frsformat.StringRecordBytes,
		frsformat.IPv4RangeRecordBytes,
		frsformat.DomainNodeRecordBytes,
		frsformat.DomainEdgeRecordBytes,
		frsformat.KeywordRecordBytes,
	}
	expected := []uint32{64, 1, 8, 16, 16, 16}
	for index := range strides {
		if strides[index] != expected[index] {
			t.Fatalf("stride[%d] = %d, want %d", index, strides[index], expected[index])
		}
	}
}

func TestEmptyContainerGoldenBytes(t *testing.T) {
	t.Parallel()
	encoded, err := os.ReadFile("../../testdata/frs/empty-v1.golden.hex")
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 104 {
		t.Fatalf("file length = %d, want 104", len(data))
	}
	if string(data[0:8]) != frsformat.Magic {
		t.Fatalf("magic bytes = %x", data[0:8])
	}
	if binary.LittleEndian.Uint16(data[8:10]) != 1 ||
		binary.LittleEndian.Uint16(data[10:12]) != 0 ||
		binary.LittleEndian.Uint32(data[12:16]) != 64 {
		t.Fatal("invalid version or header size")
	}
	if binary.LittleEndian.Uint32(data[16:20]) != 0 ||
		binary.LittleEndian.Uint32(data[20:24]) != 1 ||
		binary.LittleEndian.Uint64(data[24:32]) != uint64(len(data)) ||
		binary.LittleEndian.Uint64(data[32:40]) != 64 {
		t.Fatal("invalid header capability, directory, or length fields")
	}
	if !allZero(data[40:48]) || !allZero(data[56:64]) {
		t.Fatal("reserved header bytes are not zero")
	}
	if binary.LittleEndian.Uint32(data[64:68]) != 1 ||
		binary.LittleEndian.Uint32(data[68:72]) != 1 ||
		binary.LittleEndian.Uint64(data[72:80]) != 104 ||
		binary.LittleEndian.Uint64(data[80:88]) != 0 ||
		binary.LittleEndian.Uint64(data[88:96]) != 0 ||
		binary.LittleEndian.Uint32(data[96:100]) != 64 ||
		binary.LittleEndian.Uint32(data[100:104]) != 0 {
		t.Fatal("invalid empty SETS directory entry")
	}

	stored := binary.LittleEndian.Uint64(data[48:56])
	checksumInput := append([]byte(nil), data...)
	clear(checksumInput[48:56])
	if actual := referenceXXH64(checksumInput); actual != stored {
		t.Fatalf("checksum = %016x, want %016x", actual, stored)
	}
}

func TestReferenceXXH64KnownVector(t *testing.T) {
	t.Parallel()
	if actual := referenceXXH64(nil); actual != 0xef46db3751d8e999 {
		t.Fatalf("XXH64(empty) = %016x", actual)
	}
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

const (
	xxhPrime1 uint64 = 11400714785074694791
	xxhPrime2 uint64 = 14029467366897019727
	xxhPrime3 uint64 = 1609587929392839161
	xxhPrime4 uint64 = 9650029242287828579
	xxhPrime5 uint64 = 2870177450012600261
)

func xxhRound(accumulator, input uint64) uint64 {
	accumulator += input * xxhPrime2
	accumulator = bits.RotateLeft64(accumulator, 31)
	return accumulator * xxhPrime1
}

func xxhMergeRound(accumulator, value uint64) uint64 {
	accumulator ^= xxhRound(0, value)
	return accumulator*xxhPrime1 + xxhPrime4
}

func referenceXXH64(data []byte) uint64 {
	original := data
	var hash uint64
	if len(data) >= 32 {
		v1 := uint64(xxhPrime1)
		v1 += xxhPrime2
		v2 := xxhPrime2
		v3 := uint64(0)
		v4 := uint64(0)
		v4 -= xxhPrime1
		for len(data) >= 32 {
			v1 = xxhRound(v1, binary.LittleEndian.Uint64(data[0:8]))
			v2 = xxhRound(v2, binary.LittleEndian.Uint64(data[8:16]))
			v3 = xxhRound(v3, binary.LittleEndian.Uint64(data[16:24]))
			v4 = xxhRound(v4, binary.LittleEndian.Uint64(data[24:32]))
			data = data[32:]
		}
		hash = bits.RotateLeft64(v1, 1) + bits.RotateLeft64(v2, 7) +
			bits.RotateLeft64(v3, 12) + bits.RotateLeft64(v4, 18)
		hash = xxhMergeRound(hash, v1)
		hash = xxhMergeRound(hash, v2)
		hash = xxhMergeRound(hash, v3)
		hash = xxhMergeRound(hash, v4)
	} else {
		hash = xxhPrime5
	}
	hash += uint64(len(original))
	for len(data) >= 8 {
		value := xxhRound(0, binary.LittleEndian.Uint64(data[:8]))
		hash ^= value
		hash = bits.RotateLeft64(hash, 27)*xxhPrime1 + xxhPrime4
		data = data[8:]
	}
	if len(data) >= 4 {
		hash ^= uint64(binary.LittleEndian.Uint32(data[:4])) * xxhPrime1
		hash = bits.RotateLeft64(hash, 23)*xxhPrime2 + xxhPrime3
		data = data[4:]
	}
	for _, value := range data {
		hash ^= uint64(value) * xxhPrime5
		hash = bits.RotateLeft64(hash, 11) * xxhPrime1
	}
	hash ^= hash >> 33
	hash *= xxhPrime2
	hash ^= hash >> 29
	hash *= xxhPrime3
	hash ^= hash >> 32
	return hash
}
