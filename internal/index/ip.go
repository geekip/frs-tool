package index

import (
	"errors"
	"net/netip"
	"sort"

	"frs-tool/internal/model"
)

// IPv4Range 是规范化、闭合的 IPv4 数值区间。
type IPv4Range struct {
	Lo uint32
	Hi uint32
}

// IPv4Index 保存合并后的有序区间。
type IPv4Index struct {
	Ranges      []IPv4Range
	PrefixCount int
}

// BuildIPv4 对规范前缀去重，并合并覆盖或相邻区间。
func BuildIPv4(records []model.Record) (IPv4Index, error) {
	prefixes := make(map[netip.Prefix]struct{}, len(records))
	for _, record := range records {
		if record.Kind != model.RuleIPv4 || !record.Prefix.IsValid() || !record.Prefix.Addr().Is4() {
			return IPv4Index{}, errors.New("invalid IPv4 index record")
		}
		prefixes[record.Prefix.Masked()] = struct{}{}
	}
	ranges := make([]IPv4Range, 0, len(prefixes))
	for prefix := range prefixes {
		lo := ipv4Number(prefix.Addr())
		hostBits := 32 - prefix.Bits()
		var size uint64
		if hostBits == 32 {
			size = uint64(1) << 32
		} else {
			size = uint64(1) << hostBits
		}
		hi := uint32(uint64(lo) + size - 1)
		ranges = append(ranges, IPv4Range{Lo: lo, Hi: hi})
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].Lo != ranges[j].Lo {
			return ranges[i].Lo < ranges[j].Lo
		}
		return ranges[i].Hi < ranges[j].Hi
	})

	merged := ranges[:0]
	for _, current := range ranges {
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		previous := &merged[len(merged)-1]
		if uint64(current.Lo) <= uint64(previous.Hi)+1 {
			if current.Hi > previous.Hi {
				previous.Hi = current.Hi
			}
			continue
		}
		merged = append(merged, current)
	}
	return IPv4Index{
		Ranges:      append([]IPv4Range(nil), merged...),
		PrefixCount: len(prefixes),
	}, nil
}

// Contains 使用二分判断地址是否属于任一区间。
func (i IPv4Index) Contains(address netip.Addr) bool {
	if !address.Is4() {
		return false
	}
	value := ipv4Number(address)
	position := sort.Search(len(i.Ranges), func(index int) bool {
		return i.Ranges[index].Lo > value
	})
	if position == 0 {
		return false
	}
	return value <= i.Ranges[position-1].Hi
}

func ipv4Number(address netip.Addr) uint32 {
	octets := address.As4()
	return uint32(octets[0])<<24 |
		uint32(octets[1])<<16 |
		uint32(octets[2])<<8 |
		uint32(octets[3])
}
