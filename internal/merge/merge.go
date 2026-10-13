package merge

import (
	"errors"
	"sort"

	"frs-tool/internal/config"
	"frs-tool/internal/extract"
	frsformat "frs-tool/internal/format"
	"frs-tool/internal/index"
	"frs-tool/internal/model"
	"frs-tool/internal/source"
)

// SetKind 对应 FRS 集合类型。
type SetKind uint16

const (
	SetIPv4   SetKind = SetKind(frsformat.SetKindIPv4)
	SetDomain SetKind = SetKind(frsformat.SetKindDomain)
)

// Set 是 writer 之前的确定性集合索引。
type Set struct {
	Kind   SetKind
	Label  string
	IPv4   *index.IPv4Index
	Domain *index.DomainIndex
}

// RecordCount 返回集合的规范记录数量。
func (s Set) RecordCount() int {
	switch s.Kind {
	case SetIPv4:
		if s.IPv4 != nil {
			return s.IPv4.PrefixCount
		}
	case SetDomain:
		if s.Domain != nil {
			return s.Domain.RecordCount
		}
	}
	return 0
}

// Stats 保存归并前后确定性计数。
type Stats struct {
	InputRecords  uint64
	UniqueRecords uint64
	IPv4Prefixes  uint64
	IPv4Ranges    uint64
	OmittedGroups uint64
	IPv4Sets      uint64
	DomainSets    uint64
}

// Build 按 bindings 复用来源结果，并构建有序集合。
func Build(groups []config.Group, bindings []source.SourceBinding, results []extract.SourceResult) ([]Set, Stats, error) {
	resultByID := make(map[uint32]extract.SourceResult, len(results))
	for _, result := range results {
		if result.SourceID == 0 {
			return nil, Stats{}, errors.New("source result has zero ID")
		}
		if _, exists := resultByID[result.SourceID]; exists {
			return nil, Stats{}, errors.New("duplicate source result")
		}
		resultByID[result.SourceID] = result
	}

	orderedBindings := append([]source.SourceBinding(nil), bindings...)
	sort.Slice(orderedBindings, func(i, j int) bool {
		if orderedBindings[i].GroupID != orderedBindings[j].GroupID {
			return orderedBindings[i].GroupID < orderedBindings[j].GroupID
		}
		if orderedBindings[i].SourceIndex != orderedBindings[j].SourceIndex {
			return orderedBindings[i].SourceIndex < orderedBindings[j].SourceIndex
		}
		return orderedBindings[i].PhysicalID < orderedBindings[j].PhysicalID
	})

	type groupRecords struct {
		ip      []model.Record
		domains []model.Record
	}
	records := make([]groupRecords, len(groups))
	var stats Stats
	for _, binding := range orderedBindings {
		if binding.GroupID == 0 || int(binding.GroupID) > len(groups) {
			return nil, Stats{}, errors.New("binding references unknown group")
		}
		result, ok := resultByID[binding.PhysicalID]
		if !ok {
			return nil, Stats{}, errors.New("binding references missing source result")
		}
		if result.Status != extract.StatusSuccess {
			continue
		}
		group := &records[binding.GroupID-1]
		group.ip = append(group.ip, result.IPv4...)
		group.domains = append(group.domains, result.Domains...)
		stats.InputRecords += uint64(len(result.IPv4) + len(result.Domains))
	}

	var sets []Set
	for groupIndex, group := range records {
		generated := false
		if len(group.ip) > 0 {
			ipIndex, err := index.BuildIPv4(group.ip)
			if err != nil {
				return nil, Stats{}, err
			}
			sets = append(sets, Set{
				Kind:  SetIPv4,
				Label: groups[groupIndex].Name,
				IPv4:  &ipIndex,
			})
			stats.UniqueRecords += uint64(ipIndex.PrefixCount)
			stats.IPv4Prefixes += uint64(ipIndex.PrefixCount)
			stats.IPv4Ranges += uint64(len(ipIndex.Ranges))
			stats.IPv4Sets++
			generated = true
		}
		if len(group.domains) > 0 {
			domainIndex, err := index.BuildDomain(group.domains)
			if err != nil {
				return nil, Stats{}, err
			}
			sets = append(sets, Set{
				Kind:   SetDomain,
				Label:  groups[groupIndex].Name,
				Domain: &domainIndex,
			})
			stats.UniqueRecords += uint64(domainIndex.RecordCount)
			stats.DomainSets++
			generated = true
		}
		if !generated {
			stats.OmittedGroups++
		}
	}

	sort.Slice(sets, func(i, j int) bool {
		if sets[i].Kind != sets[j].Kind {
			return sets[i].Kind < sets[j].Kind
		}
		return sets[i].Label < sets[j].Label
	})
	return sets, stats, nil
}
