package merge

import (
	"net/netip"
	"reflect"
	"testing"

	"frs-tool/internal/config"
	"frs-tool/internal/extract"
	"frs-tool/internal/model"
	"frs-tool/internal/source"
)

func TestBuildReusesSourcesAndProducesDeterministicSets(t *testing.T) {
	t.Parallel()
	groups := []config.Group{
		{Name: "zeta"},
		{Name: "alpha"},
		{Name: "empty"},
	}
	results := []extract.SourceResult{
		{
			SourceID: 1,
			Status:   extract.StatusSuccess,
			IPv4: []model.Record{
				{Kind: model.RuleIPv4, Prefix: netip.MustParsePrefix("10.0.0.0/25")},
			},
			Domains: []model.Record{
				{Kind: model.RuleDomainExact, Value: "exact.example"},
			},
		},
		{
			SourceID: 2,
			Status:   extract.StatusSuccess,
			IPv4: []model.Record{
				{Kind: model.RuleIPv4, Prefix: netip.MustParsePrefix("10.0.0.128/25")},
			},
			Domains: []model.Record{
				{Kind: model.RuleDomainSuffix, Value: "suffix.example"},
				{Kind: model.RuleDomainKeyword, Value: "media"},
			},
		},
		{SourceID: 3, Status: extract.StatusFailed, ErrorCode: "SOURCE_READ"},
	}
	bindings := []source.SourceBinding{
		{PhysicalID: 1, GroupID: 1, SourceIndex: 1},
		{PhysicalID: 2, GroupID: 1, SourceIndex: 2},
		{PhysicalID: 2, GroupID: 2, SourceIndex: 1},
		{PhysicalID: 2, GroupID: 2, SourceIndex: 2},
		{PhysicalID: 3, GroupID: 3, SourceIndex: 1},
	}

	sets, stats, err := Build(groups, bindings, results)
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 4 {
		t.Fatalf("sets = %+v", sets)
	}
	expectedOrder := []struct {
		kind  SetKind
		label string
	}{
		{SetIPv4, "alpha"},
		{SetIPv4, "zeta"},
		{SetDomain, "alpha"},
		{SetDomain, "zeta"},
	}
	for index, expected := range expectedOrder {
		if sets[index].Kind != expected.kind || sets[index].Label != expected.label {
			t.Fatalf("set[%d] = %d/%q", index, sets[index].Kind, sets[index].Label)
		}
	}
	if len(sets[1].IPv4.Ranges) != 1 ||
		!sets[1].IPv4.Contains(netip.MustParseAddr("10.0.0.255")) {
		t.Fatalf("zeta IPv4 index = %+v", sets[1].IPv4)
	}
	if stats.InputRecords != 11 || stats.UniqueRecords != 8 ||
		stats.IPv4Ranges != 2 || stats.OmittedGroups != 1 ||
		stats.IPv4Sets != 2 || stats.DomainSets != 2 {
		t.Fatalf("stats = %+v", stats)
	}

	reversedResults := []extract.SourceResult{results[2], results[1], results[0]}
	reversedBindings := make([]source.SourceBinding, len(bindings))
	for index := range bindings {
		reversedBindings[index] = bindings[len(bindings)-1-index]
	}
	again, againStats, err := Build(groups, reversedBindings, reversedResults)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sets, again) || stats != againStats {
		t.Fatal("merge output depends on completion or binding order")
	}
}

func TestBuildRejectsMissingSourceResult(t *testing.T) {
	t.Parallel()
	_, _, err := Build(
		[]config.Group{{Name: "one"}},
		[]source.SourceBinding{{PhysicalID: 1, GroupID: 1, SourceIndex: 1}},
		nil,
	)
	if err == nil {
		t.Fatal("missing source result was accepted")
	}
}
