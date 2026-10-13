package index

import (
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"

	"frs-tool/internal/model"
	"frs-tool/internal/normalize"
)

func TestBuildDomainAndMatchSemantics(t *testing.T) {
	t.Parallel()
	records := []model.Record{
		domainRecord(model.RuleDomainExact, "exact.example.com"),
		domainRecord(model.RuleDomainSuffix, "suffix.example.com"),
		domainRecord(model.RuleDomainExact, "both.example.net"),
		domainRecord(model.RuleDomainSuffix, "both.example.net"),
		domainRecord(model.RuleDomainKeyword, "media"),
		domainRecord(model.RuleDomainKeyword, "media"),
	}
	index, err := BuildDomain(records)
	if err != nil {
		t.Fatal(err)
	}
	if index.RecordCount != 5 || len(index.Keywords) != 1 {
		t.Fatalf("index counts = %+v", index)
	}
	tests := map[string]bool{
		"exact.example.com":        true,
		"child.exact.example.com":  false,
		"suffix.example.com":       true,
		"child.suffix.example.com": true,
		"badsuffix.example.com":    false,
		"both.example.net":         true,
		"child.both.example.net":   true,
		"streaming-media.test":     true,
		"unrelated.test":           false,
	}
	for value, expected := range tests {
		actual, err := index.Contains(value)
		if err != nil {
			t.Fatal(err)
		}
		if actual != expected {
			t.Errorf("Contains(%q) = %v, want %v", value, actual, expected)
		}
	}
	if len(index.Nodes) == 0 || index.Nodes[0].TerminalFlags != 0 {
		t.Fatal("domain trie has no non-terminal root")
	}
	for nodeIndex, node := range index.Nodes {
		if node.EdgeCount == 0 {
			if node.EdgeStart != 0 {
				t.Fatalf("empty node %d has edge start", nodeIndex)
			}
			continue
		}
		start := int(node.EdgeStart - 1)
		edges := index.Edges[start : start+int(node.EdgeCount)]
		if !sort.SliceIsSorted(edges, func(i, j int) bool {
			return edges[i].Label[0] < edges[j].Label[0]
		}) {
			t.Fatalf("node %d edges are not sorted", nodeIndex)
		}
		for _, edge := range edges {
			if edge.Child <= uint32(nodeIndex+1) {
				t.Fatalf("child %d is not after parent %d", edge.Child, nodeIndex+1)
			}
		}
	}
}

func TestBuildDomainKeywordOnlyHasNoTrie(t *testing.T) {
	t.Parallel()
	index, err := BuildDomain([]model.Record{domainRecord(model.RuleDomainKeyword, "keyword")})
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Nodes) != 0 || len(index.Edges) != 0 || !reflect.DeepEqual(index.Keywords, []string{"keyword"}) {
		t.Fatalf("keyword-only index = %+v", index)
	}
}

func TestDomainIndexDeterministicAndRandomDifferential(t *testing.T) {
	t.Parallel()
	random := rand.New(rand.NewSource(73))
	var records []model.Record
	for count := 0; count < 250; count++ {
		value := randomDomain(random)
		kind := []model.RuleKind{
			model.RuleDomainExact,
			model.RuleDomainSuffix,
			model.RuleDomainKeyword,
		}[random.Intn(3)]
		if kind == model.RuleDomainKeyword {
			value = strings.Split(value, ".")[0]
		}
		records = append(records, domainRecord(kind, value))
	}
	first, err := BuildDomain(records)
	if err != nil {
		t.Fatal(err)
	}
	shuffled := append([]model.Record(nil), records...)
	random.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	second, err := BuildDomain(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("domain index depends on input order")
	}

	for count := 0; count < 3000; count++ {
		query := randomDomain(random)
		expected := referenceDomainMatch(records, query)
		actual, err := first.Contains(query)
		if err != nil {
			t.Fatal(err)
		}
		if actual != expected {
			t.Fatalf("Contains(%q) = %v, want %v", query, actual, expected)
		}
	}
}

func TestBuildDomainRejectsUnnormalizedRecords(t *testing.T) {
	t.Parallel()
	_, err := BuildDomain([]model.Record{domainRecord(model.RuleDomainExact, "Upper.Example")})
	if err == nil {
		t.Fatal("unnormalized domain was accepted")
	}
	_, err = BuildDomain([]model.Record{domainRecord(model.RuleDomainKeyword, "UPPER")})
	if err == nil {
		t.Fatal("unnormalized keyword was accepted")
	}
}

func referenceDomainMatch(records []model.Record, query string) bool {
	domain, err := normalize.Domain(query)
	if err != nil {
		return false
	}
	for _, record := range records {
		switch record.Kind {
		case model.RuleDomainExact:
			if domain == record.Value {
				return true
			}
		case model.RuleDomainSuffix:
			if domain == record.Value || strings.HasSuffix(domain, "."+record.Value) {
				return true
			}
		case model.RuleDomainKeyword:
			if strings.Contains(domain, record.Value) {
				return true
			}
		}
	}
	return false
}

func randomDomain(random *rand.Rand) string {
	labels := 2 + random.Intn(3)
	parts := make([]string, labels)
	for index := range parts {
		length := 1 + random.Intn(6)
		var builder strings.Builder
		for char := 0; char < length; char++ {
			builder.WriteByte(byte('a' + random.Intn(6)))
		}
		parts[index] = builder.String()
	}
	return strings.Join(parts, ".")
}

func domainRecord(kind model.RuleKind, value string) model.Record {
	return model.Record{Kind: kind, Value: value}
}
