package parser

import (
	"bufio"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"frs-tool/internal/model"
	"frs-tool/internal/normalize"
)

type fixtureRecord struct {
	Line  uint64
	Kind  string
	Value string
}

type fixtureFiltered struct {
	Line  uint64
	Value string
}

type fixtureWarning struct {
	Line uint64
	Code string
}

type fixtureExpected struct {
	Records  []fixtureRecord
	Filtered []fixtureFiltered
	Warnings []fixtureWarning
}

type queryVector struct {
	Kind  string
	Value string
	Match bool
}

func TestMixedInputFixtureAndQueryVectors(t *testing.T) {
	t.Parallel()
	file, err := os.Open("../../testdata/input/mixed-rules.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var actual fixtureExpected
	var parsed []model.Record
	scanner := bufio.NewScanner(file)
	lineNumber := uint64(0)
	for scanner.Scan() {
		lineNumber++
		outcome := ParseLine(scanner.Bytes(), model.SourcePosition{
			SourceID: 1,
			Location: "mixed-rules.txt",
			Line:     lineNumber,
			Column:   1,
		})
		switch outcome.Kind {
		case model.OutcomeAccept:
			parsed = append(parsed, outcome.Records...)
			for _, record := range outcome.Records {
				value := record.Value
				if record.Kind == model.RuleIPv4 {
					value = record.Prefix.String()
				}
				actual.Records = append(actual.Records, fixtureRecord{
					Line: record.Position.Line, Kind: string(record.Kind), Value: value,
				})
			}
		case model.OutcomeFilterIPv6:
			actual.Filtered = append(actual.Filtered, fixtureFiltered{
				Line: outcome.Position.Line, Value: outcome.FilteredValue,
			})
		case model.OutcomeWarnSkip:
			actual.Warnings = append(actual.Warnings, fixtureWarning{
				Line: outcome.Position.Line, Code: outcome.Diagnostic.Code,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	var expected fixtureExpected
	readJSONFixture(t, "../../testdata/expected/mixed-rules.json", &expected)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("mixed fixture mismatch actual=%#v expected=%#v", actual, expected)
	}

	var vectors []queryVector
	readJSONFixture(t, "../../testdata/query-vectors.json", &vectors)
	for _, vector := range vectors {
		actualMatch := referenceMatch(t, parsed, vector)
		if actualMatch != vector.Match {
			t.Errorf("%s query %q = %v, want %v", vector.Kind, vector.Value, actualMatch, vector.Match)
		}
	}
}

func readJSONFixture(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}

func referenceMatch(t *testing.T, records []model.Record, vector queryVector) bool {
	t.Helper()
	switch vector.Kind {
	case "ip":
		address, err := netip.ParseAddr(vector.Value)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range records {
			if record.Kind == model.RuleIPv4 && record.Prefix.Contains(address) {
				return true
			}
		}
		return false
	case "domain":
		domain, err := normalize.Domain(vector.Value)
		if err != nil {
			t.Fatal(err)
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
	default:
		t.Fatalf("unknown query kind %q", vector.Kind)
		return false
	}
}
