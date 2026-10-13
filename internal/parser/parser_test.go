package parser

import (
	"testing"

	"frs-tool/internal/model"
)

func TestParseLineSupportedSyntaxes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		line        string
		outcome     model.OutcomeKind
		kind        model.RuleKind
		value       string
		recordCount int
	}{
		{"# comment", model.OutcomeIgnore, "", "", 0},
		{"IP-CIDR,192.168.7.99/24,DIRECT,no-resolve", model.OutcomeAccept, model.RuleIPv4, "192.168.7.0/24", 1},
		{"IP-CIDR6,2001:db8::1/64", model.OutcomeFilterIPv6, "", "2001:db8::/64", 0},
		{"full:Exact.Example.COM.", model.OutcomeAccept, model.RuleDomainExact, "exact.example.com", 1},
		{"domain:Example.COM", model.OutcomeAccept, model.RuleDomainSuffix, "example.com", 1},
		{"keyword:Media,Video", model.OutcomeAccept, model.RuleDomainKeyword, "media,video", 1},
		{"server=/One.Example/Two.Example/8.8.8.8", model.OutcomeAccept, model.RuleDomainSuffix, "one.example", 2},
		{"-.Host.Example.COM", model.OutcomeAccept, model.RuleDomainExact, "host.example.com", 1},
		{"+.Example.COM", model.OutcomeAccept, model.RuleDomainSuffix, "example.com", 1},
		{"192.0.2.1", model.OutcomeAccept, model.RuleIPv4, "192.0.2.1/32", 1},
		{"2001:db8::1", model.OutcomeFilterIPv6, "", "2001:db8::1/128", 0},
		{"Plain.Example.COM", model.OutcomeAccept, model.RuleDomainSuffix, "plain.example.com", 1},
	}
	for index, test := range tests {
		position := model.SourcePosition{SourceID: 7, Location: "fixture", Line: uint64(index + 1), Column: 1}
		outcome := ParseLine([]byte(test.line), position)
		if outcome.Kind != test.outcome {
			t.Errorf("%q outcome = %q, want %q; diagnostic=%+v", test.line, outcome.Kind, test.outcome, outcome.Diagnostic)
			continue
		}
		if len(outcome.Records) != test.recordCount {
			t.Errorf("%q record count = %d, want %d", test.line, len(outcome.Records), test.recordCount)
			continue
		}
		if test.outcome == model.OutcomeFilterIPv6 {
			if outcome.FilteredValue != test.value {
				t.Errorf("%q filtered = %q, want %q", test.line, outcome.FilteredValue, test.value)
			}
			continue
		}
		if test.recordCount > 0 {
			record := outcome.Records[0]
			actual := record.Value
			if record.Kind == model.RuleIPv4 {
				actual = record.Prefix.String()
			}
			if record.Kind != test.kind || actual != test.value {
				t.Errorf("%q record = (%q,%q), want (%q,%q)", test.line, record.Kind, actual, test.kind, test.value)
			}
			if record.Position != position {
				t.Errorf("%q lost source position", test.line)
			}
		}
	}
}

func TestParseLineWarningsDoNotFallback(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"DOMAIN-REGEX,^.*example$":              CodeUnsupported,
		"UNKNOWN,whatever":                      CodeUnsupported,
		"unknown:value":                         CodeUnsupported,
		"*.example.com":                         CodeWildcard,
		"DOMAIN,bad_name":                       CodeInvalidDomain,
		"IP-CIDR,2001:db8::/32":                 CodeAddressFamily,
		"IP-CIDR6,192.0.2.0/24":                 CodeAddressFamily,
		"IP-CIDR,not-an-ip":                     CodeInvalidIP,
		"server=/good.example/*/8.8.8.8":        CodeWildcard,
		"server=/good.example/bad_name/8.8.8.8": CodeInvalidDomain,
		"server=/example.com/#":                 CodeUnsupported,
	}
	for line, code := range tests {
		outcome := ParseLine([]byte(line), model.SourcePosition{Line: 2, Column: 1})
		if outcome.Kind != model.OutcomeWarnSkip || outcome.Diagnostic == nil {
			t.Errorf("%q did not produce warning: %+v", line, outcome)
			continue
		}
		if outcome.Diagnostic.Code != code {
			t.Errorf("%q code = %q, want %q", line, outcome.Diagnostic.Code, code)
		}
		if len(outcome.Records) != 0 {
			t.Errorf("%q accepted records after warning", line)
		}
	}
}

func TestParseLineBOMOnlyAtFileStartAndInvalidUTF8(t *testing.T) {
	t.Parallel()
	bom := string(rune(0xfeff))
	first := ParseLine([]byte(bom+"example.com"), model.SourcePosition{Line: 1})
	if first.Kind != model.OutcomeAccept {
		t.Fatalf("first-line BOM was not accepted: %+v", first)
	}
	later := ParseLine([]byte(bom+"example.com"), model.SourcePosition{Line: 2})
	if later.Kind != model.OutcomeWarnSkip || later.Diagnostic.Code != CodeInvalidDomain {
		t.Fatalf("later BOM was accepted: %+v", later)
	}
	invalid := ParseLine([]byte{0xff}, model.SourcePosition{Line: 1})
	if invalid.Kind != model.OutcomeWarnSkip || invalid.Diagnostic.Code != CodeInvalidUTF8 {
		t.Fatalf("invalid UTF-8 result: %+v", invalid)
	}
}
