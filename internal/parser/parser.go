package parser

import (
	"net/netip"
	"strings"
	"unicode/utf8"

	"frs-tool/internal/model"
	"frs-tool/internal/normalize"
)

const (
	CodeInvalidUTF8    = "RULE_INVALID_UTF8"
	CodeInvalidIP      = "RULE_INVALID_IP"
	CodeAddressFamily  = "RULE_ADDRESS_FAMILY"
	CodeUnsupported    = "RULE_UNSUPPORTED"
	CodeWildcard       = "RULE_WILDCARD"
	CodeInvalidDomain  = "RULE_INVALID_DOMAIN"
	CodeInvalidKeyword = "RULE_INVALID_KEYWORD"
	CodeInvalidSyntax  = "RULE_INVALID_SYNTAX"
)

// ParseLine 按冻结的识别顺序解析一行混合规则文本。
func ParseLine(line []byte, position model.SourcePosition) model.Outcome {
	if !utf8.Valid(line) {
		return warning(position, CodeInvalidUTF8, "line is not valid UTF-8", "")
	}
	value := string(line)
	if position.Line == 1 {
		value = strings.TrimPrefix(value, "\ufeff")
	}
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "#") || strings.HasPrefix(value, "//") {
		return model.Outcome{Kind: model.OutcomeIgnore, Position: position}
	}

	if strings.HasPrefix(value, "server=/") {
		return parseDNSMasq(value, position)
	}
	if prefix, err := normalize.IPPrefix(value); err == nil {
		return acceptPrefix(prefix, position)
	}
	if tag, payload, ok := explicitPrefix(value); ok {
		return parseExplicit(tag, payload, position)
	}
	if strings.Contains(value, ",") {
		return parseClash(value, position)
	}
	return parsePlain(value, position)
}

func parseDNSMasq(value string, position model.SourcePosition) model.Outcome {
	parts := strings.Split(strings.TrimPrefix(value, "server=/"), "/")
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		return warning(position, CodeInvalidSyntax, "invalid dnsmasq server rule", value)
	}
	target := parts[len(parts)-1]
	if target == "#" || target == "-" {
		return warning(position, CodeUnsupported, "unsupported dnsmasq server target", value)
	}
	records := make([]model.Record, 0, len(parts)-1)
	for _, domain := range parts[:len(parts)-1] {
		if domain == "" {
			return warning(position, CodeInvalidSyntax, "empty dnsmasq domain", value)
		}
		if strings.Contains(domain, "*") {
			return warning(position, CodeWildcard, "wildcard domain is not supported", domain)
		}
		normalized, err := normalize.Domain(domain)
		if err != nil {
			return warning(position, CodeInvalidDomain, "invalid dnsmasq domain", domain)
		}
		records = append(records, record(model.RuleDomainSuffix, netip.Prefix{}, normalized, position))
	}
	return model.Outcome{Kind: model.OutcomeAccept, Records: records, Position: position}
}

func explicitPrefix(value string) (string, string, bool) {
	index := strings.IndexByte(value, ':')
	if index <= 0 {
		return "", "", false
	}
	tag := value[:index]
	if !isASCIIAlpha(tag[0]) {
		return "", "", false
	}
	for i := 1; i < len(tag); i++ {
		c := tag[i]
		if !isASCIIAlpha(c) && (c < '0' || c > '9') && c != '-' && c != '_' {
			return "", "", false
		}
	}
	return strings.ToLower(tag), strings.TrimSpace(value[index+1:]), true
}

func parseExplicit(tag, payload string, position model.SourcePosition) model.Outcome {
	switch tag {
	case "full":
		return acceptDomain(payload, model.RuleDomainExact, position)
	case "domain":
		return acceptDomain(payload, model.RuleDomainSuffix, position)
	case "keyword":
		normalized, err := normalize.Keyword(payload)
		if err != nil {
			return warning(position, CodeInvalidKeyword, "invalid domain keyword", payload)
		}
		return acceptRecord(record(model.RuleDomainKeyword, netip.Prefix{}, normalized, position), position)
	case "regexp", "include":
		return warning(position, CodeUnsupported, "unsupported explicit rule type", tag)
	default:
		return warning(position, CodeUnsupported, "unknown explicit rule type", tag)
	}
}

func parseClash(value string, position model.SourcePosition) model.Outcome {
	fields := strings.Split(value, ",")
	if len(fields) < 2 {
		return warning(position, CodeInvalidSyntax, "invalid Clash rule", value)
	}
	ruleType := strings.ToUpper(strings.TrimSpace(fields[0]))
	payload := strings.TrimSpace(fields[1])
	if payload == "" {
		return warning(position, CodeInvalidSyntax, "empty Clash rule value", value)
	}

	switch ruleType {
	case "IP-CIDR", "IP-CIDR6":
		prefix, err := normalize.IPPrefix(payload)
		if err != nil {
			return warning(position, CodeInvalidIP, "invalid IP prefix", payload)
		}
		expectIPv6 := ruleType == "IP-CIDR6"
		if prefix.Addr().Is6() != expectIPv6 {
			return warning(position, CodeAddressFamily, "rule type and address family do not match", payload)
		}
		return acceptPrefix(prefix, position)
	case "DOMAIN":
		return acceptDomain(payload, model.RuleDomainExact, position)
	case "DOMAIN-SUFFIX":
		return acceptDomain(payload, model.RuleDomainSuffix, position)
	case "DOMAIN-KEYWORD":
		normalized, err := normalize.Keyword(payload)
		if err != nil {
			return warning(position, CodeInvalidKeyword, "invalid domain keyword", payload)
		}
		return acceptRecord(record(model.RuleDomainKeyword, netip.Prefix{}, normalized, position), position)
	case "DOMAIN-REGEX":
		return warning(position, CodeUnsupported, "regular expression rules are not supported", payload)
	default:
		return warning(position, CodeUnsupported, "unknown Clash rule type", ruleType)
	}
}

func parsePlain(value string, position model.SourcePosition) model.Outcome {
	kind := model.RuleDomainSuffix
	domain := value
	switch {
	case strings.HasPrefix(value, "-."):
		kind = model.RuleDomainExact
		domain = value[2:]
	case strings.HasPrefix(value, "+."):
		domain = value[2:]
	case strings.HasPrefix(value, "."):
		domain = value[1:]
	}
	if strings.Contains(domain, "*") {
		return warning(position, CodeWildcard, "wildcard domain is not supported", value)
	}
	return acceptDomain(domain, kind, position)
}

func acceptDomain(value string, kind model.RuleKind, position model.SourcePosition) model.Outcome {
	if strings.Contains(value, "*") {
		return warning(position, CodeWildcard, "wildcard domain is not supported", value)
	}
	normalized, err := normalize.Domain(value)
	if err != nil {
		return warning(position, CodeInvalidDomain, "invalid domain", value)
	}
	return acceptRecord(record(kind, netip.Prefix{}, normalized, position), position)
}

func acceptPrefix(prefix netip.Prefix, position model.SourcePosition) model.Outcome {
	prefix = prefix.Masked()
	if prefix.Addr().Is6() {
		return model.Outcome{
			Kind:          model.OutcomeFilterIPv6,
			FilteredValue: prefix.String(),
			Position:      position,
		}
	}
	return acceptRecord(record(model.RuleIPv4, prefix, "", position), position)
}

func acceptRecord(value model.Record, position model.SourcePosition) model.Outcome {
	return model.Outcome{
		Kind:     model.OutcomeAccept,
		Records:  []model.Record{value},
		Position: position,
	}
}

func record(kind model.RuleKind, prefix netip.Prefix, value string, position model.SourcePosition) model.Record {
	return model.Record{Kind: kind, Prefix: prefix, Value: value, Position: position}
}

func warning(position model.SourcePosition, code, message, value string) model.Outcome {
	return model.Outcome{
		Kind: model.OutcomeWarnSkip,
		Diagnostic: &model.Diagnostic{
			Code:     code,
			Message:  message,
			Value:    value,
			Position: position,
		},
		Position: position,
	}
}

func isASCIIAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
