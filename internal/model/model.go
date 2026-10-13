package model

import "net/netip"

// RuleKind 表示已经规范化的规则类型。
type RuleKind string

const (
	RuleIPv4          RuleKind = "ipv4"
	RuleDomainExact   RuleKind = "domain_exact"
	RuleDomainSuffix  RuleKind = "domain_suffix"
	RuleDomainKeyword RuleKind = "domain_keyword"
)

// OutcomeKind 表示单行解析结果。
type OutcomeKind string

const (
	OutcomeIgnore     OutcomeKind = "ignore"
	OutcomeAccept     OutcomeKind = "accept"
	OutcomeFilterIPv6 OutcomeKind = "filter_ipv6"
	OutcomeWarnSkip   OutcomeKind = "warn_skip"
)

// SourcePosition 标识诊断信息对应的来源与位置。
type SourcePosition struct {
	SourceID uint32
	Location string
	Line     uint64
	Column   uint64
}

// Record 是解析后的规范化规则。
type Record struct {
	Kind     RuleKind
	Prefix   netip.Prefix
	Value    string
	Position SourcePosition
}

// Diagnostic 是可聚合、可定位的解析诊断。
type Diagnostic struct {
	Code     string
	Message  string
	Value    string
	Position SourcePosition
}

// Outcome 保留接受、忽略、过滤与告警跳过四种互斥结果。
type Outcome struct {
	Kind          OutcomeKind
	Records       []Record
	FilteredValue string
	Diagnostic    *Diagnostic
	Position      SourcePosition
}
