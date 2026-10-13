package frs

import (
	"fmt"
	"sort"
	"unicode/utf8"

	frsformat "frs-tool/internal/format"
	"frs-tool/internal/index"
	"frs-tool/internal/merge"
	"frs-tool/internal/normalize"
)

func validateSets(sets []merge.Set) error {
	for position := range sets {
		set := &sets[position]
		if !validSetLabel(set.Label) {
			return frsError(CodeSet, fmt.Sprintf("set %d has an invalid label", position+1), nil)
		}
		switch set.Kind {
		case merge.SetIPv4:
			if set.IPv4 == nil || set.Domain != nil {
				return frsError(CodeSet, fmt.Sprintf("IPv4 set %q has inconsistent indexes", set.Label), nil)
			}
			if err := validateIPv4Index(*set.IPv4); err != nil {
				return err
			}
		case merge.SetDomain:
			if set.Domain == nil || set.IPv4 != nil {
				return frsError(CodeSet, fmt.Sprintf("domain set %q has inconsistent indexes", set.Label), nil)
			}
			if err := validateDomainIndex(*set.Domain); err != nil {
				return err
			}
		default:
			return frsError(CodeSet, fmt.Sprintf("set %q has an unsupported kind", set.Label), nil)
		}
	}
	return nil
}

func validSetLabel(label string) bool {
	if label == "" || !utf8.ValidString(label) {
		return false
	}
	first, _ := utf8.DecodeRuneInString(label)
	last, _ := utf8.DecodeLastRuneInString(label)
	if unicodeSpace(first) || unicodeSpace(last) {
		return false
	}
	for _, value := range label {
		if value == ',' || value <= 0x1f || value >= 0x7f && value <= 0x9f {
			return false
		}
	}
	return true
}

func unicodeSpace(value rune) bool {
	return value >= 0x09 && value <= 0x0d || value == 0x20 || value == 0x85 ||
		value == 0xa0 || value == 0x1680 || value >= 0x2000 && value <= 0x200a ||
		value == 0x2028 || value == 0x2029 || value == 0x202f ||
		value == 0x205f || value == 0x3000
}

func validateIPv4Index(value index.IPv4Index) error {
	if value.PrefixCount < 0 || len(value.Ranges) == 0 && value.PrefixCount != 0 ||
		len(value.Ranges) > 0 && value.PrefixCount < len(value.Ranges) {
		return frsError(CodeIndex, "IPv4 prefix count is inconsistent with its ranges", nil)
	}
	for position, current := range value.Ranges {
		if current.Lo > current.Hi {
			return frsError(CodeIndex, "IPv4 range lower bound exceeds upper bound", nil)
		}
		if position > 0 && uint64(current.Lo) <= uint64(value.Ranges[position-1].Hi)+1 {
			return frsError(CodeNonCanonical, "IPv4 ranges overlap or are adjacent", nil)
		}
	}
	return nil
}

func validateDomainIndex(value index.DomainIndex) error {
	for position, keyword := range value.Keywords {
		normalized, err := normalize.Keyword(keyword)
		if err != nil || normalized != keyword {
			return frsError(CodeIndex, "domain keyword is not normalized", nil)
		}
		if position > 0 && value.Keywords[position-1] >= keyword {
			return frsError(CodeNonCanonical, "domain keywords are not strictly sorted", nil)
		}
	}

	if len(value.Nodes) == 0 {
		if len(value.Edges) != 0 {
			return frsError(CodeIndex, "domain edges exist without a trie", nil)
		}
		if value.RecordCount != len(value.Keywords) {
			return frsError(CodeIndex, "domain record count is inconsistent", nil)
		}
		return nil
	}
	if value.Nodes[0].TerminalFlags != 0 {
		return frsError(CodeIndex, "domain trie root is terminal", nil)
	}

	nextEdge := uint64(1)
	terminalCount := 0
	for nodePosition, node := range value.Nodes {
		if node.TerminalFlags&^(frsformat.DomainTerminalExact|frsformat.DomainTerminalSuffix) != 0 {
			return frsError(CodeIndex, "domain node has unsupported terminal flags", nil)
		}
		terminalCount += boolInt(node.TerminalFlags&frsformat.DomainTerminalExact != 0)
		terminalCount += boolInt(node.TerminalFlags&frsformat.DomainTerminalSuffix != 0)
		if node.EdgeCount == 0 {
			if node.EdgeStart != 0 {
				return frsError(CodeNonCanonical, "empty domain edge span has a non-zero start", nil)
			}
		} else {
			if uint64(node.EdgeStart) != nextEdge || uint64(node.EdgeStart-1)+uint64(node.EdgeCount) > uint64(len(value.Edges)) {
				return frsError(CodeNonCanonical, "domain node edge spans are not contiguous", nil)
			}
			nextEdge += uint64(node.EdgeCount)
		}
		if nodePosition > 0 && node.TerminalFlags == 0 && node.EdgeCount <= 1 {
			return frsError(CodeNonCanonical, "domain trie contains an uncompressed node", nil)
		}
	}
	if nextEdge-1 != uint64(len(value.Edges)) {
		return frsError(CodeNonCanonical, "domain edge spans do not cover the edge table", nil)
	}
	if terminalCount == 0 {
		return frsError(CodeIndex, "domain trie has no terminal node", nil)
	}

	for nodePosition, node := range value.Nodes {
		if node.EdgeCount == 0 {
			continue
		}
		start := int(node.EdgeStart - 1)
		end := start + int(node.EdgeCount)
		for edgePosition := start; edgePosition < end; edgePosition++ {
			edge := value.Edges[edgePosition]
			if !validEdgeLabel(edge.Label) {
				return frsError(CodeIndex, "domain edge label is invalid", nil)
			}
			if edge.Child == 0 || uint64(edge.Child) > uint64(len(value.Nodes)) || edge.Child <= uint32(nodePosition+1) {
				return frsError(CodeIndex, "domain edge child is outside the forward trie", nil)
			}
			if edgePosition > start && value.Edges[edgePosition-1].Label[0] >= edge.Label[0] {
				return frsError(CodeNonCanonical, "domain sibling edges are not strictly sorted", nil)
			}
		}
	}

	// 节点编号必须是从根开始、按已排序边进行 DFS 的先序编号。
	type frame struct {
		node       uint32
		next       uint32
		pathLength int
	}
	stack := []frame{{node: 1}}
	path := make([]byte, 0, 253)
	expectedNode := uint32(1)
	visitedTerminals := 0
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		node := value.Nodes[top.node-1]
		if top.next == 0 && node.TerminalFlags != 0 {
			domain := reverseBytes(string(path))
			normalized, err := normalize.Domain(domain)
			if err != nil || normalized != domain {
				return frsError(CodeIndex, "domain terminal path is not normalized", nil)
			}
			visitedTerminals += boolInt(node.TerminalFlags&frsformat.DomainTerminalExact != 0)
			visitedTerminals += boolInt(node.TerminalFlags&frsformat.DomainTerminalSuffix != 0)
		}
		if top.next == node.EdgeCount {
			path = path[:top.pathLength]
			stack = stack[:len(stack)-1]
			continue
		}
		edgePosition := uint64(node.EdgeStart-1) + uint64(top.next)
		edge := value.Edges[int(edgePosition)]
		top.next++
		expectedNode++
		if edge.Child != expectedNode {
			return frsError(CodeNonCanonical, "domain nodes are not in canonical DFS order", nil)
		}
		parentLength := len(path)
		if parentLength+len(edge.Label) > 253 {
			return frsError(CodeIndex, "domain trie path exceeds the normalized domain limit", nil)
		}
		path = append(path, edge.Label...)
		stack = append(stack, frame{node: edge.Child, pathLength: parentLength})
	}
	if int(expectedNode) != len(value.Nodes) || visitedTerminals != terminalCount {
		return frsError(CodeIndex, "domain trie contains unreachable nodes", nil)
	}
	if value.RecordCount != terminalCount+len(value.Keywords) {
		return frsError(CodeIndex, "domain record count is inconsistent", nil)
	}
	return nil
}

func validEdgeLabel(value string) bool {
	if value == "" {
		return false
	}
	for position := range value {
		current := value[position]
		if !(current >= 'a' && current <= 'z' || current >= '0' && current <= '9' || current == '-' || current == '.') {
			return false
		}
	}
	return true
}

func reverseBytes(value string) string {
	data := []byte(value)
	for left, right := 0, len(data)-1; left < right; left, right = left+1, right-1 {
		data[left], data[right] = data[right], data[left]
	}
	return string(data)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func setLess(left, right merge.Set) bool {
	if left.Kind != right.Kind {
		return left.Kind < right.Kind
	}
	return left.Label < right.Label
}

func sortSets(sets []merge.Set) {
	sort.Slice(sets, func(i, j int) bool { return setLess(sets[i], sets[j]) })
}
