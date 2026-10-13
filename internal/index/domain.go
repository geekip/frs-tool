package index

import (
	"errors"
	"sort"
	"strings"

	frsformat "frs-tool/internal/format"
	"frs-tool/internal/model"
	"frs-tool/internal/normalize"
)

// DomainNode 是反向压缩 Trie 的确定性节点。
type DomainNode struct {
	EdgeStart     uint32
	EdgeCount     uint32
	TerminalFlags uint32
}

// DomainEdge 是反向 ASCII 压缩边。
type DomainEdge struct {
	Label string
	Child uint32
}

// DomainIndex 保存 exact/suffix Trie 与有序关键词。
type DomainIndex struct {
	Nodes       []DomainNode
	Edges       []DomainEdge
	Keywords    []string
	RecordCount int
}

type rawNode struct {
	terminal uint32
	children map[byte]*rawNode
}

type logicalNode struct {
	terminal uint32
	edges    []logicalEdge
}

type logicalEdge struct {
	label string
	child *logicalNode
}

// BuildDomain 对域名规则分类型去重并构建规范压缩 Trie。
func BuildDomain(records []model.Record) (DomainIndex, error) {
	exact := make(map[string]struct{})
	suffix := make(map[string]struct{})
	keywords := make(map[string]struct{})
	for _, record := range records {
		switch record.Kind {
		case model.RuleDomainExact:
			normalized, err := normalize.Domain(record.Value)
			if err != nil || normalized != record.Value {
				return DomainIndex{}, errors.New("domain exact record is not normalized")
			}
			exact[record.Value] = struct{}{}
		case model.RuleDomainSuffix:
			normalized, err := normalize.Domain(record.Value)
			if err != nil || normalized != record.Value {
				return DomainIndex{}, errors.New("domain suffix record is not normalized")
			}
			suffix[record.Value] = struct{}{}
		case model.RuleDomainKeyword:
			normalized, err := normalize.Keyword(record.Value)
			if err != nil || normalized != record.Value {
				return DomainIndex{}, errors.New("domain keyword record is not normalized")
			}
			keywords[record.Value] = struct{}{}
		default:
			return DomainIndex{}, errors.New("invalid domain index record")
		}
	}

	var nodes []DomainNode
	var edges []DomainEdge
	if len(exact)+len(suffix) > 0 {
		root := &rawNode{children: make(map[byte]*rawNode)}
		for value := range exact {
			insertDomain(root, value, frsformat.DomainTerminalExact)
		}
		for value := range suffix {
			insertDomain(root, value, frsformat.DomainTerminalSuffix)
		}
		logicalRoot := compressNode(root)

		var ordered []*logicalNode
		var assign func(*logicalNode)
		assign = func(node *logicalNode) {
			ordered = append(ordered, node)
			for _, edge := range node.edges {
				assign(edge.child)
			}
		}
		assign(logicalRoot)
		ids := make(map[*logicalNode]uint32, len(ordered))
		for index, node := range ordered {
			ids[node] = uint32(index + 1)
		}

		nodes = make([]DomainNode, len(ordered))
		for index, node := range ordered {
			nodes[index].TerminalFlags = node.terminal
			if len(node.edges) == 0 {
				continue
			}
			nodes[index].EdgeStart = uint32(len(edges) + 1)
			nodes[index].EdgeCount = uint32(len(node.edges))
			for _, edge := range node.edges {
				edges = append(edges, DomainEdge{Label: edge.label, Child: ids[edge.child]})
			}
		}
	}

	keywordList := make([]string, 0, len(keywords))
	for keyword := range keywords {
		keywordList = append(keywordList, keyword)
	}
	sort.Strings(keywordList)
	recordCount := len(exact) + len(suffix) + len(keywordList)
	return DomainIndex{
		Nodes:       nodes,
		Edges:       edges,
		Keywords:    keywordList,
		RecordCount: recordCount,
	}, nil
}

func insertDomain(root *rawNode, value string, flag uint32) {
	node := root
	for index := len(value) - 1; index >= 0; index-- {
		if node.children == nil {
			node.children = make(map[byte]*rawNode)
		}
		next := node.children[value[index]]
		if next == nil {
			next = &rawNode{children: make(map[byte]*rawNode)}
			node.children[value[index]] = next
		}
		node = next
	}
	node.terminal |= flag
}

func compressNode(raw *rawNode) *logicalNode {
	result := &logicalNode{terminal: raw.terminal}
	keys := sortedChildKeys(raw.children)
	for _, key := range keys {
		label := []byte{key}
		child := raw.children[key]
		for child.terminal == 0 && len(child.children) == 1 {
			nextKey := sortedChildKeys(child.children)[0]
			label = append(label, nextKey)
			child = child.children[nextKey]
		}
		result.edges = append(result.edges, logicalEdge{
			label: string(label),
			child: compressNode(child),
		})
	}
	return result
}

func sortedChildKeys(children map[byte]*rawNode) []byte {
	keys := make([]byte, 0, len(children))
	for key := range children {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

// Contains 按 FRS exact、suffix 与 keyword 语义查询域名。
func (i DomainIndex) Contains(value string) (bool, error) {
	domain, err := normalize.Domain(value)
	if err != nil {
		return false, err
	}
	reversed := reverseBytes(domain)
	if len(i.Nodes) > 0 && i.matchTrie(reversed) {
		return true, nil
	}
	for _, keyword := range i.Keywords {
		if strings.Contains(domain, keyword) {
			return true, nil
		}
	}
	return false, nil
}

func (i DomainIndex) matchTrie(reversed string) bool {
	nodeID := uint32(1)
	position := 0
	for {
		if nodeID == 0 || int(nodeID) > len(i.Nodes) {
			return false
		}
		node := i.Nodes[nodeID-1]
		if node.TerminalFlags&frsformat.DomainTerminalExact != 0 && position == len(reversed) {
			return true
		}
		if node.TerminalFlags&frsformat.DomainTerminalSuffix != 0 &&
			(position == len(reversed) || reversed[position] == '.') {
			return true
		}
		if position == len(reversed) || node.EdgeCount == 0 {
			return false
		}

		start := int(node.EdgeStart - 1)
		end := start + int(node.EdgeCount)
		if start < 0 || end > len(i.Edges) {
			return false
		}
		target := reversed[position]
		offset := sort.Search(end-start, func(index int) bool {
			return i.Edges[start+index].Label[0] >= target
		})
		if offset == end-start {
			return false
		}
		edge := i.Edges[start+offset]
		if edge.Label[0] != target || !strings.HasPrefix(reversed[position:], edge.Label) {
			return false
		}
		position += len(edge.Label)
		nodeID = edge.Child
	}
}

func reverseBytes(value string) string {
	data := []byte(value)
	for left, right := 0, len(data)-1; left < right; left, right = left+1, right-1 {
		data[left], data[right] = data[right], data[left]
	}
	return string(data)
}
