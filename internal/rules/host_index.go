package rules

import (
	"sort"
	"strings"
)

// hostCandidateIndex is an immutable, reversed-label hostname tree. It does
// not replace matcher semantics: it only narrows the ordered rule candidates
// that still run through matcher.match. Rules that cannot be indexed safely
// remain in fallback and are merged by original rule number at lookup time.
//
// For example, *.ads.example.com and an imported suffix for example.com are
// both indexed along root -> com -> example. A lookup walks the requested host
// right-to-left, gathers candidates attached to every visited node, merges the
// fallback list, and evaluates the resulting rule numbers in source order.
type hostCandidateIndex struct {
	nodes    []hostIndexNode
	edges    []hostIndexEdge
	ruleIDs  []int
	fallback []int
}

type hostIndexNode struct {
	edgeStart uint32
	edgeCount uint32
	ruleStart uint32
	ruleCount uint32
}

type hostIndexEdge struct {
	label string
	child uint32
}

// mutableHostIndexNode exists only while compiling. buildHostCandidateIndex
// flattens it into the compact slices above, allowing all per-node maps and
// pointers to be reclaimed before the policy reaches the request path.
type mutableHostIndexNode struct {
	children map[string]*mutableHostIndexNode
	rules    []int
}

func buildHostCandidateIndex(rules []CompiledRule) *hostCandidateIndex {
	root := &mutableHostIndexNode{}
	var fallback []int
	for ruleID := range rules {
		m := rules[ruleID].connHost
		if suffixes, ok := importedSuffixRegex(m); ok {
			for _, suffix := range suffixes {
				insertHostSuffix(root, suffix, ruleID)
			}
			continue
		}
		if suffix := literalGlobSuffix(m); suffix != "" {
			insertHostSuffix(root, suffix, ruleID)
			continue
		}
		fallback = append(fallback, ruleID)
	}
	return compactHostIndex(root, fallback)
}

func insertHostSuffix(root *mutableHostIndexNode, host string, ruleID int) {
	node := root
	for end := len(host); end > 0; {
		start := strings.LastIndexByte(host[:end], '.') + 1
		label := host[start:end]
		if node.children == nil {
			node.children = make(map[string]*mutableHostIndexNode)
		}
		child := node.children[label]
		if child == nil {
			child = &mutableHostIndexNode{}
			// Do not retain a whole hostname backing array for each substring
			// used as an edge label.
			node.children[strings.Clone(label)] = child
		}
		node = child
		if start == 0 {
			break
		}
		end = start - 1
	}
	// The same grouped regex can contain both a parent and one of its
	// subdomains, so one lookup path may encounter the same rule more than
	// once. Keep node-local duplicates out; appendCandidates removes duplicates
	// across different nodes on the path.
	if len(node.rules) == 0 || node.rules[len(node.rules)-1] != ruleID {
		node.rules = append(node.rules, ruleID)
	}
}

func compactHostIndex(root *mutableHostIndexNode, fallback []int) *hostCandidateIndex {
	builders := []*mutableHostIndexNode{root}
	ids := map[*mutableHostIndexNode]uint32{root: 0}
	childLabels := make([][]string, 0, 1)
	for pos := 0; pos < len(builders); pos++ {
		node := builders[pos]
		labels := make([]string, 0, len(node.children))
		for label := range node.children {
			labels = append(labels, label)
		}
		sort.Strings(labels)
		childLabels = append(childLabels, labels)
		for _, label := range labels {
			child := node.children[label]
			ids[child] = uint32(len(builders))
			builders = append(builders, child)
		}
	}

	index := &hostCandidateIndex{
		nodes:    make([]hostIndexNode, len(builders)),
		fallback: fallback,
	}
	for nodeID, builder := range builders {
		node := &index.nodes[nodeID]
		node.edgeStart = uint32(len(index.edges))
		for _, label := range childLabels[nodeID] {
			index.edges = append(index.edges, hostIndexEdge{label: label, child: ids[builder.children[label]]})
		}
		node.edgeCount = uint32(len(index.edges)) - node.edgeStart
		node.ruleStart = uint32(len(index.ruleIDs))
		index.ruleIDs = append(index.ruleIDs, builder.rules...)
		node.ruleCount = uint32(len(index.ruleIDs)) - node.ruleStart
	}
	return index
}

// appendCandidates appends rule numbers in original first-match order. Its
// caller supplies stack storage for the common path (a few indexed candidates
// plus a catch-all); unusual policies remain correct via append's bounded
// growth.
func (i *hostCandidateIndex) appendCandidates(host string, result []int) []int {
	result = append(result, i.fallback...)

	// Imported suffix regexes are explicitly case-insensitive. Ordinary proxy
	// authorities are already canonical lowercase, while this also indexes an
	// unusually-cased transparent TLS SNI; matcher.match below remains the
	// final authority for case-sensitive glob rules.
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(i.nodes) == 0 {
		return result
	}
	nodeID := uint32(0)
	for end := len(host); end > 0; {
		start := strings.LastIndexByte(host[:end], '.') + 1
		childID, ok := i.findChild(nodeID, host[start:end])
		if !ok {
			break
		}
		nodeID = childID
		node := i.nodes[nodeID]
		result = append(result, i.ruleIDs[node.ruleStart:node.ruleStart+node.ruleCount]...)
		if start == 0 {
			break
		}
		end = start - 1
	}

	sort.Ints(result)
	if len(result) < 2 {
		return result
	}
	out := 1
	for n := 1; n < len(result); n++ {
		if result[n] != result[out-1] {
			result[out] = result[n]
			out++
		}
	}
	return result[:out]
}

func (i *hostCandidateIndex) findChild(nodeID uint32, label string) (uint32, bool) {
	node := i.nodes[nodeID]
	lo := int(node.edgeStart)
	hi := lo + int(node.edgeCount)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		edge := i.edges[mid]
		if edge.label < label {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	end := int(node.edgeStart + node.edgeCount)
	if lo == end || i.edges[lo].label != label {
		return 0, false
	}
	return i.edges[lo].child, true
}

// literalGlobSuffix extracts only complete, lowercase literal DNS labels from
// the right side of a glob. It is deliberately conservative: the original
// path.Match glob is always run afterward, so this index can produce false
// positives but must never omit a possible match.
func literalGlobSuffix(m matcher) string {
	if m.always || m.re != nil || m.suffixes != nil || m.glob == "" {
		return ""
	}
	labels := strings.Split(m.glob, ".")
	first := len(labels)
	for first > 0 && isLiteralDNSLabel(labels[first-1]) {
		first--
	}
	if first == len(labels) {
		return ""
	}
	return strings.Join(labels[first:], ".")
}

func isLiteralDNSLabel(label string) bool {
	if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range []byte(label) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

// importedSuffixRegex recognizes exactly the canonical finite-language form
// emitted by tools/adblock_to_mitmania.py:
//
//	(?i)(?:^|\.)(?:ads\.example|tracker\.example)$
//
// Recognizing this strict subset is an optimization only. Any deviation stays
// on the ordinary regex fallback path, so persisted rule syntax and arbitrary
// operator-authored regex behavior remain unchanged.
func importedSuffixRegex(m matcher) ([]string, bool) {
	if m.suffixes == nil {
		return nil, false
	}
	return m.suffixes, true
}

func parseImportedSuffixRegex(pattern string) ([]string, bool) {
	const prefix = `(?i)(?:^|\.)(?:`
	const suffix = `)$`
	if !strings.HasPrefix(pattern, prefix) || !strings.HasSuffix(pattern, suffix) {
		return nil, false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(pattern, prefix), suffix)
	if body == "" {
		return nil, false
	}
	atoms := strings.Split(body, "|")
	hosts := make([]string, 0, len(atoms))
	for _, atom := range atoms {
		var host strings.Builder
		host.Grow(len(atom))
		for pos := 0; pos < len(atom); pos++ {
			c := atom[pos]
			switch {
			case c == '\\' && pos+1 < len(atom) && atom[pos+1] == '.':
				host.WriteByte('.')
				pos++
			case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-':
				host.WriteByte(c)
			default:
				return nil, false
			}
		}
		value := host.String()
		labels := strings.Split(value, ".")
		if len(labels) < 2 {
			return nil, false
		}
		for _, label := range labels {
			if !isLiteralDNSLabel(label) {
				return nil, false
			}
		}
		hosts = append(hosts, value)
	}
	return hosts, true
}
