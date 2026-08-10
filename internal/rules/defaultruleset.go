package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// maskedKey is one parsed, normalized rules/default entry key: an
// address/mask pair generalizing a plain CIDR prefix to also allow a
// sparse (non-contiguous) bitmask — e.g. matching two fixed bytes out of
// a /64 handed out per network segment, where the bits identifying the
// client aren't the leading ones. addr and mask are both family-width (4
// or 16 bytes); addr has already had any bits outside mask cleared.
type maskedKey struct {
	is4  bool
	addr []byte
	mask []byte
}

// parseMaskedKey parses one rules/default JSON key: an address, "/", then
// either a decimal prefix length or a literal mask in
// the address family's own notation (dotted-quad for v4, colon-hex for
// v6). Address bits set outside the mask are cleared, not rejected — the
// long-standing convention for an ordinary prefix's host bits extends
// unchanged to a sparse mask's don't-care bits, so a config copied from a
// firewall or routing table loads as-is.
func parseMaskedKey(s string) (maskedKey, error) {
	addrPart, maskPart, ok := strings.Cut(s, "/")
	if !ok {
		return maskedKey{}, fmt.Errorf("missing \"/\"")
	}
	addr, err := netip.ParseAddr(addrPart)
	if err != nil {
		return maskedKey{}, fmt.Errorf("invalid address %q: %w", addrPart, err)
	}
	width := 16
	if addr.Is4() {
		width = 4
	}

	var mask []byte
	if isDecimal(maskPart) {
		n, convErr := strconv.Atoi(maskPart)
		if convErr != nil || n < 0 || n > width*8 {
			return maskedKey{}, fmt.Errorf("invalid prefix length %q", maskPart)
		}
		mask = prefixMask(n, width)
	} else {
		maskAddr, maskErr := netip.ParseAddr(maskPart)
		if maskErr != nil {
			return maskedKey{}, fmt.Errorf("invalid mask %q: %w", maskPart, maskErr)
		}
		if maskAddr.Is4() != addr.Is4() {
			return maskedKey{}, fmt.Errorf("mask %q family does not match address %q", maskPart, addrPart)
		}
		mask = maskAddr.AsSlice()
	}

	addrBytes := addr.AsSlice()
	cleared := make([]byte, width)
	for i := range cleared {
		cleared[i] = addrBytes[i] & mask[i]
	}
	return maskedKey{is4: addr.Is4(), addr: cleared, mask: mask}, nil
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func prefixMask(n, width int) []byte {
	m := make([]byte, width)
	for i := range n {
		m[i/8] |= 1 << uint(7-i%8)
	}
	return m
}

// contiguousPrefixLen reports whether mask's set bits form a contiguous
// run from the most significant bit — i.e. it's equivalent to an
// ordinary /N prefix — and if so, N. A 0 bit before a 1 bit (reading MSB
// to LSB) makes it sparse, not a prefix.
func contiguousPrefixLen(mask []byte) (int, bool) {
	n := 0
	i := 0
	for ; i < len(mask) && mask[i] == 0xff; i++ {
		n += 8
	}
	if i < len(mask) {
		b := mask[i]
		lead := 0
		for bit := 7; bit >= 0; bit-- {
			if b&(1<<uint(bit)) == 0 {
				break
			}
			lead++
		}
		want := byte(0xFF) << uint(8-lead) // e.g. lead=4 -> 0xf0; lead=0 -> shifted fully out -> 0
		if b != want {
			return 0, false
		}
		n += lead
		i++
	}
	for ; i < len(mask); i++ {
		if mask[i] != 0 {
			return 0, false
		}
	}
	return n, true
}

// canonical renders k in its stored/echoed form: "<addr>/<N>" when
// the mask is an ordinary prefix (so "/255.0.0.0" and "/8" are the same
// entry, never two competing ones), else "<addr>/<mask>" in the family's
// own notation.
func (k maskedKey) canonical() string {
	addr, _ := netip.AddrFromSlice(k.addr)
	if n, ok := contiguousPrefixLen(k.mask); ok {
		return addr.String() + "/" + strconv.Itoa(n)
	}
	maskAddr, _ := netip.AddrFromSlice(k.mask)
	return addr.String() + "/" + maskAddr.String()
}

// contains reports whether ab — a raw address's bytes, same family/width
// as k — matches k's address/mask pair.
func (k maskedKey) contains(ab []byte) bool {
	for i := range ab {
		if ab[i]&k.mask[i] != k.addr[i] {
			return false
		}
	}
	return true
}

// rawEntry is one still-unparsed rules/default JSON member, in source
// order.
type rawEntry struct {
	key string
	raw json.RawMessage
}

// decodeOrderedEntries walks data's top-level JSON object preserving
// source order — a plain map[string]RuleFile decode loses it, and order
// is exactly what decides which of two entries that NORMALIZE to the
// same key wins: the second entry replaces the first.
func decodeOrderedEntries(data []byte) ([]rawEntry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("expected a JSON object")
	}
	var entries []rawEntry
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("expected a string key")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		entries = append(entries, rawEntry{key: key, raw: raw})
	}
	if _, err := dec.Token(); err != nil { // consume '}'
		return nil, err
	}
	return entries, nil
}

// parsedEntry is one rules/default entry after key parsing/normalization
// but before http[]/egress[]/auth compiling — the shape both hot-reload
// uuid-minting (engine.go) and CompileDefaultRuleset work with.
type parsedEntry struct {
	key  maskedKey
	rule RuleFile
}

// parseDefaultRuleset parses data (the rules/default wire format),
// normalizing every key and, per that normalized identity, keeping only
// the LAST entry —
// two keys that normalize to the same address/mask (e.g. "/255.0.0.0"
// and "/8" for the same address) are one entry, not two competing ones.
// Each value decodes with the same strict (unknown-field-rejecting)
// rules as a per-IP RuleFile.
func parseDefaultRuleset(data []byte) ([]parsedEntry, error) {
	raw, err := decodeOrderedEntries(data)
	if err != nil {
		return nil, fmt.Errorf("rules/default: %w", err)
	}

	var entries []parsedEntry
	index := map[string]int{} // canonical key -> position in entries
	for _, re := range raw {
		key, err := parseMaskedKey(re.key)
		if err != nil {
			return nil, fmt.Errorf("rules/default[%q]: %w", re.key, err)
		}

		var rf RuleFile
		dec := json.NewDecoder(bytes.NewReader(re.raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rf); err != nil {
			return nil, fmt.Errorf("rules/default[%q]: %w", re.key, err)
		}

		canon := key.canonical()
		if i, ok := index[canon]; ok {
			entries[i] = parsedEntry{key: key, rule: rf}
			continue
		}
		index[canon] = len(entries)
		entries = append(entries, parsedEntry{key: key, rule: rf})
	}
	return entries, nil
}

// marshalCanonical renders entries back to the rules/default wire format,
// keyed by each entry's canonical form — this is what PUT persists, so a
// subsequent GET echoes exactly what an entry became, not what an
// operator happened to type.
func marshalCanonical(entries []parsedEntry) ([]byte, error) {
	out := make(map[string]RuleFile, len(entries))
	for _, pe := range entries {
		out[pe.key.canonical()] = pe.rule
	}
	return json.Marshal(out)
}

// compiledBucket is one compiled rules/default entry.
type compiledBucket struct {
	key   maskedKey
	label string // canonical form, e.g. "10.0.0.0/8" or "10.0.0.0/255.0.255.0"
	rules *RuleSet
}

// DefaultRuleset is a compiled rules/default table: every client without
// a per-IP override resolves against it. v4 and v6
// entries are kept separate (an entry never matches the other family)
// and each list is sorted by mask value, descending — a big-endian
// integer comparison over the family's width — so Lookup's first match
// is always the highest-ranked one. This single comparison subsumes
// longest-prefix-match (an ordinary prefix's mask is just the special
// case of a contiguous run of 1s), so a sparse mask and a prefix
// interleave in one order with no special-casing.
type DefaultRuleset struct {
	v4 []compiledBucket
	v6 []compiledBucket
}

// CompileDefaultRuleset parses, normalizes, validates, and compiles raw
// JSON bytes — the rules/default wire format — into a ready-to-use
// DefaultRuleset, plus the canonical form to persist: normalized keys,
// semantic duplicates collapsed to whichever entry appeared last. A PUT
// stores exactly this, so a subsequent GET echoes back what an entry
// became, not what an operator happened to type.
//
// Every entry's http[]/egress[]/auth compiles exactly like a per-IP
// RuleFile does (Compile/CompileEgress/CompileAuth, unchanged). Only
// entries whose mask is an ordinary prefix (contiguous from the MSB)
// participate in the coverage obligation: the v4 ones together, and the
// v6 ones together, must cover their entire address space with no gaps.
// A sparse mask is a pure override layered on top of that topology and
// isn't counted toward it — carving a service field out of an address
// block doesn't change what the block itself must cover.
func CompileDefaultRuleset(data []byte) (*DefaultRuleset, []byte, error) {
	entries, err := parseDefaultRuleset(data)
	if err != nil {
		return nil, nil, err
	}
	d, err := compileParsedEntries(entries)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := marshalCanonical(entries)
	if err != nil {
		return nil, nil, fmt.Errorf("rules/default: marshal canonical form: %w", err)
	}
	return d, canonical, nil
}

func compileParsedEntries(entries []parsedEntry) (*DefaultRuleset, error) {
	var v4, v6 []compiledBucket
	var v4Prefixes, v6Prefixes []netip.Prefix // only the contiguous (plain-prefix) subset — the coverage obligation's scope

	for _, pe := range entries {
		label := pe.key.canonical()

		auth, err := CompileAuth(pe.rule.Auth)
		if err != nil {
			return nil, fmt.Errorf("rules/default[%q]: invalid auth config: %w", label, err)
		}
		compiled, err := Compile(pe.rule)
		if err != nil {
			return nil, fmt.Errorf("rules/default[%q]: invalid rules: %w", label, err)
		}
		var egress []CompiledEgress
		if pe.rule.Egress != nil {
			if egress, err = CompileEgress(pe.rule.Egress); err != nil {
				return nil, fmt.Errorf("rules/default[%q]: invalid egress rules: %w", label, err)
			}
		}

		bucket := compiledBucket{
			key:   pe.key,
			label: label,
			rules: &RuleSet{rules: compiled, egress: egress, uuid: pe.rule.UUID, auth: auth},
		}
		if pe.key.is4 {
			v4 = append(v4, bucket)
		} else {
			v6 = append(v6, bucket)
		}

		if n, ok := contiguousPrefixLen(pe.key.mask); ok {
			addr, _ := netip.AddrFromSlice(pe.key.addr)
			prefix := netip.PrefixFrom(addr, n)
			if pe.key.is4 {
				v4Prefixes = append(v4Prefixes, prefix)
			} else {
				v6Prefixes = append(v6Prefixes, prefix)
			}
		}
	}

	if err := checkCoverage(v4Prefixes, 32); err != nil {
		return nil, fmt.Errorf("rules/default: v4 %w", err)
	}
	if err := checkCoverage(v6Prefixes, 128); err != nil {
		return nil, fmt.Errorf("rules/default: v6 %w", err)
	}

	sortByMaskDescending(v4)
	sortByMaskDescending(v6)
	return &DefaultRuleset{v4: v4, v6: v6}, nil
}

// sortByMaskDescending orders buckets by mask value, descending — one
// bytes.Compare per pair, since a family-fixed-width mask read MSB-first
// is exactly a big-endian integer.
func sortByMaskDescending(buckets []compiledBucket) {
	sort.Slice(buckets, func(i, j int) bool {
		return bytes.Compare(buckets[i].key.mask, buckets[j].key.mask) > 0
	})
}

// denyFirstEgress is deliberately both v4 and v6 on EVERY bucket, not
// just the bucket's own source-address family — a client's egress[]
// governs which DESTINATION addresses it may reach, an entirely
// different axis from which CIDR bucket its own SOURCE address fell
// into. The standard SSRF-guard ranges: loopback, RFC1918/ULA private
// ranges, and link-local (including the 169.254.169.254 cloud metadata
// address) denied; everything else allowed.
var denyFirstEgress = []EgressRule{
	{CIDR: "127.0.0.0/8", Action: "deny"},
	{CIDR: "::1/128", Action: "deny"},
	{CIDR: "10.0.0.0/8", Action: "deny"},
	{CIDR: "172.16.0.0/12", Action: "deny"},
	{CIDR: "192.168.0.0/16", Action: "deny"},
	{CIDR: "fc00::/7", Action: "deny"},
	{CIDR: "169.254.0.0/16", Action: "deny"},
	{CIDR: "fe80::/10", Action: "deny"},
	{CIDR: "0.0.0.0/0", Action: "allow"},
	{CIDR: "::/0", Action: "allow"},
}

// BuiltinDefaultRuleset is the bootstrap rules/default content
// RuleStore.EnsureDefault seeds a fresh cluster with, pre-marshaled to
// the wire format directly: two buckets covering the full v4 and v6
// address space, each with an empty http[] (no rule ever matches, so
// every connection still falls through to "no match -> 511" —
// bit-for-bit the same fail-closed behavior an unconfigured deployment
// had before this table existed at all) but a deny-first egress[] — a
// containment tool must not ship an SSRF-open default — loopback/
// private/link-local/metadata denied, public allowed — so a per-IP
// override that only wants to customize http[] still has something safe
// to inherit for egress by omitting the key.
var BuiltinDefaultRuleset = mustMarshalBuiltinDefault()

func mustMarshalBuiltinDefault() []byte {
	raw := map[string]RuleFile{
		"0.0.0.0/0": {HTTP: []Rule{}, Egress: denyFirstEgress},
		"::/0":      {HTTP: []Rule{}, Egress: denyFirstEgress},
	}
	data, err := json.Marshal(raw)
	if err != nil {
		panic(fmt.Errorf("rules: builtin default ruleset: %w", err))
	}
	return data
}

// Lookup returns the RuleSet for addr's highest-ranked matching entry:
// the first match, scanning each family's list in mask-descending order.
// Always succeeds for an address in a family whose plain-prefix
// entries pass CompileDefaultRuleset's coverage check; the bool return
// exists for the case a sparse mask or coverage gap leaves addr
// unmatched, or for a DefaultRuleset built some other way (e.g. tests).
func (d *DefaultRuleset) Lookup(addr netip.Addr) (*RuleSet, bool) {
	buckets := d.v6
	if addr.Is4() {
		buckets = d.v4
	}
	ab := addr.AsSlice()
	for _, b := range buckets {
		if b.key.contains(ab) {
			return b.rules, true
		}
	}
	return nil, false
}

// DefaultBucket is one compiled rules/default entry, paired with its
// canonical key — exposed for control's PUT-time outcall probe, which
// needs a label per bucket but not Lookup's match order.
type DefaultBucket struct {
	Key   string
	Rules *RuleSet
}

// Buckets returns every compiled bucket, in no particular order.
func (d *DefaultRuleset) Buckets() []DefaultBucket {
	out := make([]DefaultBucket, 0, len(d.v4)+len(d.v6))
	for _, b := range d.v4 {
		out = append(out, DefaultBucket{Key: b.label, Rules: b.rules})
	}
	for _, b := range d.v6 {
		out = append(out, DefaultBucket{Key: b.label, Rules: b.rules})
	}
	return out
}

// checkCoverage requires prefixes to exactly cover [0, 2^bits) with no
// gaps. On failure it reports one concrete gap (the first found scanning
// low to high) rather than a bare boolean — this is an operator-facing
// save-time rejection, so naming the hole matters.
func checkCoverage(prefixes []netip.Prefix, bits int) error {
	if len(prefixes) == 0 {
		return fmt.Errorf("coverage gap: no entries cover the %d-bit address space", bits)
	}

	type span struct{ start, end *big.Int } // end is inclusive
	spans := make([]span, len(prefixes))
	for i, p := range prefixes {
		start, end := prefixRange(p)
		spans[i] = span{start, end}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start.Cmp(spans[j].start) < 0 })

	one := big.NewInt(1)
	covered := new(big.Int).Neg(one) // "covered up through -1" = nothing yet
	for _, s := range spans {
		gapStart := new(big.Int).Add(covered, one)
		if s.start.Cmp(gapStart) > 0 {
			gapEnd := new(big.Int).Sub(s.start, one)
			return fmt.Errorf("coverage gap: %s-%s not covered", formatAddr(gapStart, bits), formatAddr(gapEnd, bits))
		}
		if s.end.Cmp(covered) > 0 {
			covered = s.end
		}
	}

	maxAddr := new(big.Int).Lsh(one, uint(bits))
	maxAddr.Sub(maxAddr, one)
	if covered.Cmp(maxAddr) < 0 {
		gapStart := new(big.Int).Add(covered, one)
		return fmt.Errorf("coverage gap: %s-%s not covered", formatAddr(gapStart, bits), formatAddr(maxAddr, bits))
	}
	return nil
}

// prefixRange converts p to its inclusive [start, end] address range, as
// big.Ints over the raw address bytes — uniform code for both 32-bit and
// 128-bit spaces, since this only runs at save/hot-reload time, not
// per-request.
func prefixRange(p netip.Prefix) (start, end *big.Int) {
	start = new(big.Int).SetBytes(p.Addr().AsSlice())
	hostBits := p.Addr().BitLen() - p.Bits()
	size := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	end = new(big.Int).Add(start, size)
	end.Sub(end, big.NewInt(1))
	return start, end
}

// formatAddr renders a big.Int address offset back as a netip.Addr string
// for an error message, e.g. "10.0.0.0" instead of a raw integer.
func formatAddr(n *big.Int, bits int) string {
	buf := make([]byte, bits/8)
	b := n.Bytes()
	copy(buf[len(buf)-len(b):], b)
	addr, ok := netip.AddrFromSlice(buf)
	if !ok {
		return n.String()
	}
	return addr.String()
}
