package rules

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// EgressRule is one entry in a client's egress[] list: permits or denies
// forwarding to a resolved destination address. Independent of the
// host-based http[] rule chain — it constrains the socket, not the L7
// conversation above it, so it applies equally to mitm and mitm:false
// connections.
type EgressRule struct {
	CIDR   string `json:"cidr"`
	Port   string `json:"port,omitempty"`
	Proto  string `json:"proto,omitempty"`
	Action string `json:"action"`
}

// portRange matches a destination port against an exact number, an
// inclusive "lo-hi" range, or "*"/omitted (always).
type portRange struct {
	always bool
	lo, hi uint16
}

func compilePortRange(s string) (portRange, error) {
	if s == "" || s == "*" {
		return portRange{always: true}, nil
	}
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		loN, err := parsePort(lo)
		if err != nil {
			return portRange{}, err
		}
		hiN, err := parsePort(hi)
		if err != nil {
			return portRange{}, err
		}
		if loN > hiN {
			return portRange{}, fmt.Errorf("invalid range %q: low > high", s)
		}
		return portRange{lo: loN, hi: hiN}, nil
	}
	n, err := parsePort(s)
	if err != nil {
		return portRange{}, err
	}
	return portRange{lo: n, hi: n}, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", s, err)
	}
	return uint16(n), nil
}

func (p portRange) match(port uint16) bool {
	return p.always || (port >= p.lo && port <= p.hi)
}

// CompiledEgress is one already-validated egress[] entry.
type CompiledEgress struct {
	prefix netip.Prefix
	port   portRange
	proto  matcher
	allow  bool
}

// CompileEgress validates and compiles a RuleFile's egress[] list: malformed
// CIDR, port, or an action other than "allow"/"deny" is a load-time
// rejection, exactly like the http[] chain's own validation.
//
// Entries are kept as a plain ordered slice, matched linearly in
// compileRule order (firstmatch across entries) — not a prefix trie: a
// per-client list is realistically a handful of entries, and this mirrors
// the http[] chain's own compiled-list-then-scan style rather than building
// routing-table machinery nothing here needs.
func CompileEgress(rules []EgressRule) ([]CompiledEgress, error) {
	compiled := make([]CompiledEgress, 0, len(rules))
	for i, r := range rules {
		ce, err := compileEgressRule(r)
		if err != nil {
			return nil, fmt.Errorf("egress %d: %w", i, err)
		}
		compiled = append(compiled, ce)
	}
	return compiled, nil
}

func compileEgressRule(r EgressRule) (CompiledEgress, error) {
	var ce CompiledEgress

	prefix, err := netip.ParsePrefix(r.CIDR)
	if err != nil {
		return ce, fmt.Errorf("cidr: %w", err)
	}
	ce.prefix = prefix

	if ce.port, err = compilePortRange(r.Port); err != nil {
		return ce, fmt.Errorf("port: %w", err)
	}
	if ce.proto, err = compileMatcher(r.Proto); err != nil {
		return ce, fmt.Errorf("proto: %w", err)
	}

	switch r.Action {
	case "allow":
		ce.allow = true
	case "deny":
		ce.allow = false
	default:
		return ce, fmt.Errorf("action: must be \"allow\" or \"deny\", got %q", r.Action)
	}
	return ce, nil
}
