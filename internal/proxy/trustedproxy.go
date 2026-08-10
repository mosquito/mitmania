package proxy

import (
	"net/http"
	"net/netip"
	"strings"
)

// isTrustedPeer reports whether addr falls within any of the configured
// --trusted-proxies prefixes.
func isTrustedPeer(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// recoverClientIP implements client-IP recovery behind a SNAT load
// balancer: if peer is a
// trusted proxy, the real client is the right-most X-Forwarded-For address
// that is not itself trusted (falling back to X-Real-IP, then peer
// verbatim); walking from the right and stopping at the first untrusted hop
// means a client cannot inject a fake identity by pre-seeding its own XFF —
// only headers written by trusted hops are believed. If peer is not
// trusted, XFF/X-Real-IP are ignored entirely and peer is returned as-is.
func recoverClientIP(peer netip.Addr, header http.Header, trusted []netip.Prefix) netip.Addr {
	if !isTrustedPeer(peer, trusted) {
		return peer
	}

	// Multiple X-Forwarded-For header lines are equivalent to one
	// comma-joined list (RFC 9110 §5.3) — join them in header order before
	// walking right to left, so the right-most hop overall (not just
	// within the last line) is considered first.
	hops := strings.Split(strings.Join(header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		addr, err := netip.ParseAddr(hop)
		if err != nil {
			continue
		}
		if !isTrustedPeer(addr, trusted) {
			return addr
		}
	}

	if xri := strings.TrimSpace(header.Get("X-Real-IP")); xri != "" {
		if addr, err := netip.ParseAddr(xri); err == nil {
			return addr
		}
	}

	return peer
}
