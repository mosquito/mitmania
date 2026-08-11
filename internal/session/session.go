// Package session defines the Session type and Acceptor interface: the
// only layer aware of transport, filling in what's known about a
// connection at accept time before handing it to the transport-agnostic
// dispatcher.
package session

import (
	"net"
	"net/netip"
)

// Transport identifies which listener mode accepted a Session.
type Transport int

const (
	// TransportExplicit is the explicit CONNECT/absolute-form proxy path —
	// a client deliberately configured to use this proxy, as opposed to
	// transparent interception.
	TransportExplicit Transport = iota
	// TransportTProxy and TransportRedirect are the two transparent
	// interception modes (TProxyAcceptor, RedirectAcceptor) — Linux-only,
	// see redirect_acceptor_linux.go/tproxy_acceptor_linux.go.
	TransportTProxy
	TransportRedirect
)

func (t Transport) String() string {
	switch t {
	case TransportExplicit:
		return "explicit"
	case TransportTProxy:
		return "tproxy"
	case TransportRedirect:
		return "redirect"
	default:
		return "unknown"
	}
}

// Session is a newly-accepted connection with whatever client/destination
// identity the Acceptor could determine at accept time. For the
// explicit proxy, Dst is unknown until the handler parses the
// CONNECT/absolute-URI request, so it's left zero-value here; the two
// transparent Acceptors (RedirectAcceptor, TProxyAcceptor) fill it in
// directly, since recovering the true destination is the whole point of
// their accept-time kernel interaction.
type Session struct {
	Client    netip.AddrPort
	Dst       netip.AddrPort
	Transport Transport
	Conn      net.Conn

	// Acceptor names which listener accepted this connection (e.g.
	// "http_proxy", "https_proxy") — set by the Acceptor at construction
	// time. Multiple explicit-proxy listeners share TransportExplicit, so
	// this is what actually distinguishes them in the access log.
	Acceptor string
}

// loopback is the default client identity for connections with no
// meaningful source IP (a unix-socket explicit-proxy connection) —
// per-client rule lookup is keyed by source IP, which doesn't exist in
// that case; the explicit proxy's unix:// mode is inherently local.
var loopback = netip.MustParseAddr("127.0.0.1")

// ClientKey returns the identity used for per-client rule file lookup
// (rules/{sha1(clientIP)}.json).
func (s Session) ClientKey() netip.Addr {
	if s.Client.IsValid() {
		return s.Client.Addr()
	}
	return loopback
}

// tcpAddrPort converts a *net.TCPAddr to netip.AddrPort with its address
// unmapped — (*net.TCPAddr).AddrPort() does NOT do this itself, so a v4
// connection accepted on a dual-stack socket comes back as a 4-in-6
// address (e.g. "::ffff:127.0.0.2") whose Is4() is false, breaking any
// downstream v4-specific matching (egress CIDRs, host comparisons) even
// though the connection is genuinely IPv4. Confirmed live against a real
// TPROXY-intercepted connection during development — every Acceptor
// should go through this rather than calling AddrPort() directly.
func tcpAddrPort(a *net.TCPAddr) netip.AddrPort {
	addr, _ := netip.AddrFromSlice(a.IP)
	return netip.AddrPortFrom(addr.Unmap(), uint16(a.Port))
}
