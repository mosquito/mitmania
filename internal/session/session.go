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
	// transparent interception. The only Transport implemented this pass.
	TransportExplicit Transport = iota
	// TransportTProxy and TransportRedirect name the two transparent
	// interception modes reserved for a future extension point — no
	// Acceptor implements them yet.
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
// CONNECT/absolute-URI request, so it's left zero-value here.
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
