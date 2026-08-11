package session

import (
	"net"
	"net/netip"
)

// HTTPProxyAcceptor accepts connections on the explicit proxy listener
// (tcp or unix) and fills in Session.Client from the peer address when
// one exists.
type HTTPProxyAcceptor struct {
	ln   net.Listener
	name string
}

// NewHTTPProxyAcceptor wraps an already-bound listener. name identifies
// this listener in Session.Acceptor (e.g. "http_proxy", "https_proxy") —
// distinct plain and TLS-terminating explicit-proxy listeners both use
// TransportExplicit, so name is what the access log actually keys on.
func NewHTTPProxyAcceptor(ln net.Listener, name string) *HTTPProxyAcceptor {
	return &HTTPProxyAcceptor{ln: ln, name: name}
}

func (a *HTTPProxyAcceptor) Accept() (Session, error) {
	conn, err := a.ln.Accept()
	if err != nil {
		return Session{}, err
	}

	var client netip.AddrPort
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		client = tcpAddrPort(tcpAddr)
	}
	// unix socket RemoteAddr carries no usable peer identity; Client stays
	// the zero value and Session.ClientKey() falls back to loopback.

	return Session{Client: client, Transport: TransportExplicit, Conn: conn, Acceptor: a.name}, nil
}

func (a *HTTPProxyAcceptor) Close() error {
	return a.ln.Close()
}
