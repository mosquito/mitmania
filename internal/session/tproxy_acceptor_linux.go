//go:build linux

package session

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// ListenTProxy binds a TCP listener with IP_TRANSPARENT (v4) and/or
// IPV6_TRANSPARENT (v6) set — the prerequisite for a TPROXY-routed
// connection (whose real destination is some OTHER address than this
// listener's own bind address) to be acceptable at all; without it the
// kernel refuses a non-locally-addressed SYN outright. Must be set via a
// Control callback (net.ListenConfig calls it after socket() but before
// bind(), the only point that matters — it cannot be applied after the
// fact).
//
// Whether the bound socket ends up AF_INET or AF_INET6 (including a
// dual-stack "[::]:port" that also accepts v4-mapped connections)
// depends on the resolved address in ways not reliably recoverable from
// the network/address strings Control receives, so this sets whichever
// of the two options apply and tolerates ENOPROTOOPT/EINVAL from the one
// that doesn't — failing only if neither could be set.
func ListenTProxy(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var v4Err, v6Err error
			ctrlErr := c.Control(func(fd uintptr) {
				v4Err = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				v6Err = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
			})
			if ctrlErr != nil {
				return ctrlErr
			}
			if v4Err != nil && v6Err != nil {
				return fmt.Errorf("set IP_TRANSPARENT: %w; set IPV6_TRANSPARENT: %w", v4Err, v6Err)
			}
			return nil
		},
	}
	return lc.Listen(context.Background(), network, address)
}

// TProxyAcceptor accepts connections on a TPROXY listener bound via
// ListenTProxy. Unlike RedirectAcceptor, no getsockopt is needed to
// recover the destination: IP_TRANSPARENT/IPV6_TRANSPARENT make the
// accepted connection's own LocalAddr() the client's real destination
// directly, not this listener's bind address.
type TProxyAcceptor struct {
	ln   net.Listener
	name string
}

// NewTProxyAcceptor wraps a listener already bound via ListenTProxy. An
// ordinary net.Listen-backed listener works too but will simply report
// this listener's own bind address as every Session's Dst, since without
// the transparent socket options the kernel never delivers a
// non-locally-addressed connection here in the first place.
func NewTProxyAcceptor(ln net.Listener, name string) (*TProxyAcceptor, error) {
	return &TProxyAcceptor{ln: ln, name: name}, nil
}

func (a *TProxyAcceptor) Accept() (Session, error) {
	conn, err := a.ln.Accept()
	if err != nil {
		return Session{}, err
	}

	tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		conn.Close()
		return Session{}, fmt.Errorf("tproxy: LocalAddr: not a TCP address (%T)", conn.LocalAddr())
	}
	dst := tcpAddrPort(tcpAddr)

	var client netip.AddrPort
	if remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		client = tcpAddrPort(remoteAddr)
	}

	return Session{Client: client, Dst: dst, Transport: TransportTProxy, Conn: conn, Acceptor: a.name}, nil
}

func (a *TProxyAcceptor) Close() error {
	return a.ln.Close()
}
