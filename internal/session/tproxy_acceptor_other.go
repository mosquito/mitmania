//go:build !linux

package session

import (
	"fmt"
	"net"
	"runtime"
)

// ListenTProxy exists on every platform so cross-compiled builds keep
// working, but IP_TRANSPARENT is a Linux-only socket option with no
// portable equivalent — this build cannot bind a transparent listener.
func ListenTProxy(network, address string) (net.Listener, error) {
	return nil, fmt.Errorf("tproxy: not supported on GOOS=%s (Linux-only)", runtime.GOOS)
}

// TProxyAcceptor exists on every platform so cross-compiled builds keep
// working; see ListenTProxy.
type TProxyAcceptor struct{}

func NewTProxyAcceptor(ln net.Listener, name string) (*TProxyAcceptor, error) {
	return nil, fmt.Errorf("tproxy: not supported on GOOS=%s (Linux-only)", runtime.GOOS)
}

func (a *TProxyAcceptor) Accept() (Session, error) {
	return Session{}, fmt.Errorf("tproxy: not supported on GOOS=%s (Linux-only)", runtime.GOOS)
}

func (a *TProxyAcceptor) Close() error { return nil }
