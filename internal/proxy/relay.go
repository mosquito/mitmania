package proxy

import (
	"io"
	"net"
	"sync"
)

// halfCloser is implemented by net.Conn types that support closing just
// the write side (net.TCPConn, *tls.Conn) — used so relay doesn't cut off
// a still-draining direction when the other one finishes.
type halfCloser interface {
	CloseWrite() error
}

// relay splices a and b bidirectionally until both directions have hit
// EOF, half-closing (rather than fully closing) each side as its copy
// direction finishes so the other, still-in-flight direction isn't cut
// short. Used for the CONNECT tunnel, the absolute-form plain-HTTP path,
// and (later) WebSocket passthrough.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		closeWrite(a)
	}()
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		closeWrite(b)
	}()
	wg.Wait()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(halfCloser); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}
