package proxy

import (
	"context"
	"io"
	"net"
	"sync"

	"mitmania/internal/telemetry"
)

// halfCloser is implemented by net.Conn types that support closing just
// the write side (net.TCPConn, *tls.Conn) — used so relay doesn't cut off
// a still-draining direction when the other one finishes.
type halfCloser interface {
	CloseWrite() error
}

// relay splices client and upstream bidirectionally until both directions
// have hit EOF, half-closing (rather than fully closing) each side as its
// copy direction finishes so the other, still-in-flight direction isn't
// cut short. Used for the CONNECT tunnel, the absolute-form plain-HTTP
// path, and WebSocket passthrough. m may be nil (BytesStreamed is
// nil-safe) — direction is "down" for upstream-to-client and "up" for
// client-to-upstream, matching every existing caller's argument order.
func relay(ctx context.Context, client, upstream net.Conn, m *telemetry.Metrics) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := getCopyBuf()
		defer putCopyBuf(buf)
		n, _ := io.CopyBuffer(client, upstream, *buf)
		m.BytesStreamed(ctx, "down", n)
		closeWrite(client)
	}()
	go func() {
		defer wg.Done()
		buf := getCopyBuf()
		defer putCopyBuf(buf)
		n, _ := io.CopyBuffer(upstream, client, *buf)
		m.BytesStreamed(ctx, "up", n)
		closeWrite(upstream)
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
