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
// hit EOF, half-closing each side as its direction finishes so the other
// isn't cut short. m may be nil (BytesStreamed is nil-safe).
func relay(ctx context.Context, client, upstream net.Conn, m *telemetry.Metrics) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n := pooledCopy(client, upstream)
		m.BytesStreamed(ctx, "down", n)
		closeWrite(client)
	}()
	go func() {
		defer wg.Done()
		n := pooledCopy(upstream, client)
		m.BytesStreamed(ctx, "up", n)
		closeWrite(upstream)
	}()
	wg.Wait()
}

// pooledCopy copies src into dst. io.CopyBuffer silently ignores a
// supplied buffer whenever either side implements ReadFrom/WriteTo, so the
// strategy has to be picked before touching the pool, not after: a pair
// that's splice-capable on both sides (a raw, unwrapped TCPConn tunnel)
// goes through plain io.Copy to keep the kernel's own fast path; otherwise
// a pooled buffer is used, hiding whichever side has ReadFrom/WriteTo so
// io.CopyBuffer can't route around it.
func pooledCopy(dst, src net.Conn) int64 {
	if isSpliceCapable(dst) && isSpliceCapable(src) {
		n, _ := io.Copy(dst, src)
		return n
	}
	if isSpliceCapable(dst) {
		dst = hideFastPath{Conn: dst}
	}
	if isSpliceCapable(src) {
		src = hideFastPath{Conn: src}
	}
	buf := getCopyBuf()
	defer putCopyBuf(buf)
	n, _ := io.CopyBuffer(dst, src, *buf)
	return n
}

// isSpliceCapable reports whether c is a raw connection offering its own
// zero-copy ReadFrom/WriteTo (true for *net.TCPConn as of Go 1.26) rather
// than a wrapper like prependConn/replayConn that only embeds net.Conn as
// an interface.
func isSpliceCapable(c net.Conn) bool {
	_, hasReadFrom := c.(io.ReaderFrom)
	_, hasWriteTo := c.(io.WriterTo)
	return hasReadFrom || hasWriteTo
}

// hideFastPath hides a net.Conn's ReadFrom/WriteTo from io.Copy by
// re-embedding it as the net.Conn interface — the same trick prependConn
// and replayConn already do unintentionally.
type hideFastPath struct{ net.Conn }

func closeWrite(c net.Conn) {
	if cw, ok := c.(halfCloser); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}
