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

// pooledCopy copies src into dst, choosing the copy strategy before
// touching the buffer pool at all — checking after the fact is too late,
// since io.CopyBuffer silently ignores a supplied buffer whenever either
// side offers a fast-path ReadFrom/WriteTo, and Go's own *net.TCPConn
// fallback for that path (reached whenever the OTHER side ISN'T itself a
// recognized zero-copy-eligible type — see net's spliceFrom/spliceTo)
// performs its own separate, unpooled io.Copy internally regardless:
//
//   - Both sides splice-capable (isSpliceCapable on each side of a raw,
//     unwrapped tunnel — both directions of a genuine mitm:false CONNECT
//     tunnel with nothing buffered ahead of it, the common case): plain
//     io.Copy, no pool touched at all, letting the kernel's own splice/
//     sendfile path run exactly as it would without this pool existing.
//   - Otherwise (the common case for anything peeked/prepended —
//     mitm:true's TLS termination, transparent listeners, any CONNECT
//     tunnel with pipelined bytes ahead of it): a pooled buffer is
//     acquired, and whichever side DOES offer a fast-path method has it
//     hidden via hideFastPath first, so io.CopyBuffer can't bypass the
//     pooled buffer by dispatching to that method anyway — without the
//     hide, a lone raw TCPConn on one side would still win the outer
//     dispatch, our buffer would sit acquired-but-unused for the whole
//     copy, and Go's own genericReadFrom/genericWriteTo fallback would
//     still allocate its own separate, unpooled buffer underneath.
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

// isSpliceCapable reports whether c is a raw, unwrapped connection that
// offers its own zero-copy ReadFrom/WriteTo — true for *net.TCPConn (as of
// Go 1.26, both), false for prependConn/replayConn and any other type that
// only embeds net.Conn as an interface, since interface embedding promotes
// just the interface's own declared method set, never a concrete value's
// extra methods.
func isSpliceCapable(c net.Conn) bool {
	_, hasReadFrom := c.(io.ReaderFrom)
	_, hasWriteTo := c.(io.WriterTo)
	return hasReadFrom || hasWriteTo
}

// hideFastPath wraps a net.Conn so io.Copy/io.CopyBuffer can no longer see
// its concrete type's ReadFrom/WriteTo — embedding net.Conn as an
// interface, rather than the concrete type, only promotes the interface's
// own method set, the same (here deliberate) trick prependConn and
// replayConn already rely on for their own wrapping.
type hideFastPath struct{ net.Conn }

func closeWrite(c net.Conn) {
	if cw, ok := c.(halfCloser); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}
