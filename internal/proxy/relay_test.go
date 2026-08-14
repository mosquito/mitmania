package proxy

import (
	"io"
	"net"
	"testing"
)

// tcpLoopbackPair returns two ends of a real TCP connection, needed since
// isSpliceCapable/pooledCopy depend on *net.TCPConn's concrete type.
func tcpLoopbackPair(t *testing.T) (a, b net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	acceptedCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			acceptedCh <- nil
			return
		}
		acceptedCh <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	server := <-acceptedCh
	if server == nil {
		t.Fatalf("Accept failed")
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// TestIsSpliceCapable_RawTCPConnVsWrapped checks a raw TCPConn reports
// splice-capable while prependConn/replayConn wrappers don't.
func TestIsSpliceCapable_RawTCPConnVsWrapped(t *testing.T) {
	a, b := tcpLoopbackPair(t)

	if !isSpliceCapable(a) {
		t.Errorf("isSpliceCapable(raw *net.TCPConn) = false, want true")
	}

	wrapped := newPrependConn(a)
	if isSpliceCapable(wrapped) {
		t.Errorf("isSpliceCapable(prependConn) = true, want false")
	}

	replayed := Replay(b, []byte("prefix"))
	if isSpliceCapable(replayed) {
		t.Errorf("isSpliceCapable(replayConn) = true, want false")
	}
}

// TestHideFastPath_HidesReadFromWriteTo checks hideFastPath actually hides
// ReadFrom/WriteTo from io.CopyBuffer's type assertions.
func TestHideFastPath_HidesReadFromWriteTo(t *testing.T) {
	a, _ := tcpLoopbackPair(t)

	if _, ok := any(a).(io.ReaderFrom); !ok {
		t.Fatalf("test invariant broken: raw *net.TCPConn doesn't implement io.ReaderFrom on this Go version")
	}

	hidden := hideFastPath{Conn: a}
	if _, ok := any(hidden).(io.ReaderFrom); ok {
		t.Errorf("hideFastPath still exposes io.ReaderFrom")
	}
	if _, ok := any(hidden).(io.WriterTo); ok {
		t.Errorf("hideFastPath still exposes io.WriterTo")
	}
}

// TestPooledCopy_CleanPairByteCorrect and TestPooledCopy_WrappedPairByteCorrect
// check both of pooledCopy's branches still copy bytes correctly.

func TestPooledCopy_CleanPairByteCorrect(t *testing.T) {
	src, srcPeer := tcpLoopbackPair(t)
	dst, dstPeer := tcpLoopbackPair(t)

	payload := []byte("clean splice-eligible pair, byte-perfect or bust")
	done := make(chan int64, 1)
	go func() { done <- pooledCopy(dst, src) }()

	if _, err := srcPeer.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	srcPeer.(*net.TCPConn).CloseWrite()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(dstPeer, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
	dst.Close()
	if n := <-done; n != int64(len(payload)) {
		t.Fatalf("pooledCopy returned n=%d, want %d", n, len(payload))
	}
}

func TestPooledCopy_WrappedPairByteCorrect(t *testing.T) {
	src, srcPeer := tcpLoopbackPair(t)
	dst, dstPeer := tcpLoopbackPair(t)

	wrappedSrc := newPrependConn(src)
	wrappedSrc.prepend([]byte("PRE-"))

	payload := []byte("wrapped pair routed through the pooled buffer")
	done := make(chan int64, 1)
	go func() { done <- pooledCopy(dst, wrappedSrc) }()

	if _, err := srcPeer.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	srcPeer.(*net.TCPConn).CloseWrite()

	want := append([]byte("PRE-"), payload...)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(dstPeer, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	dst.Close()
	if n := <-done; n != int64(len(want)) {
		t.Fatalf("pooledCopy returned n=%d, want %d", n, len(want))
	}
}
