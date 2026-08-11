package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// discardLogger and a real (in-memory) tracer let the redial unit tests
// below exercise h1RoundTripper's "if rt.log != nil"/"if rt.tracer != nil"
// branches too, instead of always taking the nil-safe no-op path.
func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestIsIdempotentMethod(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{http.MethodGet, true},
		{http.MethodHead, true},
		{http.MethodOptions, true},
		{http.MethodTrace, true},
		{http.MethodPost, false},
		{http.MethodPatch, false},
		// PUT and DELETE are idempotent per RFC 7231 §4.2.2, but this
		// codebase's isIdempotentMethod is deliberately narrower: it gates
		// "safe to blindly retry after a partially-written request", not
		// general HTTP idempotency, and a redial retry after a PUT/DELETE
		// might have partially applied server-side. Asserting the actual
		// (narrower) behavior here, not the RFC's classification.
		{http.MethodPut, false},
		{http.MethodDelete, false},
		{http.MethodConnect, false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			if got := isIdempotentMethod(tt.method); got != tt.want {
				t.Errorf("isIdempotentMethod(%q) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}

// TestIsUpgradeRequest covers isUpgradeRequest's full matrix, including the
// case its own end-to-end WebSocket tests never happen to exercise: an
// Upgrade header present but Connection either absent or not actually
// listing "Upgrade" as one of its (possibly comma-separated) tokens — a
// spec-noncompliant or unrelated-Connection-usage request that must NOT be
// treated as a protocol upgrade.
func TestIsUpgradeRequest(t *testing.T) {
	tests := []struct {
		name       string
		upgrade    string
		connection []string
		want       bool
	}{
		{"no headers at all", "", nil, false},
		{"upgrade without connection", "websocket", nil, false},
		{"connection present but doesn't list upgrade", "websocket", []string{"keep-alive"}, false},
		{"connection lists something else entirely", "websocket", []string{"close"}, false},
		{"exact match", "websocket", []string{"Upgrade"}, true},
		{"case-insensitive, extra whitespace", "websocket", []string{" upgrade "}, true},
		{"comma-separated token list", "websocket", []string{"keep-alive, Upgrade"}, true},
		{"multiple Connection header values", "websocket", []string{"keep-alive", "Upgrade"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
			if tt.upgrade != "" {
				req.Header.Set("Upgrade", tt.upgrade)
			}
			for _, v := range tt.connection {
				req.Header.Add("Connection", v)
			}
			if got := isUpgradeRequest(req); got != tt.want {
				t.Errorf("isUpgradeRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

// pipeOrigin spawns a goroutine that reads exactly one HTTP request off the
// server side of a net.Pipe, invokes respond with it once the request is
// fully parsed (so the client's req.Write is guaranteed to have completed
// synchronously, giving a deterministic "fully written" case — net.Pipe's
// Write blocks until Read consumes it), and returns the client-side conn.
// respond == nil closes the server side immediately without reading a
// response back, simulating an origin that accepted the write but never
// answered.
func pipeOrigin(t *testing.T, respond func(req *http.Request, w io.Writer)) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		br := bufio.NewReader(server)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if respond != nil {
			respond(req, server)
		}
	}()
	return client
}

func okResponder(body string) func(*http.Request, io.Writer) {
	return func(_ *http.Request, w io.Writer) {
		fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}
}

// TestH1RoundTripper_NothingWrittenRedialsAndSucceeds covers the
// "nothingWritten" retry-safety branch (roundtrip.go's RoundTrip,
// nothingWritten=true skips the isIdempotentMethod gate entirely): the very
// first write to rt's seeded connection fails outright (net.Pipe's Write on
// an already-closed peer returns io.ErrClosedPipe with zero bytes written),
// so the retry must be attempted regardless of method — here a POST, which
// isIdempotentMethod alone would never allow a retry for.
func TestH1RoundTripper_NothingWrittenRedialsAndSucceeds(t *testing.T) {
	deadClient, deadServer := net.Pipe()
	deadServer.Close() // peer already gone: the very first Write on deadClient fails with 0 bytes written

	redialCalls := 0
	redial := func(ctx context.Context) (net.Conn, error) {
		redialCalls++
		return pipeOrigin(t, okResponder("redialed ok")), nil
	}

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer tp.Shutdown(context.Background())

	rt := newH1RoundTripper(deadClient, 5*time.Second, 64<<10, redial, discardLogger(), nil, tp.Tracer("test"))
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "redialed ok" {
		t.Fatalf("body = %q, want %q", body, "redialed ok")
	}
	if redialCalls != 1 {
		t.Fatalf("redial called %d times, want 1", redialCalls)
	}
}

// TestH1RoundTripper_NonIdempotentMethodSkipsRedialOnFullWrite covers the
// opposite gate: the request is fully written (the origin actively read it
// via http.ReadRequest before closing without responding, so the write
// definitely wasn't zero-byte), and the method is POST — not idempotent —
// so a redial must never be attempted, and the original error must be
// reported as-is even though rt.redial is set and would otherwise succeed.
func TestH1RoundTripper_NonIdempotentMethodSkipsRedialOnFullWrite(t *testing.T) {
	conn := pipeOrigin(t, nil) // reads the request, then closes without responding

	redialCalls := 0
	redial := func(ctx context.Context) (net.Conn, error) {
		redialCalls++
		return pipeOrigin(t, okResponder("should never be reached")), nil
	}

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer tp.Shutdown(context.Background())

	rt := newH1RoundTripper(conn, 5*time.Second, 64<<10, redial, nil, nil, tp.Tracer("test"))
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/", nil)
	_, err := rt.RoundTrip(req)
	if err == nil {
		t.Fatalf("expected an error (origin closed without responding)")
	}
	if redialCalls != 0 {
		t.Fatalf("redial called %d times, want 0 (POST must not be retried after a full write)", redialCalls)
	}
}

// TestH1RoundTripper_IdempotentMethodRedialsAfterFullWrite is the mirror
// case: same "origin read the request then closed" setup, but a GET — an
// idempotent method — so the redial path must still be taken even though
// the write definitely wasn't zero-byte.
func TestH1RoundTripper_IdempotentMethodRedialsAfterFullWrite(t *testing.T) {
	conn := pipeOrigin(t, nil) // reads the request, then closes without responding

	redialCalls := 0
	redial := func(ctx context.Context) (net.Conn, error) {
		redialCalls++
		return pipeOrigin(t, okResponder("second try ok")), nil
	}

	rt := newH1RoundTripper(conn, 5*time.Second, 64<<10, redial, nil, nil, nil)
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "second try ok" {
		t.Fatalf("body = %q, want %q", body, "second try ok")
	}
	if redialCalls != 1 {
		t.Fatalf("redial called %d times, want 1", redialCalls)
	}
}

// TestH1RoundTripper_RedialItselfFails_ReturnsOriginalError covers the case
// where the retry is warranted (nothingWritten) but the redial dial itself
// fails — the original failure must still be what's reported, not the
// secondary redial error, and rt's own connection must be left untouched.
func TestH1RoundTripper_RedialItselfFails_ReturnsOriginalError(t *testing.T) {
	deadClient, deadServer := net.Pipe()
	deadServer.Close()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer tp.Shutdown(context.Background())

	wantErr := errors.New("redial dial failed")
	rt := newH1RoundTripper(deadClient, 5*time.Second, 64<<10, func(ctx context.Context) (net.Conn, error) {
		return nil, wantErr
	}, discardLogger(), nil, tp.Tracer("test"))

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	_, err := rt.RoundTrip(req)
	if err == nil {
		t.Fatalf("expected the original write error to be returned")
	}
	if errors.Is(err, wantErr) {
		t.Fatalf("RoundTrip returned the *redial* error (%v); want the original write failure surfaced instead", err)
	}
}

// TestH1RoundTripper_RedialSucceedsButRetryFails_ReturnsOriginalError
// covers the last redial branch: the redial dial succeeds, but the retried
// request on the fresh connection *also* fails — the original error must
// still win, and rt must not have adopted the doomed new connection.
func TestH1RoundTripper_RedialSucceedsButRetryFails_ReturnsOriginalError(t *testing.T) {
	deadClient, deadServer := net.Pipe()
	deadServer.Close()

	newDeadClient, newDeadServer := net.Pipe()
	newDeadServer.Close() // the redialed connection is ALSO already dead

	rt := newH1RoundTripper(deadClient, 5*time.Second, 64<<10, func(ctx context.Context) (net.Conn, error) {
		return newDeadClient, nil
	}, discardLogger(), nil, nil)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	_, err := rt.RoundTrip(req)
	if err == nil {
		t.Fatalf("expected an error: both the original and the redialed connection are dead")
	}

	rt.mu.Lock()
	stillOriginal := rt.conn.Conn == deadClient
	rt.mu.Unlock()
	if !stillOriginal {
		t.Fatalf("rt adopted the doomed redialed connection instead of keeping the original")
	}
}

// TestH1RoundTripper_MalformedResponseStatusLine covers roundTripOnce's
// http.ReadResponse failure branch specifically — distinct from
// boundNextHeaderBlock's own error path (exercised by every "origin closed
// without responding" test above, which fails before ever reaching
// ReadResponse): here the origin sends a complete, well-terminated header
// block, so boundNextHeaderBlock succeeds, but the bytes inside it aren't a
// parseable HTTP status line.
func TestH1RoundTripper_MalformedResponseStatusLine(t *testing.T) {
	conn := pipeOrigin(t, func(_ *http.Request, w io.Writer) {
		io.WriteString(w, "NOT A REAL STATUS LINE\r\n\r\n")
	})

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer tp.Shutdown(context.Background())

	rt := newH1RoundTripper(conn, 5*time.Second, 64<<10, nil, nil, nil, tp.Tracer("test"))
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatalf("expected a parse error from the malformed status line")
	}
}

// TestH1RoundTripper_HeadersTooLargeSkipsRedial covers the
// errors.Is(err, errHeadersTooLarge) short-circuit: a response whose
// headers exceed rt's headerLimit is a framing violation the origin itself
// produced, not a "maybe-stale-connection" signal — retrying an identical
// request against a fresh connection would just reproduce the same
// violation, so RoundTrip must report it directly without ever calling
// redial.
func TestH1RoundTripper_HeadersTooLargeSkipsRedial(t *testing.T) {
	conn := pipeOrigin(t, func(_ *http.Request, w io.Writer) {
		io.WriteString(w, "HTTP/1.1 200 OK\r\nX-Padding: "+string(make([]byte, 4096))+"\r\n\r\n")
	})

	redialCalls := 0
	rt := newH1RoundTripper(conn, 5*time.Second, 64 /* tiny, deliberately */, func(ctx context.Context) (net.Conn, error) {
		redialCalls++
		return nil, errors.New("must not be called")
	}, nil, nil, nil)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	_, err := rt.RoundTrip(req)
	if !errors.Is(err, errHeadersTooLarge) {
		t.Fatalf("err = %v, want errHeadersTooLarge", err)
	}
	if redialCalls != 0 {
		t.Fatalf("redial called %d times, want 0", redialCalls)
	}
}
