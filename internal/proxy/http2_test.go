package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"golang.org/x/net/http2"
)

// newH2TestServer starts an h2-capable httptest.Server — a plain
// httptest.NewTLSServer only ever offers http/1.1, so exercising the h2
// upstream/client paths needs this instead.
func newH2TestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(handler)
	if err := http2.ConfigureServer(ts.Config, &http2.Server{}); err != nil {
		t.Fatalf("ConfigureServer: %v", err)
	}
	ts.TLS = ts.Config.TLSConfig
	ts.StartTLS()
	return ts
}

// h1OnlyHTTPClient is proxyHTTPClient with h2 disabled client-side, forcing
// the upstream-h2/client-h1 combo even against an
// h2-capable origin.
func h1OnlyHTTPClient(t *testing.T, proxyAddr string, rootPEM []byte) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		t.Fatalf("failed to parse root PEM")
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
			TLSClientConfig: &tls.Config{RootCAs: pool, NextProtos: []string{"http/1.1"}},
			TLSNextProto:    map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
	}
}

// h2CapableHTTPClient is proxyHTTPClient with h2 explicitly forced on.
// http.Transport's docs: "ForceAttemptHTTP2 controls whether HTTP/2 is
// enabled ... By default, use of any [Dial/DialTLS/DialContext/
// TLSClientConfig] conservatively disables HTTP/2" — since these tests set
// TLSClientConfig (to supply the test root CA), h2 auto-negotiation would
// otherwise silently stay off and every request would fall back to h1.
func h2CapableHTTPClient(t *testing.T, proxyAddr string, rootPEM []byte) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		t.Fatalf("failed to parse root PEM")
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
			TLSClientConfig:   &tls.Config{RootCAs: pool},
			ForceAttemptHTTP2: true,
		},
	}
}

func TestHTTP2_H2Upstream_H2Client_RoundTripWithMutation(t *testing.T) {
	origin := newH2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Echo-Injected", r.Header.Get("X-Injected"))
		fmt.Fprintf(w, "hello from h2 origin, path=%s", r.URL.Path)
	})
	defer origin.Close()

	ruleJSON := `{"http":[{"match":{},
	  "request":[{"action":"header.add","params":{"X-Injected":"yes"}}]
	}]}`
	handler, caPEM := newTestHandler(t, ruleJSON)
	proxyAddr := runProxy(t, handler)
	client := h2CapableHTTPClient(t, proxyAddr, caPEM)

	resp, err := client.Get(origin.URL + "/hi")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("ProtoMajor = %d, want 2 (client should have negotiated h2)", resp.ProtoMajor)
	}
	if want := "hello from h2 origin, path=/hi"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
	if got := resp.Header.Get("Echo-Injected"); got != "yes" {
		t.Fatalf("Echo-Injected = %q, want yes (request header.add did not reach origin)", got)
	}
}

// TestHTTP2_UpstreamSpanTree_H2 is the h2 upstream-leg twin of
// TestHTTP1Handler_UpstreamSpanTree_H1 — same "request" -> "upstream" ->
// "upstream.connect"/"upstream.response" shape, but no "upstream.response"
// vs "upstream.request" split: http2.ClientConn.RoundTrip sends the
// request and waits for headers as one atomic call, so there's only a
// single "upstream.response" child covering both.
func TestHTTP2_UpstreamSpanTree_H2(t *testing.T) {
	origin := newH2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from h2 origin, path=%s", r.URL.Path)
	})
	defer origin.Close()

	handler, caPEM := newTestHandler(t, `{"http":[{"match":{}}]}`)
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer tp.Shutdown(context.Background())
	handler.Tracer = tp.Tracer("test")

	proxyAddr := runProxy(t, handler)
	client := h2CapableHTTPClient(t, proxyAddr, caPEM)

	resp, err := client.Get(origin.URL + "/hi")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("ProtoMajor = %d, want 2", resp.ProtoMajor)
	}

	spans := exporter.GetSpans()
	reqSpan := findSpan(spans, "request", hasMethodGET)
	if reqSpan == nil {
		t.Fatalf("no per-stream \"request\" span (method=GET) found; spans: %v", spanNames(spans))
	}
	upstreamSpan := findSpan(spans, "upstream", nil)
	if upstreamSpan == nil {
		t.Fatalf("no \"upstream\" span found; spans: %v", spanNames(spans))
	}
	if upstreamSpan.Parent.SpanID() != reqSpan.SpanContext.SpanID() {
		t.Errorf("\"upstream\" span's parent = %s, want the request span %s", upstreamSpan.Parent.SpanID(), reqSpan.SpanContext.SpanID())
	}
	if got, ok := spanAttr(*upstreamSpan, "proto"); !ok || got != "h2" {
		t.Errorf("\"upstream\" span proto = %v, ok=%v, want h2", got, ok)
	}

	connectSpan := findSpan(spans, "upstream.connect", func(s tracetest.SpanStub) bool {
		return s.Parent.SpanID() == upstreamSpan.SpanContext.SpanID()
	})
	if connectSpan == nil {
		t.Fatalf("no \"upstream.connect\" span parented under \"upstream\"; spans: %v", spanNames(spans))
	}
	if reused, ok := spanBoolAttr(*connectSpan, "reused"); !ok || !reused {
		t.Errorf("\"upstream.connect\" reused = %v, ok=%v, want true (this GET reuses the seeded upstream h2 connection)", reused, ok)
	}

	respSpan := findSpan(spans, "upstream.response", func(s tracetest.SpanStub) bool {
		return s.Parent.SpanID() == upstreamSpan.SpanContext.SpanID()
	})
	if respSpan == nil {
		t.Fatalf("no \"upstream.response\" span parented under \"upstream\"; spans: %v", spanNames(spans))
	}
	if status, ok := spanIntAttr(*respSpan, "status"); !ok || status != 200 {
		t.Errorf("\"upstream.response\" status = %v, ok=%v, want 200", status, ok)
	}
}

func TestHTTP2_ConcurrentStreamsMultiplexed(t *testing.T) {
	const n = 5
	var mu sync.Mutex
	arrived := 0
	release := make(chan struct{})
	origin := newH2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		arrived++
		reached := arrived == n
		mu.Unlock()
		if reached {
			close(release)
		}
		<-release
		fmt.Fprintf(w, "ok")
	})
	defer origin.Close()

	handler, caPEM := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)
	client := h2CapableHTTPClient(t, proxyAddr, caPEM)

	// Pre-warm the connection so all N concurrent requests below reuse the
	// one pooled h2 connection, instead of racing to dial N separate ones.
	warm, err := client.Get(origin.URL + "/warm")
	if err != nil {
		t.Fatalf("warm-up GET: %v", err)
	}
	io.Copy(io.Discard, warm.Body)
	warm.Body.Close()

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(origin.URL + "/")
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			if resp.ProtoMajor != 2 {
				errs <- fmt.Errorf("ProtoMajor = %d, want 2", resp.ProtoMajor)
				return
			}
			io.Copy(io.Discard, resp.Body)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

func TestHTTP2_MismatchedAuthorityRejected(t *testing.T) {
	origin := newH2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from origin")
	})
	defer origin.Close()

	handler, caPEM := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)

	originHost := strings.TrimPrefix(strings.TrimPrefix(origin.URL, "https://"), "http://")
	tunnelConn := connectThroughProxy(t, proxyAddr, originHost)
	defer tunnelConn.Close()

	sni, _, err := net.SplitHostPort(originHost)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("failed to parse root PEM")
	}
	tlsConn := tls.Client(tunnelConn, &tls.Config{ServerName: sni, RootCAs: pool, NextProtos: []string{"h2"}})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("did not negotiate h2 with the proxy")
	}

	cc, err := (&http2.Transport{}).NewClientConn(tlsConn)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://evil.example/", nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d (421 coalescing guard)", resp.StatusCode, http.StatusMisdirectedRequest)
	}
}

// TestHTTP2_H1ClientViaH2Upstream_UnknownLengthBodyDoesNotHang is a
// regression test: relaying an h2-upstream response (ContentLength=-1, no
// TransferEncoding — h2 has no "chunked" wire concept) straight through
// (*http.Response).Write to an h1 client used to fall back to
// close-terminated framing that the proxy never actually honored (the
// connection was kept alive for the next keep-alive request instead),
// leaving the client blocked forever waiting for either more data or a
// close that never came. A second request on the same keep-alive
// connection proves the fix: both must complete, not hang.
func TestHTTP2_H1ClientViaH2Upstream_UnknownLengthBodyDoesNotHang(t *testing.T) {
	origin := newH2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Deliberately no Content-Length: forces the h2 origin (and thus
		// our upstream h2 RoundTrip) to report ContentLength == -1.
		f, _ := w.(http.Flusher)
		fmt.Fprintf(w, "first chunk for %s;", r.URL.Path)
		if f != nil {
			f.Flush()
		}
		fmt.Fprintf(w, "second chunk")
	})
	defer origin.Close()

	handler, caPEM := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)
	client := h1OnlyHTTPClient(t, proxyAddr, caPEM)

	for i, path := range []string{"/a", "/b"} {
		resp, err := client.Get(origin.URL + path)
		if err != nil {
			t.Fatalf("GET #%d: %v", i, err)
		}
		if resp.ProtoMajor != 1 {
			resp.Body.Close()
			t.Fatalf("GET #%d: ProtoMajor = %d, want 1 (client should stay h1)", i, resp.ProtoMajor)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("GET #%d: ReadAll: %v", i, err)
		}
		want := "first chunk for " + path + ";second chunk"
		if string(body) != want {
			t.Fatalf("GET #%d: body = %q, want %q", i, body, want)
		}
	}
}

// TestH2RoundTripper_ReconnectsAfterStaleness is a regression test for the
// other half of the same bug class: a single h2RoundTripper is shared
// across every request forwarded over one client connection's lifetime,
// and the upstream origin can make its side unusable at any point (GOAWAY,
// idle close, lost ping) independent of the client. Without a redial, every
// request after that point would fail forever even though a fresh upstream
// connection works fine.
func TestH2RoundTripper_ReconnectsAfterStaleness(t *testing.T) {
	origin := newH2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok %s", r.URL.Path)
	})
	defer origin.Close()

	dst := origin.Listener.Addr().String()
	host, _, err := net.SplitHostPort(dst)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	dialer := NewUpstreamDialer(5*time.Second, 1)
	cc, upConn, err := newUpstreamH2ClientConn(context.Background(), dialer, nil, dst, host, 3, 5*time.Second, 64<<10, nil)
	if err != nil {
		t.Fatalf("newUpstreamH2ClientConn: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer tp.Shutdown(context.Background())

	// log/tracer/readTimeout are all exercised here too (not just the
	// reconnect itself): the reconnect log line, the tracer's
	// "upstream.connect" reused=false span, and a generous readTimeout that
	// should never actually fire (both RoundTrips complete well within it,
	// so timer.Stop() succeeds — the common case, distinct from the
	// timer-already-fired race).
	rt := &h2RoundTripper{dialer: dialer, dst: dst, sni: host, connectTimeout: 5 * time.Second, connectTries: 3, readTimeout: 5 * time.Second, log: log, tracer: tp.Tracer("test")}
	rt.seed(cc, upConn)
	defer rt.Close()

	req1, _ := http.NewRequest(http.MethodGet, "https://"+host+"/first", nil)
	resp1, err := rt.RoundTrip(req1)
	if err != nil {
		t.Fatalf("RoundTrip #1: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if string(body1) != "ok /first" {
		t.Fatalf("body #1 = %q", body1)
	}

	// Simulate the origin making the connection permanently unusable
	// (GOAWAY / idle-close / lost ping all end up here from cc's point of
	// view) without mitmania doing anything — closing the ClientConn
	// directly is the simplest reliable way to force CanTakeNewRequest to
	// start returning false.
	cc.Close()
	if cc.CanTakeNewRequest() {
		t.Fatalf("test setup: cc should be unusable after Close")
	}

	req2, _ := http.NewRequest(http.MethodGet, "https://"+host+"/second", nil)
	resp2, err := rt.RoundTrip(req2)
	if err != nil {
		t.Fatalf("RoundTrip #2 (should have transparently redialed): %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if string(body2) != "ok /second" {
		t.Fatalf("body #2 = %q", body2)
	}
}

// TestH2RoundTripper_ReconnectDialFails_RoundTripReturnsError is
// TestH2RoundTripper_ReconnectsAfterStaleness's failure twin: the existing
// connection goes stale exactly the same way, but this time the origin
// itself is gone by the time currentConn tries to redial, so the reconnect
// dial fails too. RoundTrip must surface that dial error directly, not
// hang or panic — and rt must be left with no cached connection, so the
// NEXT RoundTrip attempt (once the origin is back) tries a fresh dial
// again rather than reusing a known-broken cc/upConn pair.
func TestH2RoundTripper_ReconnectDialFails_RoundTripReturnsError(t *testing.T) {
	origin := newH2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	})
	dst := origin.Listener.Addr().String()
	host, _, err := net.SplitHostPort(dst)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	dialer := NewUpstreamDialer(500*time.Millisecond, 1)
	cc, upConn, err := newUpstreamH2ClientConn(context.Background(), dialer, nil, dst, host, 1, 500*time.Millisecond, 64<<10, nil)
	if err != nil {
		t.Fatalf("newUpstreamH2ClientConn: %v", err)
	}

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer tp.Shutdown(context.Background())

	rt := &h2RoundTripper{dialer: dialer, dst: dst, sni: host, connectTimeout: 500 * time.Millisecond, connectTries: 1, log: slog.New(slog.NewTextHandler(io.Discard, nil)), tracer: tp.Tracer("test")}
	rt.seed(cc, upConn)
	defer rt.Close()

	// A warm-up round trip first, same as the success-case test above —
	// an entirely unused ClientConn's internal read loop hasn't
	// necessarily synced with the server yet, so CanTakeNewRequest() can
	// still (harmlessly) read stale-true for a moment after Close() without
	// ever having actually talked to the server first.
	warmReq, _ := http.NewRequest(http.MethodGet, "https://"+host+"/warm", nil)
	warmResp, err := rt.RoundTrip(warmReq)
	if err != nil {
		t.Fatalf("warm-up RoundTrip: %v", err)
	}
	io.ReadAll(warmResp.Body)
	warmResp.Body.Close()

	cc.Close() // same staleness trigger as the success-case test above
	if cc.CanTakeNewRequest() {
		t.Fatalf("test setup: cc should be unusable after Close")
	}
	origin.Close()

	req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatalf("RoundTrip succeeded despite the origin being gone")
	}

	rt.mu.Lock()
	stillCached := rt.cc != nil
	rt.mu.Unlock()
	if stillCached {
		t.Fatalf("rt kept a cached ClientConn after a failed reconnect")
	}
}

// TestHTTP2_H1ClientViaH2Upstream_WebSocketUpgradeFallsBackToH1 is a
// regression test: h2 forbids the Upgrade header outright (RFC 9113
// §8.5), so a WebSocket upgrade request forwarded straight through the
// shared h2 upstream connection used to fail immediately with "http2:
// invalid Upgrade request header". A regular request first establishes
// (and reuses) the h2 upstream connection on this client tunnel; the
// WebSocket request on the same keep-alive tunnel must instead fall back
// to a dedicated h1-only connection to the same origin and complete the
// 101 handshake normally.
func TestHTTP2_H1ClientViaH2Upstream_WebSocketUpgradeFallsBackToH1(t *testing.T) {
	origin := newH2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "" {
			wsEchoHandler(w, r) // needs a real h1 Hijack — h2 ResponseWriters don't support it
			return
		}
		fmt.Fprintf(w, "hello from h2 origin, proto=%s", r.Proto)
	})
	defer origin.Close()

	handler, caPEM := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)

	target := origin.Listener.Addr().String()
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	tunnel := connectThroughProxy(t, proxyAddr, target)
	defer tunnel.Close()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("failed to parse root PEM")
	}
	// Client offers only http/1.1 — this test is specifically the h1-client
	// case (Step 5); the h2-client case is a different code path
	// (handleH2Stream) with no h2-forbids-Upgrade problem to fall back
	// from in the first place.
	tlsConn := tls.Client(tunnel, &tls.Config{ServerName: host, RootCAs: pool, NextProtos: []string{"http/1.1"}})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	br := bufio.NewReader(tlsConn)

	// First request: ordinary GET, establishing (and leaving cached in the
	// shared h2RoundTripper) the h2 upstream connection.
	getReq, _ := http.NewRequest(http.MethodGet, "https://"+target+"/", nil)
	if err := getReq.Write(tlsConn); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	getResp, err := http.ReadResponse(br, getReq)
	if err != nil {
		t.Fatalf("ReadResponse (GET): %v", err)
	}
	getBody, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK || !strings.HasPrefix(string(getBody), "hello from h2 origin") {
		t.Fatalf("GET status=%d body=%q, want 200 from the h2 origin", getResp.StatusCode, getBody)
	}

	// Second request, same keep-alive tunnel: WebSocket upgrade — must not
	// be forwarded over the h2 upstream connection just established above.
	const payload = "PING-AFTER-H2-FALLBACK"
	upgradeReq := "GET /ws HTTP/1.1\r\nHost: " + target + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	if _, err := tlsConn.Write([]byte(upgradeReq + payload)); err != nil {
		t.Fatalf("write upgrade request + pipelined payload: %v", err)
	}

	upResp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("ReadResponse (upgrade): %v", err)
	}
	if upResp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d, want 101", upResp.StatusCode)
	}

	got := make([]byte, len(payload))
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("reading echoed payload: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echoed payload = %q, want %q", got, payload)
	}
}
