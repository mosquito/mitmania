package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"mitmania/internal/rules"
	"mitmania/internal/session"
)

type recordingDialer struct {
	dials    atomic.Int32
	tlsDials atomic.Int32
}

func (d *recordingDialer) Dial(context.Context, string, string) (net.Conn, error) {
	d.dials.Add(1)
	a, b := net.Pipe()
	go b.Close()
	return a, nil
}

func (d *recordingDialer) DialTLS(context.Context, string, string, string) (*tls.Conn, error) {
	d.tlsDials.Add(1)
	return nil, errors.New("unexpected TLS dial")
}

func (d *recordingDialer) DialTLSH1Only(context.Context, string, string, string) (*tls.Conn, error) {
	d.tlsDials.Add(1)
	return nil, errors.New("unexpected TLS dial")
}

// LookupIP returns a fixed public-looking address (RFC 5737 TEST-NET-3),
// well within the default-allow egress policy, regardless of host — these
// tests care about dial/no-dial behavior, not real resolution.
func (d *recordingDialer) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.1")}, nil
}

func servePipe(t *testing.T, h *Http1Handler, dialer UpstreamDialer) (net.Conn, <-chan struct{}) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Serve(context.Background(), session.Session{
			Client: netip.MustParseAddrPort("127.0.0.1:12345"),
			Conn:   server,
		}, dialer)
	}()
	t.Cleanup(func() { client.Close() })
	return client, done
}

func TestDeniedCONNECTDoesNotDial(t *testing.T) {
	h, _ := newTestHandler(t, "")
	dialer := &recordingDialer{}
	conn, done := servePipe(t, h, dialer)

	io.WriteString(conn, "CONNECT denied.example:443 HTTP/1.1\r\nHost: denied.example:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	if resp.StatusCode != http.StatusNetworkAuthenticationRequired {
		t.Fatalf("status = %d, want 511", resp.StatusCode)
	}
	if got := dialer.dials.Load() + dialer.tlsDials.Load(); got != 0 {
		t.Fatalf("denied CONNECT made %d upstream dial(s), want zero", got)
	}
}

func TestDeniedAbsoluteFormDoesNotDial(t *testing.T) {
	h, _ := newTestHandler(t, "")
	dialer := &recordingDialer{}
	conn, done := servePipe(t, h, dialer)

	io.WriteString(conn, "GET http://denied.example/ HTTP/1.1\r\nHost: denied.example\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	if resp.StatusCode != http.StatusNetworkAuthenticationRequired {
		t.Fatalf("status = %d, want 511", resp.StatusCode)
	}
	if got := dialer.dials.Load() + dialer.tlsDials.Load(); got != 0 {
		t.Fatalf("denied absolute-form request made %d upstream dial(s), want zero", got)
	}
}

// TestEgressDenyBlocksCONNECTBeforeDial covers the egress-policy resolve-phase: the
// http[] rule chain matches (mitm:false, so no TLS is involved), but the
// egress[] policy denies the address recordingDialer.LookupIP resolves
// to — this must fail closed with 403 before any dial, exactly like a
// connection-phase http[] no-match, just via the independent egress list.
func TestEgressDenyBlocksCONNECTBeforeDial(t *testing.T) {
	h, _ := newTestHandler(t, `{
	  "http": [ {"match": {"host": "allowed.example", "port": "443"}, "mitm": false} ],
	  "egress": [ {"cidr": "203.0.113.0/24", "action": "deny"} ]
	}`)
	dialer := &recordingDialer{}
	conn, done := servePipe(t, h, dialer)

	io.WriteString(conn, "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := dialer.dials.Load() + dialer.tlsDials.Load(); got != 0 {
		t.Fatalf("egress-denied CONNECT made %d upstream dial(s), want zero", got)
	}
}

// TestEgressDenyBlocksAbsoluteFormBeforeDial is the same case on the
// absolute-form (plain http://) path.
func TestEgressDenyBlocksAbsoluteFormBeforeDial(t *testing.T) {
	h, _ := newTestHandler(t, `{
	  "http": [ {"match": {"host": "allowed.example"}} ],
	  "egress": [ {"cidr": "203.0.113.0/24", "action": "deny"} ]
	}`)
	dialer := &recordingDialer{}
	conn, done := servePipe(t, h, dialer)

	io.WriteString(conn, "GET http://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := dialer.dials.Load() + dialer.tlsDials.Load(); got != 0 {
		t.Fatalf("egress-denied absolute-form request made %d upstream dial(s), want zero", got)
	}
}

func TestCONNECTRejectsSNIThatDiffersFromTarget(t *testing.T) {
	h, _ := newTestHandler(t, `{"http":[{"match":{"host":"allowed.example","port":"443"}}]}`)
	dialer := &recordingDialer{}
	conn, done := servePipe(t, h, dialer)

	io.WriteString(conn, "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\n\r\n")
	br := bufio.NewReader(conn)
	connectResp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("ReadResponse CONNECT: %v", err)
	}
	connectResp.Body.Close()
	if connectResp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", connectResp.StatusCode)
	}
	if br.Buffered() != 0 {
		t.Fatalf("unexpected bytes buffered after CONNECT")
	}

	tlsConn := tls.Client(conn, &tls.Config{ServerName: "other.example", InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("fallback TLS handshake: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("ReadResponse mismatch: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", resp.StatusCode)
	}
	if got := dialer.tlsDials.Load(); got != 0 {
		t.Fatalf("SNI mismatch made %d TLS origin dial(s), want zero", got)
	}
}

func TestAuthorityNormalizationAndBinding(t *testing.T) {
	host, port, _, err := normalizeAuthority("BÜCHER.Example.:443", "80")
	if err != nil {
		t.Fatalf("normalizeAuthority: %v", err)
	}
	if host != "xn--bcher-kva.example" || port != "443" {
		t.Fatalf("normalized host/port = %q/%q", host, port)
	}
	if !authorityMatches("XN--BCHER-KVA.EXAMPLE:443", host, port, "https") {
		t.Fatalf("equivalent IDNA authority did not match")
	}
	if authorityMatches("xn--bcher-kva.example:444", host, port, "https") {
		t.Fatalf("different authority port matched")
	}
	if !sameHost("::ffff:192.0.2.1", "192.0.2.1") {
		t.Fatalf("equivalent IPv4-mapped address did not match")
	}
}

func TestCONNECTUsesRequestTargetNotHostHeader(t *testing.T) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"CONNECT target.example:443 HTTP/1.1\r\nHost: attacker.example:443\r\n\r\n",
	)))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if req.Host != "target.example:443" {
		t.Fatalf("CONNECT authority = %q, want request-target authority", req.Host)
	}
}

type countingRoundTripper struct{ calls atomic.Int32 }

func (rt *countingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	rt.calls.Add(1)
	return nil, errors.New("unexpected round trip")
}

func TestHTTP1MismatchedAuthorityRejected(t *testing.T) {
	h := &Http1Handler{}
	rt := &countingRoundTripper{}
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()

	req, _ := http.NewRequest(http.MethodGet, "https://evil.example/", nil)
	req.Host = "evil.example"
	done := make(chan bool, 1)
	go func() {
		done <- h.handleOneRequest(
			context.Background(),
			session.Session{Client: netip.MustParseAddrPort("127.0.0.1:12345")},
			proxy, rt, bufio.NewReader(proxy),
			rules.ConnInput{Host: "allowed.example", Port: "443", Proto: "https"}, "allowed.example:443", req,
			"", // mismatched-authority rejection happens before Rules.Lookup/principal are ever used
		)
	}()

	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if keep := <-done; keep {
		t.Fatalf("mismatched authority kept connection alive")
	}
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", resp.StatusCode)
	}
	if got := rt.calls.Load(); got != 0 {
		t.Fatalf("mismatched authority reached upstream %d time(s)", got)
	}
}

func TestBoundedHeadersDoNotLimitRequestBody(t *testing.T) {
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()

	body := strings.Repeat("x", 32<<10)
	go func() {
		io.WriteString(client, "POST /upload HTTP/1.1\r\nHost: allowed.example\r\nContent-Length: 32768\r\n\r\n"+body)
	}()

	stream := newPrependConn(proxy)
	br := bufio.NewReaderSize(stream, bufioReadSize)
	if err := boundNextHeaderBlock(br, stream, 256); err != nil {
		t.Fatalf("boundNextHeaderBlock: %v", err)
	}
	req, err := http.ReadRequest(br)
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll body: %v", err)
	}
	if string(got) != body {
		t.Fatalf("body length = %d, want %d", len(got), len(body))
	}
}

func TestEveryKeepAliveHeaderIsBounded(t *testing.T) {
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()

	go func() {
		io.WriteString(client, "GET /one HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
		io.WriteString(client, "GET /two HTTP/1.1\r\nHost: allowed.example\r\nX-Padding: "+strings.Repeat("x", 512)+"\r\n\r\n")
	}()

	stream := newPrependConn(proxy)
	br := bufio.NewReaderSize(stream, bufioReadSize)
	if err := boundNextHeaderBlock(br, stream, 128); err != nil {
		t.Fatalf("first header: %v", err)
	}
	first, err := http.ReadRequest(br)
	if err != nil {
		t.Fatalf("first ReadRequest: %v", err)
	}
	first.Body.Close()
	if err := boundNextHeaderBlock(br, stream, 128); !errors.Is(err, errHeadersTooLarge) {
		t.Fatalf("second header error = %v, want errHeadersTooLarge", err)
	}
}

func TestH1RoundTripperBoundsResponseHeadersNotBody(t *testing.T) {
	proxy, origin := net.Pipe()
	defer proxy.Close()
	defer origin.Close()

	body := strings.Repeat("y", 32<<10)
	go func() {
		br := bufio.NewReader(origin)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.Body.Close()
		io.WriteString(origin, "HTTP/1.1 200 OK\r\nContent-Length: 32768\r\n\r\n"+body)
	}()

	rt := newH1RoundTripper(proxy, 0, 256, nil, nil, nil, nil)
	req, _ := http.NewRequest(http.MethodGet, "http://allowed.example/", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll body: %v", err)
	}
	if string(got) != body {
		t.Fatalf("body length = %d, want %d", len(got), len(body))
	}
}

func TestH1RoundTripperRejectsOversizedResponseHeaders(t *testing.T) {
	proxy, origin := net.Pipe()
	defer proxy.Close()
	defer origin.Close()

	go func() {
		br := bufio.NewReader(origin)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.Body.Close()
		io.WriteString(origin, "HTTP/1.1 200 OK\r\nX-Padding: "+strings.Repeat("x", 512)+"\r\nContent-Length: 0\r\n\r\n")
	}()

	rt := newH1RoundTripper(proxy, 0, 128, nil, nil, nil, nil)
	req, _ := http.NewRequest(http.MethodGet, "http://allowed.example/", nil)
	if _, err := rt.RoundTrip(req); !errors.Is(err, errHeadersTooLarge) {
		t.Fatalf("RoundTrip error = %v, want errHeadersTooLarge", err)
	}
}
