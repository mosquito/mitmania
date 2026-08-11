package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mitmania/internal/rules"
	"mitmania/internal/session"
	"mitmania/internal/storage"
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

// TestCONNECTRejectsSNIThatDiffersFromTarget_FallbackHandshakeAlsoFails is
// TestCONNECTRejectsSNIThatDiffersFromTarget's failure-compounds-on-failure
// case: the SNI/authority mismatch is detected the same way, but this time
// the client also doesn't trust mitmania's root CA, so the fallback
// handshake meant to deliver the 421 page fails too. The connection must
// simply end (sni-mismatch-fallback-failed) rather than hang or retry.
func TestCONNECTRejectsSNIThatDiffersFromTarget_FallbackHandshakeAlsoFails(t *testing.T) {
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

	// No RootCAs, verification not skipped: the fallback leaf minted for
	// "other.example" is rejected client-side, same as a real browser that
	// never installed mitmania's CA.
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "other.example"})
	if err := tlsConn.Handshake(); err == nil {
		tlsConn.Close()
		t.Fatalf("client handshake against the SNI-mismatch fallback cert unexpectedly succeeded")
	}
	<-done
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

// TestCONNECTRejectsInvalidAuthorityBeforeDial covers serveConnect's
// normalizeAuthority failure path: a syntactically invalid CONNECT
// authority (port out of range) must be rejected with 400 before any
// network connection — same fail-closed-before-dial principle as the
// denied/egress-denied cases above, just for a request that's malformed
// rather than merely unauthorized.
func TestCONNECTRejectsInvalidAuthorityBeforeDial(t *testing.T) {
	h, _ := newTestHandler(t, `{"http":[{"match":{}}]}`)
	dialer := &recordingDialer{}
	conn, done := servePipe(t, h, dialer)

	io.WriteString(conn, "CONNECT allowed.example:99999 HTTP/1.1\r\nHost: allowed.example:99999\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if got := dialer.dials.Load() + dialer.tlsDials.Load(); got != 0 {
		t.Fatalf("invalid-authority CONNECT made %d upstream dial(s), want zero", got)
	}
}

// TestAbsoluteFormRejectsUnsupportedSchemeBeforeDial covers
// serveAbsoluteForm's scheme check: an absolute-form request for a scheme
// other than "http" (proxying https:// in absolute-form makes no sense —
// that's what CONNECT is for) must be rejected before any dial.
func TestAbsoluteFormRejectsUnsupportedSchemeBeforeDial(t *testing.T) {
	h, _ := newTestHandler(t, `{"http":[{"match":{}}]}`)
	dialer := &recordingDialer{}
	conn, done := servePipe(t, h, dialer)

	io.WriteString(conn, "GET ftp://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if got := dialer.dials.Load() + dialer.tlsDials.Load(); got != 0 {
		t.Fatalf("unsupported-scheme request made %d upstream dial(s), want zero", got)
	}
}

// TestAbsoluteFormRejectsInvalidAuthorityBeforeDial is
// TestCONNECTRejectsInvalidAuthorityBeforeDial's absolute-form twin.
func TestAbsoluteFormRejectsInvalidAuthorityBeforeDial(t *testing.T) {
	h, _ := newTestHandler(t, `{"http":[{"match":{}}]}`)
	dialer := &recordingDialer{}
	conn, done := servePipe(t, h, dialer)

	io.WriteString(conn, "GET http://allowed.example:99999/ HTTP/1.1\r\nHost: allowed.example:99999\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if got := dialer.dials.Load() + dialer.tlsDials.Load(); got != 0 {
		t.Fatalf("invalid-authority request made %d upstream dial(s), want zero", got)
	}
}

// failingStatStorage wraps a real storage.Storage but fails every Stat call
// from failAfter onward (1-indexed: failAfter=1 fails the very first call),
// simulating the shared rule-storage backend becoming unavailable —
// independent of anything about the request itself. Used to exercise the
// three "rule-engine-error" branches (serveConnect, serveAbsoluteForm,
// handleOneRequest), which — unlike a policy denial — deliberately end the
// connection with no response at all rather than an error page: an infra
// failure talking to Storage isn't something to describe to the client.
type failingStatStorage struct {
	storage.Storage
	calls     atomic.Int32
	failAfter int32
}

func (f *failingStatStorage) Stat(ctx context.Context, key string) (storage.Version, error) {
	if f.calls.Add(1) >= f.failAfter {
		return "", errors.New("storage: simulated backend outage")
	}
	return f.Storage.Stat(ctx, key)
}

// newRuleEngineErrorHandler builds an Http1Handler backed by a RuleEngine
// whose Storage.Stat fails starting from the failAfter'th call — everything
// else (CertFactory, CAPEM, limits) matches newHappyPathHandler.
func newRuleEngineErrorHandler(t *testing.T, failAfter int32) *Http1Handler {
	t.Helper()
	factory, ca := newTestFactory(t)
	caPEM := pemEncodeCert(ca.Cert.Raw)

	st, err := storage.NewPosixStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewPosixStorage: %v", err)
	}
	failing := &failingStatStorage{Storage: st, failAfter: failAfter}
	store := rules.NewRuleStore(failing)
	if err := store.SaveDefault(context.Background(), []byte(testPermissiveDefault)); err != nil {
		t.Fatalf("store.SaveDefault: %v", err)
	}
	// uuid and egress are both spelled out explicitly so a single
	// Rules.Lookup call makes exactly one Storage.Stat call: an omitted
	// uuid would trigger lookupIP's own mint-and-persist re-Stat, and an
	// omitted egress would fall through to a rules/default Stat via
	// resolveEgress — either would throw off failAfter's calibration
	// against "how many Lookup calls happen before the point under test".
	ruleJSON := `{"http":[{"match":{}}],"uuid":"11111111-1111-1111-1111-111111111111",
	  "egress":[{"cidr":"0.0.0.0/0","action":"allow"},{"cidr":"::/0","action":"allow"}]}`
	if err := store.Save(context.Background(), netip.MustParseAddr("127.0.0.1"), []byte(ruleJSON)); err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	return &Http1Handler{
		TLS:                 &TLSService{Factory: factory},
		Rules:               rules.NewRuleEngine(store),
		CAPEM:               caPEM,
		HeaderLimit:         64 << 10,
		BodyWindow:          64 << 10,
		HTTP2ConnectTimeout: 5 * time.Second,
		HTTP2ConnectTries:   3,
		HTTP2ReadTimeout:    5 * time.Second,
	}
}

// TestServeConnect_RuleEngineErrorClosesWithoutResponse covers serveConnect's
// h.Rules.Lookup error branch: a Storage failure while resolving the
// client's rule file must fail closed by simply ending the connection — no
// "200 Connection Established", no error page — since at that point the
// proxy can't even determine whether the client is authorized to know
// anything about the target.
func TestServeConnect_RuleEngineErrorClosesWithoutResponse(t *testing.T) {
	h := newRuleEngineErrorHandler(t, 1) // fail the very first Stat call
	conn, done := servePipe(t, h, &recordingDialer{})

	io.WriteString(conn, "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\n\r\n")
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	<-done
	if err == nil {
		t.Fatalf("expected the connection to close with no response, got %d bytes: %q", n, buf[:n])
	}
}

// TestServeAbsoluteForm_RuleEngineErrorClosesWithoutResponse is
// TestServeConnect_RuleEngineErrorClosesWithoutResponse's absolute-form
// twin.
func TestServeAbsoluteForm_RuleEngineErrorClosesWithoutResponse(t *testing.T) {
	h := newRuleEngineErrorHandler(t, 1)
	conn, done := servePipe(t, h, &recordingDialer{})

	io.WriteString(conn, "GET http://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	<-done
	if err == nil {
		t.Fatalf("expected the connection to close with no response, got %d bytes: %q", n, buf[:n])
	}
}

// TestHandleOneRequest_RuleEngineErrorMidConnection_ClosesWithoutResponse
// covers the same branch inside handleOneRequest specifically: the rule
// engine is re-consulted on every keep-alive request ("hot reload on every
// request"), so a Storage outage that starts mid-connection — after the
// CONNECT itself, and the mitm:true TLS termination it authorized, already
// succeeded — must still fail closed on the very next request, not
// silently keep serving under stale authorization. This needs a real TLS
// tunnel (recordingDialer's DialTLS is a stub that always fails, so it
// can't reach Terminate), hence the real network/origin setup rather than
// servePipe. failAfter=2 lets the CONNECT's own Rules.Lookup call (the 1st
// Storage.Stat) succeed, then fails the request-phase Rules.Lookup (the
// 2nd).
func TestHandleOneRequest_RuleEngineErrorMidConnection_ClosesWithoutResponse(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("origin was reached; the mid-connection rule-engine failure should have ended the connection first")
	}))
	defer origin.Close()
	target := origin.Listener.Addr().String()
	host, _, _ := net.SplitHostPort(target)

	h := newRuleEngineErrorHandler(t, 2)
	proxyAddr := runProxy(t, h)

	tunnel := connectThroughProxy(t, proxyAddr, target)
	defer tunnel.Close()
	tlsConn := tls.Client(tunnel, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://"+target+"/", nil)
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	buf := make([]byte, 16)
	n, err := tlsConn.Read(buf)
	if err == nil {
		t.Fatalf("expected the connection to close with no response, got %d bytes: %q", n, buf[:n])
	}
}

// failingRoundTripper always fails — used to force handleOneRequest's
// upstream-error branch deterministically, independent of any real network
// condition.
type failingRoundTripper struct{ err error }

func (rt *failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, rt.err
}

// TestHandleOneRequest_UpstreamRoundTripErrorGetsClassifiedResponse covers
// handleOneRequest's roundTripper.RoundTrip error branch directly (the same
// technique TestHTTP1MismatchedAuthorityRejected above uses): a plain,
// non-timeout, non-EOF upstream failure must be classified via
// classifyReadErr and delivered to the client as the corresponding Squid-
// style page (502 ERR_INVALID_RESP here), not a silent drop.
func TestHandleOneRequest_UpstreamRoundTripErrorGetsClassifiedResponse(t *testing.T) {
	h, _ := newHappyPathHandler(t)
	rt := &failingRoundTripper{err: errors.New("boom: upstream exploded")}
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()

	req, _ := http.NewRequest(http.MethodGet, "https://allowed.example/", nil)
	req.Host = "allowed.example"
	done := make(chan bool, 1)
	go func() {
		done <- h.handleOneRequest(
			context.Background(),
			session.Session{Client: netip.MustParseAddrPort("127.0.0.1:12345")},
			proxy, rt, bufio.NewReader(proxy),
			rules.ConnInput{Host: "allowed.example", Port: "443", Proto: "https"}, "allowed.example:443", req,
			"",
		)
	}()

	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if keep := <-done; keep {
		t.Fatalf("upstream error kept the connection alive")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

// TestHandleOneRequest_ClientWriteErrorDoesNotPanic covers
// handleOneRequest's resp.Write(client) failure branch: the upstream
// answers normally, but the client side is already gone by the time the
// proxy tries to write the response back — a real scenario (client
// disconnects mid-flight) that must be handled as a clean return, not a
// panic or a hang.
func TestHandleOneRequest_ClientWriteErrorDoesNotPanic(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}))
	defer origin.Close()
	originAddr := origin.Listener.Addr().String()
	originHost, originPort, _ := net.SplitHostPort(originAddr)

	h, _ := newHappyPathHandler(t)
	client, proxy := net.Pipe()
	client.Close() // gone before the proxy ever tries to write the response back
	defer proxy.Close()

	req, _ := http.NewRequest(http.MethodGet, origin.URL+"/", nil)
	// authorityMatches needs the port too — origin listens on a random
	// ephemeral port, not the http-default 80 that a bare host would
	// normalize to, so leaving the port off here would reject the request
	// as misdirected before ever reaching resp.Write, never exercising the
	// branch this test is actually about.
	req.Host = originAddr

	done := make(chan bool, 1)
	go func() {
		done <- h.handleOneRequest(
			context.Background(),
			session.Session{Client: netip.MustParseAddrPort("127.0.0.1:12345")},
			proxy, &http.Transport{}, bufio.NewReader(proxy),
			rules.ConnInput{Host: originHost, Port: originPort, Proto: "http"}, originAddr, req,
			"",
		)
	}()

	select {
	case keep := <-done:
		if keep {
			t.Fatalf("client-write-error kept the connection alive")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("handleOneRequest did not return after the client conn was already closed")
	}
}

// TestHandleOneRequest_WebSocketUpgrade_H1FallbackDialFails covers the
// upgrade-fallback-connect-fail branch: a WebSocket Upgrade request arriving
// on a shared h2 upstream must fall back to a dedicated h1-only connection
// (h2 structurally can't carry Upgrade — RFC 9113 §8.5); when that fallback
// dial itself fails, the client must get a classified error response, not a
// silent hang waiting on an h2 stream that was never going to work anyway.
func TestHandleOneRequest_WebSocketUpgrade_H1FallbackDialFails(t *testing.T) {
	h, _ := newHappyPathHandler(t)
	// recordingDialer.DialTLSH1Only always errors — exactly the dial
	// H1Fallback makes.
	upstream := &h2RoundTripper{dialer: &recordingDialer{}, dst: "allowed.example:443", sni: "allowed.example", readTimeout: 5 * time.Second, maxHeaderListSize: 64 << 10}

	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()

	req, _ := http.NewRequest(http.MethodGet, "https://allowed.example/ws", nil)
	req.Host = "allowed.example"
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")

	done := make(chan bool, 1)
	go func() {
		done <- h.handleOneRequest(
			context.Background(),
			session.Session{Client: netip.MustParseAddrPort("127.0.0.1:12345")},
			proxy, upstream, bufio.NewReader(proxy),
			rules.ConnInput{Host: "allowed.example", Port: "443", Proto: "https"}, "allowed.example:443", req,
			"",
		)
	}()

	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if keep := <-done; keep {
		t.Fatalf("h1-fallback dial failure kept the connection alive")
	}
	if resp.StatusCode != http.StatusBadGateway && resp.StatusCode != 521 {
		t.Fatalf("status = %d, want a classified upstream-failure status (521/502)", resp.StatusCode)
	}
}
