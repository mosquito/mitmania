package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"mitmania/internal/rules"
	"mitmania/internal/storage"
)

// syncBuffer is a mutex-guarded bytes.Buffer for tests that assert on
// access-log output written by a proxy handler running on its own
// goroutine — a plain bytes.Buffer races because logAccess (server
// goroutine) can still be writing the record after the client has already
// read the full HTTP response (response bytes reaching the client says
// nothing about whether server-side post-response logging has run yet).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitForSubstring polls b for substr, giving the server goroutine time to
// finish writing its access-log record asynchronously relative to the
// client having already read the response.
func waitForSubstring(t *testing.T, b *syncBuffer, substr string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		last = b.String()
		if strings.Contains(last, substr) {
			return last
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for access log to contain %q: %q", substr, last)
	return ""
}

func prefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		out[i] = netip.MustParsePrefix(c)
	}
	return out
}

func TestIsTrustedPeer(t *testing.T) {
	trusted := prefixes("10.0.0.0/8", "2001:db8::/32")

	tests := []struct {
		addr string
		want bool
	}{
		{"10.1.2.3", true},
		{"192.0.2.1", false},
		{"2001:db8::1", true},
		{"2001:db9::1", false},
	}
	for _, tt := range tests {
		got := isTrustedPeer(netip.MustParseAddr(tt.addr), trusted)
		if got != tt.want {
			t.Errorf("isTrustedPeer(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestRecoverClientIP_UntrustedPeerIgnoresHeaders(t *testing.T) {
	peer := netip.MustParseAddr("203.0.113.9")
	header := http.Header{"X-Forwarded-For": {"198.51.100.1"}}
	got := recoverClientIP(peer, header, prefixes("10.0.0.0/8"))
	if got != peer {
		t.Fatalf("got %v, want peer %v verbatim (peer not trusted)", got, peer)
	}
}

func TestRecoverClientIP_NoTrustedProxiesConfigured(t *testing.T) {
	peer := netip.MustParseAddr("127.0.0.1")
	header := http.Header{"X-Forwarded-For": {"198.51.100.1"}}
	got := recoverClientIP(peer, header, nil)
	if got != peer {
		t.Fatalf("got %v, want peer %v verbatim (no trusted proxies)", got, peer)
	}
}

func TestRecoverClientIP_TrustedPeerRightmostUntrustedHop(t *testing.T) {
	peer := netip.MustParseAddr("10.0.0.1")
	trusted := prefixes("10.0.0.0/8")
	header := http.Header{"X-Forwarded-For": {"198.51.100.1, 10.0.0.2"}}
	got := recoverClientIP(peer, header, trusted)
	want := netip.MustParseAddr("198.51.100.1")
	if got != want {
		t.Fatalf("got %v, want %v (right-most untrusted hop)", got, want)
	}
}

func TestRecoverClientIP_SkipsAllTrustedHopsFromTheRight(t *testing.T) {
	peer := netip.MustParseAddr("10.0.0.1")
	trusted := prefixes("10.0.0.0/8")
	// Two trusted hops appended on the right; the real client is further left.
	header := http.Header{"X-Forwarded-For": {"198.51.100.1, 10.0.0.5, 10.0.0.2"}}
	got := recoverClientIP(peer, header, trusted)
	want := netip.MustParseAddr("198.51.100.1")
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRecoverClientIP_ClientCannotSpoofByPreseedingXFF(t *testing.T) {
	// A malicious client pre-seeds its own XFF with a fake identity, but
	// the client's own hop (right-most, since XFF is appended-to, not
	// prepended-to) is what a trusted proxy would have added — the fake
	// left-most entry must never be trusted just because it's present.
	peer := netip.MustParseAddr("10.0.0.1") // the trusted LB
	trusted := prefixes("10.0.0.0/8")
	header := http.Header{"X-Forwarded-For": {"6.6.6.6, 198.51.100.1"}}
	got := recoverClientIP(peer, header, trusted)
	want := netip.MustParseAddr("198.51.100.1")
	if got != want {
		t.Fatalf("got %v, want %v (spoofed left-most hop must be ignored)", got, want)
	}
}

func TestRecoverClientIP_MultipleXFFHeaderLinesJoinedInOrder(t *testing.T) {
	peer := netip.MustParseAddr("10.0.0.1")
	trusted := prefixes("10.0.0.0/8")
	header := http.Header{"X-Forwarded-For": {"198.51.100.1", "10.0.0.2"}}
	got := recoverClientIP(peer, header, trusted)
	want := netip.MustParseAddr("198.51.100.1")
	if got != want {
		t.Fatalf("got %v, want %v (multiple header lines treated as one ordered list)", got, want)
	}
}

func TestRecoverClientIP_FallsBackToXRealIP(t *testing.T) {
	peer := netip.MustParseAddr("10.0.0.1")
	trusted := prefixes("10.0.0.0/8")
	header := http.Header{}
	header.Set("X-Real-IP", "198.51.100.1")
	got := recoverClientIP(peer, header, trusted)
	want := netip.MustParseAddr("198.51.100.1")
	if got != want {
		t.Fatalf("got %v, want %v (X-Real-IP fallback)", got, want)
	}
}

func TestRecoverClientIP_FallsBackToPeerWhenNoUsableHeader(t *testing.T) {
	peer := netip.MustParseAddr("10.0.0.1")
	trusted := prefixes("10.0.0.0/8")
	got := recoverClientIP(peer, http.Header{}, trusted)
	if got != peer {
		t.Fatalf("got %v, want peer %v verbatim", got, peer)
	}
}

func TestRecoverClientIP_IPv6TrustedPeerAndIPv6RealClient(t *testing.T) {
	peer := netip.MustParseAddr("2001:db8::1") // trusted fronting LB, IPv6
	trusted := prefixes("2001:db8::/64")       // narrow enough that the real client (a different /64) falls outside it
	header := http.Header{"X-Forwarded-For": {"2001:db8:1::42, 2001:db8::2"}}
	got := recoverClientIP(peer, header, trusted)
	want := netip.MustParseAddr("2001:db8:1::42")
	if got != want {
		t.Fatalf("got %v, want %v (IPv6 real client behind IPv6 trusted proxy)", got, want)
	}
}

func TestRecoverClientIP_MixedFamilyChain(t *testing.T) {
	// IPv4 peer, but the chain records an IPv6 real client (outside the
	// trusted IPv6 range) behind a dual-stack trusted proxy hop.
	peer := netip.MustParseAddr("10.0.0.1")
	trusted := prefixes("10.0.0.0/8", "2001:db8::/32")
	header := http.Header{"X-Forwarded-For": {"2001:db9:1::99, 2001:db8::5, 10.0.0.2"}}
	got := recoverClientIP(peer, header, trusted)
	want := netip.MustParseAddr("2001:db9:1::99")
	if got != want {
		t.Fatalf("got %v, want %v (mixed-family chain, IPv6 real client)", got, want)
	}
}

func TestRecoverClientIP_BareIPv6TrustedProxyLiteral(t *testing.T) {
	// A --trusted-proxies entry naming a single IPv6 address (parsed by
	// config.ParseTrustedProxies as a /128) must still match that exact
	// peer.
	peer := netip.MustParseAddr("2001:db8::1")
	trusted := prefixes("2001:db8::1/128")
	header := http.Header{"X-Forwarded-For": {"198.51.100.1"}}
	got := recoverClientIP(peer, header, trusted)
	want := netip.MustParseAddr("198.51.100.1")
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRecoverClientIP_IgnoresUnparseableHops(t *testing.T) {
	peer := netip.MustParseAddr("10.0.0.1")
	trusted := prefixes("10.0.0.0/8")
	header := http.Header{"X-Forwarded-For": {"198.51.100.1, garbage, 10.0.0.2"}}
	got := recoverClientIP(peer, header, trusted)
	want := netip.MustParseAddr("198.51.100.1")
	if got != want {
		t.Fatalf("got %v, want %v (unparseable hop skipped, not treated as untrusted-and-real)", got, want)
	}
}

// TestHTTP1Handler_ServeRecoversClientIPFromTrustedXFF verifies the whole
// path end to end: TrustedProxies wired onto Http1Handler, a real
// connection from the trusted loopback peer, and an X-Forwarded-For header
// naming the real client — the access log (keyed off the post-recovery
// sess.Client) must show the recovered address, not the raw peer.
func TestHTTP1Handler_ServeRecoversClientIPFromTrustedXFF(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}))
	defer origin.Close()

	buf := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Rules key on the (post-recovery) client identity, so the recovered
	// IPv6 address needs its own permissive rule file — build the handler
	// by hand (rather than newHappyPathHandler, which only seeds
	// 127.0.0.1) to save one for it.
	factory, ca := newTestFactory(t)
	st, err := storage.NewPosixStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewPosixStorage: %v", err)
	}
	store := rules.NewRuleStore(st)
	if err := store.SaveDefault(context.Background(), []byte(testPermissiveDefault)); err != nil {
		t.Fatalf("store.SaveDefault: %v", err)
	}
	if err := store.Save(context.Background(), netip.MustParseAddr("2001:db8::dead:beef"), []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatalf("Save rule for recovered client: %v", err)
	}
	handler := &Http1Handler{
		TLS:            &TLSService{Factory: factory},
		Rules:          rules.NewRuleEngine(store),
		CAPEM:          pemEncodeCert(ca.Cert.Raw),
		HeaderLimit:    64 << 10,
		BodyWindow:     64 << 10,
		Logger:         log,
		TrustedProxies: prefixes("127.0.0.1/32"),
	}
	proxyAddr := runProxy(t, handler)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req, _ := http.NewRequest(http.MethodGet, origin.URL+"/", nil)
	req.Header.Set("X-Forwarded-For", "2001:db8::dead:beef")
	if err := req.WriteProxy(conn); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	got := waitForSubstring(t, buf, "client=2001:db8::dead:beef")
	if strings.Contains(got, "client=127.0.0.1") {
		t.Fatalf("access log still shows the raw trusted-proxy peer instead of the recovered client: %q", got)
	}
}

// TestHTTP1Handler_ServeIgnoresXFFFromUntrustedPeer is the negative
// counterpart: without TrustedProxies configured (this session's default),
// a client-supplied X-Forwarded-For must never override the real
// peer identity — otherwise any client could spoof its own rule-file key.
func TestHTTP1Handler_ServeIgnoresXFFFromUntrustedPeer(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}))
	defer origin.Close()

	buf := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	handler, _ := newHappyPathHandler(t)
	handler.Logger = log
	// TrustedProxies left nil/empty: recovery disabled entirely.
	proxyAddr := runProxy(t, handler)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req, _ := http.NewRequest(http.MethodGet, origin.URL+"/", nil)
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	if err := req.WriteProxy(conn); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	got := waitForSubstring(t, buf, "client=127.0.0.1")
	if strings.Contains(got, "client=6.6.6.6") {
		t.Fatalf("access log trusted a client-supplied XFF with no --trusted-proxies configured: %q", got)
	}
}
