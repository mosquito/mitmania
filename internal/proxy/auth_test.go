package proxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"mitmania/internal/outcall"
	"mitmania/internal/rules"
	"mitmania/internal/session"
	"mitmania/internal/storage"
)

func testArgon2Hash(password string) string {
	salt := []byte("0123456789abcdef")
	sum := argon2.IDKey([]byte(password), salt, 3, 65536, 4, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum))
}

func testBearerHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// newTestHandlerWithStore is newTestHandler but also returns the
// underlying *rules.RuleStore, for tests that need direct store access
// beyond the one IP-keyed rule file newTestHandler seeds (e.g. to also
// PUT a rules/default table).
func newTestHandlerWithStore(t *testing.T, ruleJSON string) (*Http1Handler, []byte, *rules.RuleStore) {
	t.Helper()
	factory, ca := newTestFactory(t)
	caPEM := pemEncodeCert(ca.Cert.Raw)

	st, err := storage.NewPosixStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewPosixStorage: %v", err)
	}
	store := rules.NewRuleStore(st)
	if ruleJSON != "" {
		if err := store.Save(context.Background(), netip.MustParseAddr("127.0.0.1"), []byte(ruleJSON)); err != nil {
			t.Fatalf("store.Save: %v", err)
		}
	}

	handler := &Http1Handler{
		TLS:                 &TLSService{Factory: factory},
		Rules:               rules.NewRuleEngine(store),
		CAPEM:               caPEM,
		HeaderLimit:         64 << 10,
		BodyWindow:          64 << 10,
		HTTP2ConnectTimeout: 5 * time.Second,
		HTTP2ConnectTries:   3,
		HTTP2ReadTimeout:    5 * time.Second,
	}
	return handler, caPEM, store
}

// connectRaw sends a raw CONNECT with extra headers to proxyAddr and
// returns the parsed response without asserting its status — callers
// check 200 vs 407 vs whatever themselves.
func connectRaw(t *testing.T, proxyAddr, target string, headers map[string]string) *http.Response {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	var buf strings.Builder
	fmt.Fprintf(&buf, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	for k, v := range headers {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
	}
	buf.WriteString("\r\n")
	if _, err := conn.Write([]byte(buf.String())); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	return resp
}

func TestAuth_Connect_NoCredentialRequires407(t *testing.T) {
	rule := fmt.Sprintf(`{"http":[{"match":{}}],
	  "auth":{"http_proxy":{"required":true,"realm":"testrealm",
	    "basic":[{"user":"alice","hash":%q}]}}}`, testArgon2Hash("s3cret"))
	handler, _ := newTestHandler(t, rule)
	proxyAddr := runProxy(t, handler)

	resp := connectRaw(t, proxyAddr, "example.com:443", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); !strings.Contains(got, `Basic realm="testrealm"`) {
		t.Fatalf("Proxy-Authenticate = %q, want a Basic realm=\"testrealm\" challenge", got)
	}
}

func TestAuth_Connect_BasicWrongPasswordFails407(t *testing.T) {
	rule := fmt.Sprintf(`{"http":[{"match":{}}],
	  "auth":{"http_proxy":{"required":true,
	    "basic":[{"user":"alice","hash":%q}]}}}`, testArgon2Hash("s3cret"))
	handler, _ := newTestHandler(t, rule)
	proxyAddr := runProxy(t, handler)

	cred := base64.StdEncoding.EncodeToString([]byte("alice:wrong-password"))
	resp := connectRaw(t, proxyAddr, "example.com:443", map[string]string{"Proxy-Authorization": "Basic " + cred})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
}

func TestAuth_Connect_BasicCorrectSucceeds(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	rule := fmt.Sprintf(`{"http":[{"match":{}}],
	  "auth":{"http_proxy":{"required":true,
	    "basic":[{"user":"alice","hash":%q}]}}}`, testArgon2Hash("s3cret"))
	handler, _ := newTestHandler(t, rule)
	proxyAddr := runProxy(t, handler)

	cred := base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	target := origin.Listener.Addr().String()
	resp := connectRaw(t, proxyAddr, target, map[string]string{"Proxy-Authorization": "Basic " + cred})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (auth succeeded, tunnel established)", resp.StatusCode)
	}
}

func TestAuth_Connect_BearerCorrectSucceeds(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	rule := fmt.Sprintf(`{"http":[{"match":{}}],
	  "auth":{"http_proxy":{"required":true,
	    "bearer":[{"id":"ci-bot","hash":%q}]}}}`, testBearerHash("tok-good"))
	handler, _ := newTestHandler(t, rule)
	proxyAddr := runProxy(t, handler)

	target := origin.Listener.Addr().String()
	resp := connectRaw(t, proxyAddr, target, map[string]string{"Proxy-Authorization": "Bearer tok-good"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestAuth_Connect_BearerWrongTokenFails407(t *testing.T) {
	rule := fmt.Sprintf(`{"http":[{"match":{}}],
	  "auth":{"http_proxy":{"required":true,
	    "bearer":[{"id":"ci-bot","hash":%q}]}}}`, testBearerHash("tok-good"))
	handler, _ := newTestHandler(t, rule)
	proxyAddr := runProxy(t, handler)

	resp := connectRaw(t, proxyAddr, "example.com:443", map[string]string{"Proxy-Authorization": "Bearer tok-bad"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
}

// TestAuth_AbsoluteForm_ProxyAuthorizationStrippedFromUpstream verifies
// that Proxy-Authorization is hop-by-hop — consumed and stripped, never
// forwarded upstream — on the absolute-form path, where req is the
// same *http.Request object handed to the upstream RoundTrip.
func TestAuth_AbsoluteForm_ProxyAuthorizationStrippedFromUpstream(t *testing.T) {
	var gotProxyAuth string
	var sawHeader bool
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProxyAuth = r.Header.Get("Proxy-Authorization")
		_, sawHeader = r.Header["Proxy-Authorization"]
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	rule := fmt.Sprintf(`{"http":[{"match":{}}],
	  "auth":{"http_proxy":{"required":true,
	    "basic":[{"user":"alice","hash":%q}]}}}`, testArgon2Hash("s3cret"))
	handler, _ := newTestHandler(t, rule)
	proxyAddr := runProxy(t, handler)

	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword("alice", "s3cret")}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if sawHeader || gotProxyAuth != "" {
		t.Fatalf("origin saw Proxy-Authorization = %q (present=%v), want it stripped entirely", gotProxyAuth, sawHeader)
	}
}

func TestAuth_AbsoluteForm_NoCredentialRequires407(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("origin reached despite missing auth credential")
	}))
	defer origin.Close()

	rule := fmt.Sprintf(`{"http":[{"match":{}}],
	  "auth":{"http_proxy":{"required":true,
	    "basic":[{"user":"alice","hash":%q}]}}}`, testArgon2Hash("s3cret"))
	handler, _ := newTestHandler(t, rule)
	proxyAddr := runProxy(t, handler)

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr})}}
	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
}

// TestAuth_AccessLogRecordsPrincipal verifies the access-log invariant:
// the authenticated principal appears on the record once auth succeeds.
// Uses a mitm:false rule so the access record is written right after the
// CONNECT succeeds (the "splice (mitm:false)" outcome), without this
// test needing to also drive a real TLS handshake through the tunnel.
func TestAuth_AccessLogRecordsPrincipal(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	rule := fmt.Sprintf(`{"http":[{"match":{},"mitm":false}],
	  "auth":{"http_proxy":{"required":true,
	    "basic":[{"user":"alice","hash":%q}]}}}`, testArgon2Hash("s3cret"))
	handler, _ := newTestHandler(t, rule)
	buf := &syncBuffer{}
	handler.Logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxyAddr := runProxy(t, handler)

	cred := base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	target := origin.Listener.Addr().String()
	// Once the CONNECT succeeds, the connection is a raw tunnel (mitm:false
	// splices it to origin immediately) — there's no bounded "body" to
	// read here the way a normal HTTP response has one, so don't try;
	// just check the status and let t.Cleanup's conn.Close() (registered
	// inside connectRaw) tear the splice down once this test returns.
	resp := connectRaw(t, proxyAddr, target, map[string]string{"Proxy-Authorization": "Basic " + cred})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	got := waitForSubstring(t, buf, "principal=alice")
	if !strings.Contains(got, "splice (mitm:false)") {
		t.Fatalf("access log missing the splice outcome alongside principal: %q", got)
	}
}

// TestAuth_NeverChangesGoverningRuleFile verifies the data-plane
// principle: a successful auth.http_proxy credential authenticates the
// connection but never changes which rule file governs it — proven by
// seeding a rules/default bucket with a distinguishable header injection
// alongside the IP file's own (different) one, and observing that only
// the IP file's takes effect even after a successful login.
func TestAuth_NeverChangesGoverningRuleFile(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Echo-From", r.Header.Get("X-From"))
	}))
	defer origin.Close()

	ipRule := fmt.Sprintf(`{
	  "auth":{"http_proxy":{"required":true,
	    "basic":[{"user":"alice","hash":%q}]}},
	  "http":[{"match":{},"request":[{"action":"header.add","params":{"X-From":"ip-file"}}]}]
	}`, testArgon2Hash("s3cret"))
	handler, _, store := newTestHandlerWithStore(t, ipRule)
	// A rules/default bucket covering this same address also exists, with
	// a distinguishable injection of its own — a successful login must
	// never fall through to it in place of the IP file.
	defaultBlob := `{"0.0.0.0/0":{"http":[{"match":{},
	  "request":[{"action":"header.add","params":{"X-From":"default-bucket"}}]}],
	  "egress":[{"cidr":"0.0.0.0/0","action":"allow"},{"cidr":"::/0","action":"allow"}]},
	  "::/0":{"http":[],"egress":[{"cidr":"0.0.0.0/0","action":"allow"},{"cidr":"::/0","action":"allow"}]}}`
	if err := store.SaveDefault(context.Background(), []byte(defaultBlob)); err != nil {
		t.Fatalf("SaveDefault: %v", err)
	}

	proxyAddr := runProxy(t, handler)
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword("alice", "s3cret")}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Echo-From"); got != "ip-file" {
		t.Fatalf("X-From reaching origin = %q, want \"ip-file\" (auth must never change which rule file governs)", got)
	}
}

// TestAuth_TransparentListenerFailsClosedWhenRequired verifies that
// auth.http_proxy.required:true reached over a non-explicit transport
// fails closed (403/ERR_FORWARDING_DENIED) rather than silently serving
// unauthenticated.
func TestAuth_TransparentListenerFailsClosedWhenRequired(t *testing.T) {
	rule := fmt.Sprintf(`{"http":[{"match":{}}],
	  "auth":{"http_proxy":{"required":true,
	    "basic":[{"user":"alice","hash":%q}]}}}`, testArgon2Hash("s3cret"))
	handler, _ := newTestHandler(t, rule)

	client, srv := net.Pipe()
	defer client.Close()
	sess := session.Session{
		Client:    netip.MustParseAddrPort("127.0.0.1:12345"),
		Dst:       netip.MustParseAddrPort("93.184.216.34:80"), // a real Acceptor always fills this in; a zero Dst is not a real scenario
		Transport: session.TransportTProxy,
		Conn:      srv,
		Acceptor:  "http_tproxy",
	}
	dialer := NewUpstreamDialer(2*time.Second, 1)
	done := make(chan struct{})
	go func() {
		handler.Serve(context.Background(), sess, dialer)
		close(done)
	}()

	fmt.Fprintf(client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	// Drain the body over net.Pipe's unbuffered, synchronous Write before
	// checking anything — httperror.WriteResponse's second Write (the
	// body) blocks until read, and nothing else here ever reads it; a
	// deferred-but-unread Close wouldn't unblock the writer either, so
	// Serve (and this test's <-done below) would deadlock without this.
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (ERR_FORWARDING_DENIED, fail-closed on a transparent listener)", resp.StatusCode)
	}
	<-done
}

// TestAuth_BrokerScheme_AllowsAndAdoptsPrincipal verifies the auth
// broker scheme: the credential is forwarded to the broker, and a 2xx
// reply's principal is adopted.
func TestAuth_BrokerScheme_AllowsAndAdoptsPrincipal(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	broker, lastReq := brokerServer(t, func(req outcall.Request) (int, outcall.Response) {
		return http.StatusOK, outcall.Response{Principal: "broker-alice"}
	})

	rule := fmt.Sprintf(`{"http":[{"match":{}}],
	  "auth":{"http_proxy":{"required":true,"broker":{"url":%q}}}}`, broker.URL)
	handler, _ := newTestHandler(t, rule)
	handler = withOutcall(handler)
	proxyAddr := runProxy(t, handler)

	target := origin.Listener.Addr().String()
	resp := connectRaw(t, proxyAddr, target, map[string]string{"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:whatever"))})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if lastReq.Action != outcall.ActionAuth {
		t.Errorf("broker saw action %q, want %q", lastReq.Action, outcall.ActionAuth)
	}
	if lastReq.Credential == nil || lastReq.Credential.Scheme != "Basic" {
		t.Errorf("broker credential = %+v, want scheme=Basic", lastReq.Credential)
	}
}

func TestAuth_BrokerScheme_DeniedFails407(t *testing.T) {
	broker, _ := brokerServer(t, func(req outcall.Request) (int, outcall.Response) {
		return http.StatusForbidden, outcall.Response{Message: "no"}
	})

	rule := fmt.Sprintf(`{"http":[{"match":{}}],
	  "auth":{"http_proxy":{"required":true,"broker":{"url":%q}}}}`, broker.URL)
	handler, _ := newTestHandler(t, rule)
	handler = withOutcall(handler)
	proxyAddr := runProxy(t, handler)

	resp := connectRaw(t, proxyAddr, "example.com:443", map[string]string{"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:whatever"))})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
}
