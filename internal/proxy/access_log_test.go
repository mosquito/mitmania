package proxy

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"mitmania/internal/session"
)

func TestHttp1Handler_NoAccessLogSuppressesAccessRecordsOnly(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	sess := session.Session{Client: netip.MustParseAddrPort("127.0.0.1:12345")}

	h := &Http1Handler{Logger: log, NoAccessLog: true}
	h.logAccessErr(sess, "GET", "https://example.com/", "ok", 200, reqTrace{start: time.Now()}, errors.New("boom"))
	if buf.Len() != 0 {
		t.Fatalf("NoAccessLog:true still wrote an access record: %q", buf.String())
	}

	// Logger itself is untouched by NoAccessLog — anything else that logs
	// through it directly (e.g. an upstream roundtripper's reconnect
	// debug logging) must still work.
	log.Debug("upstream reconnect", "dst", "example.com:443")
	if !strings.Contains(buf.String(), "upstream reconnect") {
		t.Fatalf("NoAccessLog:true incorrectly silenced non-access-log records: %q", buf.String())
	}

	buf.Reset()
	h.NoAccessLog = false
	h.logAccessErr(sess, "GET", "https://example.com/", "ok", 200, reqTrace{start: time.Now()}, nil)
	if !strings.Contains(buf.String(), "outcome=ok") {
		t.Fatalf("NoAccessLog:false did not write an access record: %q", buf.String())
	}
}

func TestHttp1Handler_AccessLogIncludesResolvedDst(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	sess := session.Session{Client: netip.MustParseAddrPort("127.0.0.1:12345")}
	h := &Http1Handler{Logger: log}

	treq := reqTrace{start: time.Now()}
	treq.withDst("93.184.216.34:443")
	h.logAccess(sess, "GET", "https://example.com/", "ok", 200, treq)

	if !strings.Contains(buf.String(), "dst=93.184.216.34:443") {
		t.Fatalf("access log missing resolved dst: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "url=https://example.com/") {
		t.Fatalf("access log lost the domain-based url after adding dst: %q", buf.String())
	}
}

func TestHttp1Handler_AccessLogOmitsDstWhenNeverResolved(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	sess := session.Session{Client: netip.MustParseAddrPort("127.0.0.1:12345")}
	h := &Http1Handler{Logger: log}

	// An early failure (e.g. invalid request) never reaches the
	// resolve-phase — dst must not appear at all, not as an empty field.
	h.logAccess(sess, "", "", "invalid-request", 400, reqTrace{start: time.Now()})

	if strings.Contains(buf.String(), "dst=") {
		t.Fatalf("access log has a dst field despite dst never being resolved: %q", buf.String())
	}
}

func TestHttp1Handler_AccessLogIncludesResolvedDstIPv6(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	sess := session.Session{Client: netip.MustParseAddrPort("127.0.0.1:12345")}
	h := &Http1Handler{Logger: log}

	treq := reqTrace{start: time.Now()}
	treq.withDst("[2606:2800:220:1:248:1893:25c8:1946]:443")
	h.logAccess(sess, "GET", "https://example.com/", "ok", 200, treq)

	if !strings.Contains(buf.String(), "dst=[2606:2800:220:1:248:1893:25c8:1946]:443") {
		t.Fatalf("access log missing resolved IPv6 dst: %q", buf.String())
	}
}

// TestHttp1Handler_EmptyConnectionLogged proves an explicit-proxy
// connection that closes before sending a single byte — a health check,
// or a client racing several connections and abandoning the losers —
// logs the distinct "empty-connection" outcome rather than
// "invalid-request", which would wrongly suggest the client sent
// something malformed.
func TestHttp1Handler_EmptyConnectionLogged(t *testing.T) {
	handler, _ := newHappyPathHandler(t)
	buf := &syncBuffer{}
	handler.Logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxyAddr := runProxy(t, handler)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close() // no bytes ever written

	log := waitForSubstring(t, buf, "outcome=")
	if !strings.Contains(log, "outcome=empty-connection") {
		t.Fatalf("outcome = %q, want empty-connection", log)
	}
	if strings.Contains(log, "outcome=invalid-request") {
		t.Fatalf("a connection with zero bytes sent was logged as invalid-request, not empty-connection: %q", log)
	}
}

// TestHttp1Handler_ClientReadTimeoutLogged proves a client that opens an
// explicit-proxy connection and never sends a complete request within
// ClientReadTimeout gets a distinct "client-read-timeout" outcome — not
// left to hang forever (the historical, unbounded behavior) and not
// misclassified as an ordinary parse failure.
func TestHttp1Handler_ClientReadTimeoutLogged(t *testing.T) {
	handler, _ := newHappyPathHandler(t)
	handler.ClientReadTimeout = 50 * time.Millisecond
	buf := &syncBuffer{}
	handler.Logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxyAddr := runProxy(t, handler)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	conn.Write([]byte("GET / HTTP/1.1\r\n")) // incomplete: no terminating blank line

	log := waitForSubstring(t, buf, "outcome=")
	if !strings.Contains(log, "outcome=client-read-timeout") {
		t.Fatalf("outcome = %q, want client-read-timeout", log)
	}
}
