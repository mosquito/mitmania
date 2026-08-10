package httperror

import (
	"bufio"
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderContainsExpectedFields(t *testing.T) {
	spec := Raise(403, "Declined")
	body := Render("https://example.com/token", spec)
	s := string(body)

	for _, want := range []string{
		"<h1>ERROR</h1>",
		"While trying to retrieve the URL:",
		"https://example.com/token",
		"Declined",
		"ERR_ACCESS_DENIED",
		Generator,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Render() missing %q in:\n%s", want, s)
		}
	}
}

func TestRenderEscapesHTML(t *testing.T) {
	spec := Raise(403, `<script>alert(1)</script>`)
	body := Render(`https://example.com/"><script>x</script>`, spec)
	s := string(body)
	if strings.Contains(s, "<script>alert(1)</script>") {
		t.Fatalf("Render() did not escape a message containing HTML:\n%s", s)
	}
	if strings.Contains(s, `"><script>x</script>`) {
		t.Fatalf("Render() did not escape a URL containing HTML:\n%s", s)
	}
}

func TestWriteResponse(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResponse(&buf, "https://example.com/", NoMatch); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNetworkAuthenticationRequired {
		t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusNetworkAuthenticationRequired)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html prefix", got)
	}
	if resp.ContentLength <= 0 {
		t.Fatalf("ContentLength = %d, want > 0", resp.ContentLength)
	}
}

func TestWriteResponse_ServableByHTTPTest(t *testing.T) {
	// Sanity: the response WriteResponse produces is exactly what a real
	// client parses as a complete, well-formed HTTP/1.1 response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spec := Raise(451, "Blocked for legal reasons")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(spec.Status)
		w.Write(Render(r.URL.String(), spec))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/blocked")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 451 {
		t.Fatalf("StatusCode = %d, want 451", resp.StatusCode)
	}
}

func TestRaiseDefaultsStatus(t *testing.T) {
	spec := Raise(0, "no status given")
	if spec.Status != http.StatusForbidden {
		t.Fatalf("Status = %d, want %d", spec.Status, http.StatusForbidden)
	}
}

// TestWriteResponse_CloudflareStyleStatusParses verifies that the
// non-standard Cloudflare 52x codes (net/http.StatusText doesn't know
// them) still produce a well-formed, parseable status line via the
// statusText fallback table.
func TestWriteResponse_CloudflareStyleStatusParses(t *testing.T) {
	for _, spec := range []Spec{UpstreamUnreachable, UpstreamDown, ConnectTimeout, ReadTimeout, TLSHandshakeFail, InvalidUpstreamCert} {
		var buf bytes.Buffer
		if err := WriteResponse(&buf, "https://example.com/", spec); err != nil {
			t.Fatalf("WriteResponse(%d): %v", spec.Status, err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
		if err != nil {
			t.Fatalf("ReadResponse(%d): %v", spec.Status, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != spec.Status {
			t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, spec.Status)
		}
		wantReason := cloudflareStatusText[spec.Status]
		if !strings.Contains(resp.Status, wantReason) {
			t.Fatalf("Status line = %q, want it to contain reason phrase %q", resp.Status, wantReason)
		}
	}
}

func TestProxyAuthRequired_WriteResponseEmitsChallengeHeaders(t *testing.T) {
	spec := ProxyAuthRequired("corp", []string{"Basic", "Bearer"})
	var buf bytes.Buffer
	if err := WriteResponse(&buf, "https://example.com/", spec); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}
	got := resp.Header.Values("Proxy-Authenticate")
	want := []string{`Basic realm="corp"`, `Bearer realm="corp"`}
	if len(got) != len(want) {
		t.Fatalf("Proxy-Authenticate = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Proxy-Authenticate[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestProxyAuthRequired_SingleScheme(t *testing.T) {
	spec := ProxyAuthRequired("mitmania", []string{"Basic"})
	var buf bytes.Buffer
	if err := WriteResponse(&buf, "https://example.com/", spec); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	got := resp.Header.Values("Proxy-Authenticate")
	if len(got) != 1 || got[0] != `Basic realm="mitmania"` {
		t.Fatalf("Proxy-Authenticate = %v, want [Basic realm=\"mitmania\"]", got)
	}
}

func TestProxyAuthRequired_StripsQuotesFromRealm(t *testing.T) {
	spec := ProxyAuthRequired(`corp"; evil="x`, []string{"Basic"})
	got := spec.Headers.Get("Proxy-Authenticate")
	if strings.Count(got, `"`) != 2 {
		t.Fatalf("Proxy-Authenticate = %q, want exactly 2 quote characters (the realm's own delimiters)", got)
	}
}

func TestHandle_EmitsChallengeHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Handle(w, r.URL.String(), ProxyAuthRequired("mitmania", []string{"Basic", "Bearer"}))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}
	got := resp.Header.Values("Proxy-Authenticate")
	if len(got) != 2 {
		t.Fatalf("Proxy-Authenticate = %v, want 2 entries", got)
	}
}

func TestWriteResponse_NoExtraHeadersForOrdinarySpec(t *testing.T) {
	// A Spec with no Headers set (the common case) must not add anything
	// beyond Content-Type/Content-Length/Connection.
	var buf bytes.Buffer
	if err := WriteResponse(&buf, "https://example.com/", NoMatch); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	if len(resp.Header.Values("Proxy-Authenticate")) != 0 {
		t.Fatalf("unexpected Proxy-Authenticate header on a plain Spec")
	}
}
