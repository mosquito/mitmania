// Package httperror renders Http1Handler's Squid-style synthetic error
// responses: every mitmania-generated HTTP response (raise, no rule
// match, upstream failures) shares the same ERROR-page layout, with a
// status code and an ERR_* code identifying the case.
//
// This is HTTP/1.1-specific, not a generic multi-protocol facility —
// other protocols get their own error form (e.g. SMTP 5xx, a bare
// connection reset), not this page.
package httperror

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Generator identifies as squid in the page footer.
const Generator = "squid"

// Spec describes one synthetic response — the SynthResp field a rule
// engine Verdict carries when it short-circuits a request
// (Verdict{ShortCircuit, Resp *SynthResp}).
type Spec struct {
	Status  int
	ErrCode string
	Message string

	// Headers carries extra response headers beyond Content-Type/
	// Content-Length/Connection (which WriteResponse/Handle always set
	// themselves) — currently just the 407 proxy-auth challenge's
	// Proxy-Authenticate header.
	// nil for every other Spec.
	Headers http.Header
}

// The fixed cases in Squid's ERR_* vocabulary that mitmania mirrors.
// NoMatch is the connection-phase "no rule matched" fallback: 511.
// Upstream failures use Cloudflare-style 52x granularity — self-
// documenting in logs/metrics; an unrecognized 5xx is treated as a generic
// server error by clients regardless, and we render our own page anyway.
var (
	NoMatch = Spec{
		Status:  http.StatusNetworkAuthenticationRequired, // 511
		ErrCode: "ERR_ACCESS_DENIED",
		Message: "No rule matched this request.",
	}

	// InvalidRequest: malformed request line/headers, or a request shape
	// that doesn't fit proxy semantics (e.g. origin-form outside a tunnel).
	InvalidRequest = Spec{
		Status:  http.StatusBadRequest, // 400
		ErrCode: "ERR_INVALID_REQ",
		Message: "Invalid or malformed request.",
	}
	// HeadersTooLarge: the --http-header-limit bound tripped by the
	// header block.
	HeadersTooLarge = Spec{
		Status:  http.StatusRequestHeaderFieldsTooLarge, // 431
		ErrCode: "ERR_TOO_BIG",
		Message: "Request headers too large.",
	}
	// RequestTimeout: the client itself (not the upstream — see
	// ReadTimeout below) took longer than --http-timeout-client-read to
	// deliver a complete request/ClientHello.
	RequestTimeout = Spec{
		Status:  http.StatusRequestTimeout, // 408
		ErrCode: "ERR_REQUEST_TIMEOUT",
		Message: "Timed out waiting for the request.",
	}
	// URITooLarge: not wired to any current caller (--http-header-limit
	// only bounds the header block, not the request line/URI
	// separately) — kept for parity with Squid's own ERR_* table.
	URITooLarge = Spec{
		Status:  http.StatusRequestURITooLong, // 414
		ErrCode: "ERR_TOO_BIG",
		Message: "Request URI too large.",
	}
	// UnsupportedMethod: not wired to any current caller (every method is
	// relayed transparently today) — kept for parity with Squid's own
	// ERR_* table and for future protocol-level method restrictions.
	UnsupportedMethod = Spec{
		Status:  http.StatusNotImplemented, // 501
		ErrCode: "ERR_UNSUP_REQ",
		Message: "Unsupported request method.",
	}

	// UpstreamUnreachable: DNS resolution failed / no route to host.
	UpstreamUnreachable = Spec{
		Status:  523, // Origin Is Unreachable (Cloudflare)
		ErrCode: "ERR_DNS_FAIL",
		Message: "The remote server's address could not be resolved.",
	}
	// UpstreamDown: TCP connect refused (or refused-equivalent).
	UpstreamDown = Spec{
		Status:  521, // Web Server Is Down (Cloudflare)
		ErrCode: "ERR_CONNECT_FAIL",
		Message: "The remote server refused the connection.",
	}
	// ConnectTimeout: SYN sent, no response within the connect budget.
	ConnectTimeout = Spec{
		Status:  522, // Connection Timed Out (Cloudflare)
		ErrCode: "ERR_CONNECT_FAIL",
		Message: "Connection to the remote server timed out.",
	}
	// ReadTimeout: connected fine, but no response within the read budget.
	ReadTimeout = Spec{
		Status:  524, // A Timeout Occurred (Cloudflare)
		ErrCode: "ERR_READ_TIMEOUT",
		Message: "The remote server stopped responding.",
	}
	// TLSHandshakeFail: the upstream TLS handshake itself failed.
	TLSHandshakeFail = Spec{
		Status:  525, // SSL Handshake Failed (Cloudflare)
		ErrCode: "ERR_SECURE_CONNECT_FAIL",
		Message: "Unable to negotiate a secure connection to the remote server.",
	}
	// InvalidUpstreamCert: not wired to any current caller — an invalid
	// upstream chain is always cloned verbatim today, so the client fails
	// validation itself the same way it would connecting directly; kept
	// for parity with Squid's own ERR_* table and for a future per-rule
	// "don't clone, return an error" option.
	InvalidUpstreamCert = Spec{
		Status:  526, // Invalid SSL Certificate (Cloudflare)
		ErrCode: "ERR_SECURE_CONNECT_FAIL",
		Message: "The remote server's certificate is invalid.",
	}
	// BadGateway / ZeroSizeObject: same status, distinct ERR_* — upstream
	// sent something unparseable as HTTP vs. closed without sending
	// anything at all (matches Squid's own distinction between the two).
	BadGateway = Spec{
		Status:  http.StatusBadGateway, // 502
		ErrCode: "ERR_INVALID_RESP",
		Message: "The remote server returned an invalid response.",
	}
	ZeroSizeObject = Spec{
		Status:  http.StatusBadGateway, // 502
		ErrCode: "ERR_ZERO_SIZE_OBJECT",
		Message: "The remote server closed the connection without sending a response.",
	}
	// LoopDetected: not wired to any current caller (no Via/self-loop
	// check exists yet) — kept for parity with Squid's own ERR_* table.
	LoopDetected = Spec{
		Status:  http.StatusLoopDetected, // 508
		ErrCode: "ERR_ACCESS_DENIED",
		Message: "Forwarding loop detected.",
	}
	// InternalError: our own failure (e.g. cert mint), not upstream's.
	InternalError = Spec{
		Status:  http.StatusInternalServerError, // 500
		ErrCode: "ERR_GATEWAY_FAILURE",
		Message: "Internal proxy error.",
	}

	// ForwardingDenied is the egress policy's refusal: a destination
	// address (explicit deny, or fall-off-the-end no-match) that the
	// client's egress[] list refuses to forward to.
	ForwardingDenied = Spec{
		Status:  http.StatusForbidden, // 403
		ErrCode: "ERR_FORWARDING_DENIED",
		Message: "Forwarding to this address is not permitted.",
	}

	// RuleDenied is a connection: {"accept": false} match: the operator
	// rejected this host/port/proto outright, before any dial or TLS
	// termination was attempted — distinct from ForwardingDenied (an
	// egress-policy refusal of a resolved address) and from a
	// mitm:true rule's request-phase block, both of which happen later
	// and (for block) only after interception.
	RuleDenied = Spec{
		Status:  http.StatusForbidden, // 403
		ErrCode: "ERR_RULE_DENIED",
		Message: "This connection is denied by policy.",
	}

	// MisdirectedRequest is Http2Bridge's coalescing defense: an h2 stream
	// whose :authority doesn't match the single host this connection was
	// actually dialed for gets rejected rather than served, forcing the
	// client to open a fresh connection for that other origin.
	MisdirectedRequest = Spec{
		Status:  http.StatusMisdirectedRequest, // 421
		ErrCode: "ERR_MISDIRECTED_REQUEST",
		Message: "This connection cannot serve requests for the requested host.",
	}

	// OutcallFail covers the broker being unreachable, timed out, or
	// answering incoherently — distinct from OutcallDenied ("the broker
	// said no"), since this means "the broker is broken." Subject to the
	// action's failOpen; OutcallDenied never is.
	OutcallFail = Spec{
		Status:  http.StatusBadGateway, // 502
		ErrCode: "ERR_OUTCALL_FAIL",
		Message: "The policy service could not be reached.",
	}
)

// ProxyAuthRequired builds the Spec for the proxy-auth gate's 407
// challenge: one Proxy-Authenticate header per scheme in schemes
// (typically "Basic" and/or "Bearer", from
// CompiledAuth.ChallengeSchemes), each carrying
// realm. Double quotes in realm are stripped rather than escaped — it's
// operator-authored rule-file config, not attacker input, so this is
// defense in depth against a misconfigured realm producing a malformed
// header, not an injection concern.
func ProxyAuthRequired(realm string, schemes []string) Spec {
	realm = strings.ReplaceAll(realm, `"`, "")
	h := make(http.Header, len(schemes))
	for _, scheme := range schemes {
		h.Add("Proxy-Authenticate", scheme+` realm="`+realm+`"`)
	}
	return Spec{
		Status:  http.StatusProxyAuthRequired, // 407
		ErrCode: "ERR_CACHE_ACCESS_DENIED",
		Message: "Proxy authentication required.",
		Headers: h,
	}
}

// OutcallDenied builds the Spec for a broker's explicit refusal: a
// parsed non-2xx response. status is the broker's http_status override,
// or 0 for the 403 default; message becomes the page's human message,
// falling back to a generic one when the broker sent none.
func OutcallDenied(status int, message string) Spec {
	if status == 0 {
		status = http.StatusForbidden
	}
	if message == "" {
		message = "Denied by policy."
	}
	return Spec{Status: status, ErrCode: "ERR_OUTCALL_DENIED", Message: message}
}

// Raise builds the Spec for a rule's raise action: the raise body
// becomes the message, params.http the status. A zero status defaults
// to 403.
func Raise(status int, message string) Spec {
	if status == 0 {
		status = http.StatusForbidden
	}
	return Spec{Status: status, ErrCode: "ERR_ACCESS_DENIED", Message: message}
}

// cloudflareStatusText holds reason phrases for the Cloudflare-style 52x
// codes net/http doesn't know (they're not in the standard IANA registry,
// so http.StatusText returns "" for them).
var cloudflareStatusText = map[int]string{
	521: "Web Server Is Down",
	522: "Connection Timed Out",
	523: "Origin Is Unreachable",
	524: "A Timeout Occurred",
	525: "SSL Handshake Failed",
	526: "Invalid SSL Certificate",
}

// statusText is http.StatusText with a fallback for the Cloudflare-style
// codes above.
func statusText(code int) string {
	if t := http.StatusText(code); t != "" {
		return t
	}
	return cloudflareStatusText[code]
}

const pageTemplate = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>ERROR: {{.Message}}</title></head>
<body>
<h1>ERROR</h1>
<p>While trying to retrieve the URL: <a href="{{.URL}}">{{.URL}}</a></p>
<p>{{.Message}}</p>
<p>{{.ErrCode}}</p>
<hr>
<p><small>Generated by {{.Generator}} at {{.Timestamp}}</small></p>
</body>
</html>
`

var tmpl = template.Must(template.New("errpage").Parse(pageTemplate))

type pageData struct {
	URL, Message, ErrCode, Generator, Timestamp string
}

// Render renders the Squid-style ERROR HTML page for a request to reqURL.
func Render(reqURL string, spec Spec) []byte {
	var buf bytes.Buffer
	data := pageData{
		URL:       reqURL,
		Message:   spec.Message,
		ErrCode:   spec.ErrCode,
		Generator: Generator,
		Timestamp: time.Now().UTC().Format(time.RFC1123),
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		// tmpl is a fixed, package-level template; a failure here is a
		// programming error (e.g. a bad template edit), not something a
		// caller can recover from at the call site.
		panic(fmt.Errorf("errpage: render: %w", err))
	}
	return buf.Bytes()
}

// WriteResponse writes a complete HTTP/1.1 response (status line, headers,
// Squid-style HTML body) for spec to w.
func WriteResponse(w io.Writer, reqURL string, spec Spec) error {
	body := Render(reqURL, spec)
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "HTTP/1.1 %d %s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\n",
		spec.Status, statusText(spec.Status), len(body))
	for name, values := range spec.Headers {
		for _, v := range values {
			fmt.Fprintf(&buf, "%s: %s\r\n", name, v)
		}
	}
	buf.WriteString("Connection: close\r\n\r\n")
	if _, err := w.Write(buf.Bytes()); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// Handle writes spec's Squid-style page via an http.ResponseWriter — the
// h2 twin of WriteResponse, for Http2Bridge's handler-callback model where
// there's no raw io.Writer to write a whole status-line response onto.
func Handle(w http.ResponseWriter, reqURL string, spec Spec) {
	body := Render(reqURL, spec)
	h := w.Header()
	for name, values := range spec.Headers {
		for _, v := range values {
			h.Add(name, v)
		}
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(spec.Status)
	w.Write(body)
}
