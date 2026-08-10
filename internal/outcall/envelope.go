// Package outcall implements mitmania's broker calls: the
// webhook (may this request proceed) and header.fetch (what headers to
// attach) request-phase actions, both the same OutcallService primitive
// underneath — an HTTP POST to a unix socket or https URL, with an
// RFC 9111-subset response cache the broker's own Cache-Control/Expires/
// ETag govern entirely. This is the one place in the request pipeline
// that does real network I/O, so everything here exists to bound that:
// timeouts, a process-wide concurrency cap, and a strict split between
// "the broker said no" and "the broker is broken."
package outcall

import "encoding/json"

// Version is the wire envelope's version field — bumped on any
// incompatible change; a broker may reject an unknown one.
const Version = 1

// Action names an outcall's kind — the same envelope answers either.
type Action string

const (
	ActionWebhook     Action = "webhook"
	ActionHeaderFetch Action = "header.fetch"

	// ActionAuth is the auth.http_proxy broker scheme: the presented
	// Proxy-Authorization credential is sent to the broker for
	// validation, in place of (or alongside) the rule file's own
	// basic/bearer credential lists.
	ActionAuth Action = "auth"
)

// Request is the envelope POSTed to a broker.
type Request struct {
	Version int    `json:"version"`
	Action  Action `json:"action"`
	UUID    string `json:"uuid,omitempty"` // proxied client's stable identity, from the rule engine's addressing; empty when the effective rule file has none yet
	Client  string `json:"client"`         // source IP, a transport fact — not the identity the rule engine addresses by
	Proto   string `json:"proto"`          // names the one protocol object present; "http" in v1
	Dst     string `json:"dst"`            // resolved, pinned upstream address already cleared by the egress policy, ip:port

	HTTP *HTTPRequest `json:"http,omitempty"`

	// Credential is present only for ActionAuth: the client's
	// presented Proxy-Authorization, passed through verbatim rather than
	// mitmania deciding how to decode it — Basic's value is still its
	// raw base64 blob, Bearer's is still its raw token, and the broker
	// is free to interpret either.
	Credential *Credential `json:"credential,omitempty"`
}

// Credential is ActionAuth's request payload — the
// Proxy-Authorization header's scheme and value, split apart but
// otherwise unprocessed.
type Credential struct {
	Scheme string `json:"scheme"` // "Basic" or "Bearer"
	Value  string `json:"value"`  // everything after "<Scheme> " in the header
}

// HTTPRequest is the "http" proto object: the request-so-far,
// state captured before any mutation earlier in this pipeline so an
// injected secret can never round-trip back out to the broker.
type HTTPRequest struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"` // absolute; reconstructed from the authorized authority + target
	Headers map[string][]string `json:"headers,omitempty"`
}

// Response is a broker's reply. HTTP status carries the verdict;
// the body is this envelope and may be empty on the common allow path.
type Response struct {
	HTTP       *HTTPResponse `json:"http,omitempty"`
	Message    string        `json:"message,omitempty"`
	HTTPStatus int           `json:"http_status,omitempty"`

	// Principal is ActionAuth's 2xx reply payload: the identity
	// the broker vouches for, adopted as the authenticated principal.
	// Ignored for every other action, same as HTTP is ignored on a
	// webhook reply.
	Principal string `json:"principal,omitempty"`
}

// HTTPResponse carries the header set a header.fetch broker wants
// applied — each entry becomes a header.set, so a null value deletes the
// name (matching header.set's own null-means-delete convention in the
// rule pipeline) rather than merely omitting it; that's why the value
// type isn't a plain []string.
type HTTPResponse struct {
	Headers map[string]HeaderValue `json:"headers,omitempty"`
}

// HeaderValue is one header.fetch response entry: either a set of values
// (encoded as a JSON array) or an explicit deletion (encoded as JSON
// null) — the same null-means-delete convention header.set already uses
// in the rule pipeline, just needing a custom type here since a plain
// []string can't represent "absent" and "null" differently.
type HeaderValue struct {
	Delete bool
	Values []string
}

// MarshalJSON implements the null-means-delete convention — needed for
// any Go-side broker (including this package's own tests) to produce the
// same wire shape a real broker would, not Go's default struct encoding.
func (h HeaderValue) MarshalJSON() ([]byte, error) {
	if h.Delete {
		return []byte("null"), nil
	}
	return json.Marshal(h.Values)
}

// UnmarshalJSON implements the null-means-delete convention.
func (h *HeaderValue) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		h.Delete = true
		h.Values = nil
		return nil
	}
	h.Delete = false
	return json.Unmarshal(data, &h.Values)
}
