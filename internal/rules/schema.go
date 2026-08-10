// Package rules implements mitmania's per-client rule engine:
// loading/compiling rule files, connection- and message-phase matching,
// and the request/response action registries that mutate or short-circuit
// a request.
package rules

// RuleFile is the on-disk rule document, protocol-namespaced. Only "http"
// is implemented this pass. It's used both as a per-client override
// (rules/ip/{sha1(clientIP)}.json) and, embedded per address/mask key, as
// one bucket of the rules/default gapless table.
//
// Egress is nil when the "egress" key is absent from the JSON entirely
// (client inherits RuleEngine's default list) and non-nil-but-
// possibly-empty when the key is present ("egress": [] matches nothing —
// not an opt-out, since no-match is itself a denial). This nil-vs-empty
// distinction is exactly what encoding/json already gives an unmarshaled
// slice field for free, so RuleEngine.Lookup tells the two apart with a
// plain nil check — no separate "was this key present" bookkeeping needed.
type RuleFile struct {
	// UUID is the proxied client's stable identity: operator-assigned,
	// or a persisted uuid4 minted by RuleEngine.Lookup if
	// absent from an otherwise-existing file. Sent to every outcall
	// broker and namespaces this client's outcall cache.
	UUID   string       `json:"uuid,omitempty"`
	Auth   *AuthConfig  `json:"auth,omitempty"`
	HTTP   []Rule       `json:"http"`
	Egress []EgressRule `json:"egress,omitempty"`
}

// AuthConfig is the "auth" namespace — keyed by mechanism, one key per
// protocol handler's own auth exchange. v1 defines http_proxy only.
type AuthConfig struct {
	HTTPProxy *HTTPProxyAuth `json:"http_proxy,omitempty"`
}

// HTTPProxyAuth is auth.http_proxy: a credential the client presents to
// the proxy itself via Proxy-Authorization, sibling to egress/http.
type HTTPProxyAuth struct {
	Required bool   `json:"required,omitempty"`
	Realm    string `json:"realm,omitempty"`

	Basic  []BasicCredential  `json:"basic,omitempty"`
	Bearer []BearerCredential `json:"bearer,omitempty"`
	Broker *AuthBroker        `json:"broker,omitempty"`
}

// BasicCredential is one Proxy-Authorization: Basic entry — the presented
// password is checked against Hash (a canonical $argon2id$... PHC string),
// never a plaintext.
type BasicCredential struct {
	User string `json:"user"`
	Hash string `json:"hash"`
}

// BearerCredential is one Proxy-Authorization: Bearer entry — the
// presented token is checked against Hash ("sha256:<hex>").
type BearerCredential struct {
	ID   string `json:"id"`
	Hash string `json:"hash"`
}

// AuthBroker delegates auth.http_proxy credential validation to an
// OutcallService — exactly one of Socket or URL, same mutual-exclusivity
// rule as a webhook/header.fetch action's target.
type AuthBroker struct {
	Socket string `json:"socket,omitempty"`
	URL    string `json:"url,omitempty"`
	Path   string `json:"path,omitempty"`
}

// Match selects which requests a Rule applies to. Wildcards: glob (*/?)
// or a "re:"-prefixed regex; an empty/omitted field is an implicit "*".
// Connection-phase fields: Host, Port, Proto. Message-phase fields: Path,
// Method, Header.
//
// Status is parsed for schema completeness but not evaluated by the
// engine in this pass: the rule engine runs exactly two first-match
// passes (connection, then message) and Status is a response-only field
// — matching it correctly would need a third, response-phase pass this
// design doesn't have, and no worked example exercises it.
type Match struct {
	Host   string            `json:"host,omitempty"`
	Port   string            `json:"port,omitempty"`
	Proto  string            `json:"proto,omitempty"`
	Path   string            `json:"path,omitempty"`
	Method string            `json:"method,omitempty"`
	Header map[string]string `json:"header,omitempty"`
	Status string            `json:"status,omitempty"`
}

// Action is one step of a request[]/response[] pipeline.
type Action struct {
	Action string `json:"action"`
	Params Params `json:"params,omitempty"`
}

// Params carries action-specific arguments. Its shape differs per action:
// header.add/header.set treat it as a flat header-name -> value map (a
// null value is header.set's delete); raise uses "http"/"body";
// body.replace uses "body"; status.set uses "status".
type Params map[string]any

// String reads a string-valued param.
func (p Params) String(key string) (string, bool) {
	v, ok := p[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// Int reads an int-valued param. JSON numbers decode as float64 into
// Params' any values, so both float64 and int are accepted.
func (p Params) Int(key string) (int, bool) {
	v, ok := p[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	}
	return 0, false
}

// IsNull reports whether key is present with a JSON null value —
// header.set's "delete this header" signal.
func (p Params) IsNull(key string) bool {
	v, ok := p[key]
	return ok && v == nil
}

// Bool reads a bool-valued param — webhook/header.fetch's "failOpen".
func (p Params) Bool(key string) (bool, bool) {
	v, ok := p[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// StringSlice reads a string-array-valued param — webhook/header.fetch's
// "send" header allowlist. A present-but-wrong-typed value (not a
// JSON array of strings) is reported via ok=false, same as every other
// typed accessor here.
func (p Params) StringSlice(key string) ([]string, bool) {
	v, ok := p[key]
	if !ok {
		return nil, false
	}
	raw, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(raw))
	for i, e := range raw {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

// Rule is one entry in a RuleFile's protocol list, evaluated top-down,
// first-match-wins — exactly one rule's pipeline runs per request, no
// cascading (iptables-like).
type Rule struct {
	Match    Match    `json:"match"`
	MITM     *bool    `json:"mitm,omitempty"` // nil = default true
	Request  []Action `json:"request,omitempty"`
	Response []Action `json:"response,omitempty"`
}

func (r Rule) mitm() bool {
	if r.MITM == nil {
		return true
	}
	return *r.MITM
}

// hasMessageFields reports whether Match sets any message-phase-only
// field — these force interception and are rejected at load on a
// mitm:false rule.
func (m Match) hasMessageFields() bool {
	return m.Path != "" || m.Method != "" || len(m.Header) > 0
}
