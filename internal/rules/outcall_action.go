package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/textproto"
	"sort"
)

// outcallDenylist is the fixed set of response header names a header.fetch
// broker can never set: framing/addressing headers, not authorization —
// a broker attempting one is a hard failure (ERR_OUTCALL_FAIL), not a
// filtered field. Applied by the caller (proxy package) when
// it actually has a broker response in hand; kept here purely as the
// canonical name list so compile-time code and apply-time code agree on
// exactly one set.
var OutcallDenylist = map[string]bool{
	"Host":              true,
	"Content-Length":    true,
	"Transfer-Encoding": true,
	"Connection":        true,
	"Upgrade":           true,
	"Te":                true, // textproto.CanonicalMIMEHeaderKey("TE") == "Te"
}

// CompiledOutcall is a validated webhook/header.fetch action. Compiled
// once at load, like every other action — the socket-vs-url
// shape check, the "send" allowlist, and the cache key are all settled
// here so the request-serving path never re-parses Params.
type CompiledOutcall struct {
	Socket string // unix socket path; "" if URL-based
	Path   string // request path over Socket, "/" default
	URL    string // https URL; "" if Socket-based

	Send     []string // canonicalized request-header allowlist to forward to the broker
	FailOpen bool

	// CacheKey identifies this action's outcall cache entries — derived
	// from the transport target plus a hash of every param, never from
	// request fields: a key varying by path would let a sandbox probe
	// for other scopes' secrets, and folding in the params means a rule
	// edit invalidates its own cache entries.
	CacheKey string
}

func compileOutcallAction(a Action) (*CompiledOutcall, error) {
	socket, hasSocket := a.Params.String("socket")
	url, hasURL := a.Params.String("url")
	if hasSocket == hasURL {
		return nil, fmt.Errorf("%s: exactly one of \"socket\" or \"url\" is required", a.Action)
	}

	co := &CompiledOutcall{Socket: socket, URL: url}

	if hasSocket {
		path, ok := a.Params.String("path")
		if !ok || path == "" {
			path = "/"
		}
		co.Path = path
	} else if _, ok := a.Params["path"]; ok {
		return nil, fmt.Errorf("%s: \"path\" only applies to a \"socket\" target", a.Action)
	}

	if send, ok := a.Params.StringSlice("send"); ok {
		canon := make([]string, len(send))
		for i, name := range send {
			canon[i] = textproto.CanonicalMIMEHeaderKey(name)
		}
		co.Send = canon
	} else if _, present := a.Params["send"]; present {
		return nil, fmt.Errorf("%s: \"send\" must be an array of header names", a.Action)
	}

	if fo, ok := a.Params.Bool("failOpen"); ok {
		co.FailOpen = fo
	} else if _, present := a.Params["failOpen"]; present {
		return nil, fmt.Errorf("%s: \"failOpen\" must be a bool", a.Action)
	}

	co.CacheKey = outcallCacheKey(co, a.Params)
	return co, nil
}

// outcallCacheKey derives a stable cache key from the target (socket+path
// or url) and every param — json.Marshal on a map[string]any sorts keys,
// so this is deterministic across an identically-authored action without
// needing our own canonicalization pass.
func outcallCacheKey(co *CompiledOutcall, params Params) string {
	target := co.URL
	if co.Socket != "" {
		target = co.Socket + co.Path
	}
	data, _ := json.Marshal(sortedParams(params))
	sum := sha256.Sum256(data)
	return target + "#" + hex.EncodeToString(sum[:8])
}

// sortedParams re-encodes params through a slice of key/value pairs so
// the hash above is stable even if a future Go version's map iteration
// or JSON encoding ever stopped sorting keys on its own — belt and
// braces for a value that gates a security-relevant cache partition.
func sortedParams(params Params) [][2]any {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([][2]any, len(keys))
	for i, k := range keys {
		pairs[i] = [2]any{k, params[k]}
	}
	return pairs
}
