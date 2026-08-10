package rules

import (
	"fmt"
	"net/textproto"
	"path"
	"regexp"
	"strings"
)

var validRequestActions = map[string]bool{
	"header.add": true,
	"header.set": true,
	"raise":      true,
	"block":      true,

	// webhook/header.fetch are outcall actions: they reach an external
	// broker mid-request — the only actions that aren't
	// pure/instantaneous. header.fetch is http-only (httpReqActions, this
	// map); a future non-http protocol namespace must not inherit it
	// merely by sharing a name.
	"webhook":      true,
	"header.fetch": true,
}

var validResponseActions = map[string]bool{
	"header.add":   true,
	"header.set":   true,
	"body.replace": true,
	"status.set":   true,
}

// matcher matches a single string against a compiled glob or "re:" regex
// pattern; the zero value (always: true) matches everything, for an
// omitted match field — missing field means implicit "*".
type matcher struct {
	always bool
	glob   string
	re     *regexp.Regexp
}

func compileMatcher(pattern string) (matcher, error) {
	if pattern == "" {
		return matcher{always: true}, nil
	}
	if rest, ok := strings.CutPrefix(pattern, "re:"); ok {
		re, err := regexp.Compile(rest)
		if err != nil {
			return matcher{}, fmt.Errorf("invalid regex %q: %w", pattern, err)
		}
		return matcher{re: re}, nil
	}
	return matcher{glob: pattern}, nil
}

// match reports whether s satisfies the pattern. path.Match (rather than
// filepath.Match) is used deliberately: it hardcodes "/" as the separator
// regardless of GOOS, matching host/path glob semantics independent of
// the platform mitmania runs on.
func (m matcher) match(s string) bool {
	if m.always {
		return true
	}
	if m.re != nil {
		return m.re.MatchString(s)
	}
	ok, _ := path.Match(m.glob, s)
	return ok
}

// CompiledAction is one already-validated step of a request[]/response[]
// pipeline. The name->method dispatch registry is owned by the
// ProtocolHandler, not this package — CompiledRule.Request/Response
// expose the ordered action list for that registry to drive. Outcall is
// non-nil only for the outcall actions "webhook"/"header.fetch" — already
// parsed and validated at compile time, like everything else here, so
// the request-serving path never re-parses Params for these either.
type CompiledAction struct {
	Name    string
	Params  Params
	Outcall *CompiledOutcall
}

// CompiledRule is a Rule after load-time validation and pattern
// compilation.
type CompiledRule struct {
	connHost, connPort, connProto matcher
	msgPath, msgMethod            matcher
	msgHeader                     map[string]matcher // canonicalized header name -> value matcher

	mitm     bool
	hasMsg   bool // true if Match set path/method/header — forces interception
	request  []CompiledAction
	response []CompiledAction
}

// Request returns the rule's request[] action pipeline, in order.
func (r *CompiledRule) Request() []CompiledAction { return r.request }

// Response returns the rule's response[] action pipeline, in order.
func (r *CompiledRule) Response() []CompiledAction { return r.response }

// Compile validates and compiles a RuleFile's http[] list. Load-time
// validation rejects: unknown action, raise/block under response, and
// mitm:false rules carrying message-phase match fields.
func Compile(rf RuleFile) ([]CompiledRule, error) {
	compiled := make([]CompiledRule, 0, len(rf.HTTP))
	for i, r := range rf.HTTP {
		cr, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		compiled = append(compiled, cr)
	}
	return compiled, nil
}

func compileRule(r Rule) (CompiledRule, error) {
	var cr CompiledRule
	var err error

	if cr.connHost, err = compileMatcher(r.Match.Host); err != nil {
		return cr, fmt.Errorf("match.host: %w", err)
	}
	if cr.connPort, err = compileMatcher(r.Match.Port); err != nil {
		return cr, fmt.Errorf("match.port: %w", err)
	}
	if cr.connProto, err = compileMatcher(r.Match.Proto); err != nil {
		return cr, fmt.Errorf("match.proto: %w", err)
	}
	if cr.msgPath, err = compileMatcher(r.Match.Path); err != nil {
		return cr, fmt.Errorf("match.path: %w", err)
	}
	if cr.msgMethod, err = compileMatcher(r.Match.Method); err != nil {
		return cr, fmt.Errorf("match.method: %w", err)
	}
	if len(r.Match.Header) > 0 {
		cr.msgHeader = make(map[string]matcher, len(r.Match.Header))
		for name, pattern := range r.Match.Header {
			m, err := compileMatcher(pattern)
			if err != nil {
				return cr, fmt.Errorf("match.header[%s]: %w", name, err)
			}
			cr.msgHeader[textproto.CanonicalMIMEHeaderKey(name)] = m
		}
	}

	cr.hasMsg = r.Match.hasMessageFields()
	cr.mitm = r.mitm()

	if !cr.mitm && cr.hasMsg {
		return cr, fmt.Errorf("mitm:false rule cannot carry message-phase match fields (path/method/header)")
	}

	if cr.request, err = compileActions(r.Request, validRequestActions, "request"); err != nil {
		return cr, err
	}
	if cr.response, err = compileActions(r.Response, validResponseActions, "response"); err != nil {
		return cr, err
	}

	return cr, nil
}

func compileActions(actions []Action, valid map[string]bool, phase string) ([]CompiledAction, error) {
	out := make([]CompiledAction, 0, len(actions))
	for i, a := range actions {
		if !valid[a.Action] {
			return nil, fmt.Errorf("%s[%d]: unknown or phase-inapplicable action %q", phase, i, a.Action)
		}
		ca := CompiledAction{Name: a.Action, Params: a.Params}
		if a.Action == "webhook" || a.Action == "header.fetch" {
			outcall, err := compileOutcallAction(a)
			if err != nil {
				return nil, fmt.Errorf("%s[%d]: %w", phase, i, err)
			}
			ca.Outcall = outcall
		}
		out = append(out, ca)
	}
	return out, nil
}
