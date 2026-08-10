package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/textproto"

	"mitmania/internal/httperror"
	"mitmania/internal/outcall"
	"mitmania/internal/rules"
)

// alwaysMaskedHeaders are dropped from an outcall's request envelope even
// when named in an action's "send" allowlist: a webhook/header.fetch
// call must never leak the client's own credentials to the broker.
var alwaysMaskedHeaders = map[string]bool{
	"Authorization":       true,
	"Proxy-Authorization": true,
	"Cookie":              true,
}

// outcallContext is everything a webhook/header.fetch action needs to
// build its envelope, captured once per request — before any
// action in the pipeline (including an earlier one in the same list) has
// mutated it, per "state is before any mutation earlier in this pipeline."
type outcallContext struct {
	Service *outcall.Service
	UUID    string // effective rule file's uuid — empty if it has none yet
	Client  string // source IP, a transport fact — not the identity
	Dst     string // resolved, pinned upstream address, ip:port (post egress-policy resolve-phase)
	Method  string
	ReqURL  string      // absolute URL, from the already-authorized authority + target
	Headers http.Header // pre-pipeline snapshot
}

func newOutcallContext(svc *outcall.Service, uuid, client, dst, method, reqURL string, headers http.Header) *outcallContext {
	return &outcallContext{
		Service: svc,
		UUID:    uuid,
		Client:  client,
		Dst:     dst,
		Method:  method,
		ReqURL:  reqURL,
		Headers: headers.Clone(),
	}
}

func filterHeaders(h http.Header, allow []string) map[string][]string {
	if len(allow) == 0 {
		return nil
	}
	out := make(map[string][]string, len(allow))
	for _, name := range allow {
		canon := textproto.CanonicalMIMEHeaderKey(name)
		if alwaysMaskedHeaders[canon] {
			continue
		}
		if v, ok := h[canon]; ok {
			out[canon] = v
		}
	}
	return out
}

// doOutcall builds and performs one broker call, per the outcall wire format.
func doOutcall(ctx context.Context, oc *outcallContext, co *rules.CompiledOutcall, action outcall.Action) (*outcall.Response, error) {
	if oc == nil || oc.Service == nil {
		return nil, errors.New("outcall: no OutcallService configured")
	}
	target := outcall.Target{Socket: co.Socket, Path: co.Path, URL: co.URL}
	req := outcall.Request{
		Version: outcall.Version,
		Action:  action,
		UUID:    oc.UUID,
		Client:  oc.Client,
		Proto:   "http",
		Dst:     oc.Dst,
		HTTP: &outcall.HTTPRequest{
			Method:  oc.Method,
			URL:     oc.ReqURL,
			Headers: filterHeaders(oc.Headers, co.Send),
		},
	}
	return oc.Service.Do(ctx, co.CacheKey, target, req)
}

// outcallFailVerdict is "the broker is broken": subject to the
// action's own failOpen — proceed silently if set, else short-circuit
// with ERR_OUTCALL_FAIL.
func outcallFailVerdict(co *rules.CompiledOutcall) rules.Verdict {
	if co.FailOpen {
		return rules.Verdict{}
	}
	spec := httperror.OutcallFail
	return rules.Verdict{ShortCircuit: true, Resp: &spec}
}

// outcallDeniedVerdict is "the broker said no" — never subject to
// failOpen, a refusal is a decision, not an outage.
func outcallDeniedVerdict(denied *outcall.DeniedError) rules.Verdict {
	spec := httperror.OutcallDenied(denied.HTTPStatus, denied.Message)
	return rules.Verdict{ShortCircuit: true, Resp: &spec}
}

// requestVerdictOutcome maps a short-circuiting Spec to its access-log
// outcome string: "raise" for a rule's own raise action,
// "outcall-denied"/"outcall-fail" for webhook/header.fetch's two failure
// modes — both share the generic "raise ends with a page" code path in
// handleOneRequest/handleH2Stream, so this is where they're told apart
// again for logging.
func requestVerdictOutcome(spec httperror.Spec) string {
	switch spec.ErrCode {
	case "ERR_OUTCALL_DENIED":
		return "outcall-denied"
	case "ERR_OUTCALL_FAIL":
		return "outcall-fail"
	default:
		return "raise"
	}
}

func applyWebhook(ctx context.Context, oc *outcallContext, co *rules.CompiledOutcall) rules.Verdict {
	_, err := doOutcall(ctx, oc, co, outcall.ActionWebhook)
	if err == nil {
		return rules.Verdict{}
	}
	var denied *outcall.DeniedError
	if errors.As(err, &denied) {
		return outcallDeniedVerdict(denied)
	}
	return outcallFailVerdict(co)
}

// applyHeaderFetch applies a header.fetch broker's returned header set as
// a header.set per entry: validated against OutcallDenylist in
// full before anything is applied, so a violation never leaves the
// request half-mutated.
func applyHeaderFetch(ctx context.Context, oc *outcallContext, ri *rules.RequestInterceptor, co *rules.CompiledOutcall) rules.Verdict {
	resp, err := doOutcall(ctx, oc, co, outcall.ActionHeaderFetch)
	if err != nil {
		var denied *outcall.DeniedError
		if errors.As(err, &denied) {
			return outcallDeniedVerdict(denied)
		}
		return outcallFailVerdict(co)
	}
	if resp.HTTP == nil {
		return rules.Verdict{}
	}

	for name := range resp.HTTP.Headers {
		if rules.OutcallDenylist[textproto.CanonicalMIMEHeaderKey(name)] {
			return outcallFailVerdict(co)
		}
	}
	for name, hv := range resp.HTTP.Headers {
		canon := textproto.CanonicalMIMEHeaderKey(name)
		if hv.Delete {
			ri.Req.Header.Del(canon)
			continue
		}
		ri.Req.Header[canon] = hv.Values
	}
	return rules.Verdict{}
}
