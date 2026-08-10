package rules

import (
	"fmt"
	"net/http"
	"net/textproto"

	"mitmania/internal/httperror"
)

// Verdict is the result of applying one action: ShortCircuit ends the
// pipeline immediately, Resp (if non-nil) is the synthetic response to
// send. A short-circuit with a nil Resp (block) means reset/close instead
// of sending a response.
type Verdict struct {
	ShortCircuit bool
	Resp         *httperror.Spec
}

// RequestInterceptor applies request-phase actions to Req in place.
type RequestInterceptor struct {
	Req *http.Request
}

// HeaderAdd appends header values from params (a flat header-name -> value map).
func (r *RequestInterceptor) HeaderAdd(p Params) Verdict {
	for name, v := range p {
		r.Req.Header.Add(textproto.CanonicalMIMEHeaderKey(name), toString(v))
	}
	return Verdict{}
}

// HeaderSet replaces (or, for a null value, deletes) header values from
// params — a null value is header.set's only way to delete a header.
func (r *RequestInterceptor) HeaderSet(p Params) Verdict {
	for name, v := range p {
		key := textproto.CanonicalMIMEHeaderKey(name)
		if v == nil {
			r.Req.Header.Del(key)
			continue
		}
		r.Req.Header.Set(key, toString(v))
	}
	return Verdict{}
}

// Raise short-circuits with a Squid-style error response: params.http is
// the status, params.body the message.
func (r *RequestInterceptor) Raise(p Params) Verdict {
	status, _ := p.Int("http")
	body, _ := p.String("body")
	spec := httperror.Raise(status, body)
	return Verdict{ShortCircuit: true, Resp: &spec}
}

// Block short-circuits with no response: the connection resets/closes
// instead of getting a page — unlike Raise, which always ends with one.
func (r *RequestInterceptor) Block(Params) Verdict {
	return Verdict{ShortCircuit: true, Resp: nil}
}

// ResponseInterceptor applies response-phase actions. Resp's headers are
// mutated in place; BodyOverride and StatusOverride are staged for the
// caller to apply (recomputing Content-Length/framing), since this
// package doesn't own response serialization.
type ResponseInterceptor struct {
	Resp *http.Response

	BodyOverride   []byte
	StatusOverride int
}

func (r *ResponseInterceptor) HeaderAdd(p Params) Verdict {
	for name, v := range p {
		r.Resp.Header.Add(textproto.CanonicalMIMEHeaderKey(name), toString(v))
	}
	return Verdict{}
}

func (r *ResponseInterceptor) HeaderSet(p Params) Verdict {
	for name, v := range p {
		key := textproto.CanonicalMIMEHeaderKey(name)
		if v == nil {
			r.Resp.Header.Del(key)
			continue
		}
		r.Resp.Header.Set(key, toString(v))
	}
	return Verdict{}
}

// BodyReplace stages a literal replacement body — framing is recomputed
// by the caller when this fires.
func (r *ResponseInterceptor) BodyReplace(p Params) Verdict {
	body, _ := p.String("body")
	r.BodyOverride = []byte(body)
	return Verdict{}
}

// StatusSet stages a replacement status code, applied by the caller.
func (r *ResponseInterceptor) StatusSet(p Params) Verdict {
	status, ok := p.Int("status")
	if ok && status != 0 {
		r.StatusOverride = status
	}
	return Verdict{}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
