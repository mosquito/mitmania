package rules

import (
	"net/http"
	"testing"
)

func newReq(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestRequestInterceptor_HeaderAdd(t *testing.T) {
	req := newReq(t)
	req.Header.Set("Authorization", "old")
	ri := &RequestInterceptor{Req: req}
	ri.HeaderAdd(Params{"Authorization": "new"})
	got := req.Header.Values("Authorization")
	if len(got) != 2 || got[0] != "old" || got[1] != "new" {
		t.Fatalf("Authorization values = %v, want [old new]", got)
	}
}

func TestRequestInterceptor_HeaderSet(t *testing.T) {
	req := newReq(t)
	req.Header.Set("User-Agent", "old")
	ri := &RequestInterceptor{Req: req}
	ri.HeaderSet(Params{"User-Agent": "mitmania/1.2.3"})
	if got := req.Header.Get("User-Agent"); got != "mitmania/1.2.3" {
		t.Fatalf("User-Agent = %q, want mitmania/1.2.3", got)
	}
}

func TestRequestInterceptor_HeaderSetNullDeletes(t *testing.T) {
	req := newReq(t)
	req.Header.Set("Location", "https://evil.example/")
	ri := &RequestInterceptor{Req: req}
	ri.HeaderSet(Params{"Location": nil})
	if req.Header.Get("Location") != "" {
		t.Fatalf("Location header not deleted: %q", req.Header.Get("Location"))
	}
}

func TestRequestInterceptor_Raise(t *testing.T) {
	ri := &RequestInterceptor{Req: newReq(t)}
	v := ri.Raise(Params{"http": float64(403), "body": "Declined"})
	if !v.ShortCircuit {
		t.Fatalf("Raise: ShortCircuit = false")
	}
	if v.Resp == nil {
		t.Fatalf("Raise: Resp is nil")
	}
	if v.Resp.Status != 403 || v.Resp.Message != "Declined" {
		t.Fatalf("Raise: Resp = %+v", v.Resp)
	}
}

func TestRequestInterceptor_Block(t *testing.T) {
	ri := &RequestInterceptor{Req: newReq(t)}
	v := ri.Block(nil)
	if !v.ShortCircuit {
		t.Fatalf("Block: ShortCircuit = false")
	}
	if v.Resp != nil {
		t.Fatalf("Block: Resp = %+v, want nil (no page, per §10.1)", v.Resp)
	}
}

func newResp(t *testing.T) *http.Response {
	t.Helper()
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
	}
}

func TestResponseInterceptor_HeaderSetNullDeletes(t *testing.T) {
	resp := newResp(t)
	resp.Header.Set("Location", "https://tracker.example/")
	ri := &ResponseInterceptor{Resp: resp}
	ri.HeaderSet(Params{"Location": nil})
	if resp.Header.Get("Location") != "" {
		t.Fatalf("Location not deleted: %q", resp.Header.Get("Location"))
	}
}

func TestResponseInterceptor_BodyReplace(t *testing.T) {
	ri := &ResponseInterceptor{Resp: newResp(t)}
	ri.BodyReplace(Params{"body": "replaced"})
	if string(ri.BodyOverride) != "replaced" {
		t.Fatalf("BodyOverride = %q, want replaced", ri.BodyOverride)
	}
}

func TestResponseInterceptor_StatusSet(t *testing.T) {
	ri := &ResponseInterceptor{Resp: newResp(t)}
	ri.StatusSet(Params{"status": float64(204)})
	if ri.StatusOverride != 204 {
		t.Fatalf("StatusOverride = %d, want 204", ri.StatusOverride)
	}
}
