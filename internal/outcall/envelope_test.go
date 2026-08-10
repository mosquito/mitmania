package outcall

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestHeaderValue_MarshalUnmarshalRoundTrip guards against the
// Marshal/Unmarshal asymmetry this package briefly had: UnmarshalJSON
// expects the wire shape (a plain JSON array, or null for delete), but
// without a matching MarshalJSON, json.Marshal on this type used Go's
// default struct encoding instead — a shape no real broker sends and
// UnmarshalJSON can't read back, silently breaking any Go-side broker
// (including this package's own tests) constructing a HeaderValue
// programmatically.
func TestHeaderValue_MarshalUnmarshalRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		hv   HeaderValue
		want string // exact wire shape
	}{
		{"values", HeaderValue{Values: []string{"a", "b"}}, `["a","b"]`},
		{"empty values", HeaderValue{Values: []string{}}, `[]`},
		{"delete", HeaderValue{Delete: true}, `null`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.hv)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(data) != tc.want {
				t.Fatalf("Marshal(%+v) = %s, want %s", tc.hv, data, tc.want)
			}

			var got HeaderValue
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal(%s): %v", data, err)
			}
			if !reflect.DeepEqual(got, tc.hv) && !(len(got.Values) == 0 && len(tc.hv.Values) == 0 && got.Delete == tc.hv.Delete) {
				t.Fatalf("round-trip mismatch: got %+v, want %+v", got, tc.hv)
			}
		})
	}
}

func TestResponse_HeaderFetchEnvelopeRoundTrip(t *testing.T) {
	resp := Response{
		HTTP: &HTTPResponse{
			Headers: map[string]HeaderValue{
				"Authorization": {Values: []string{"Bearer sk-test"}},
				"X-Old-Token":   {Delete: true},
			},
		},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got Response
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal(%s): %v", data, err)
	}
	if got.HTTP == nil {
		t.Fatalf("HTTP is nil after round-trip")
	}
	if v := got.HTTP.Headers["Authorization"]; v.Delete || len(v.Values) != 1 || v.Values[0] != "Bearer sk-test" {
		t.Fatalf("Authorization = %+v, want Values=[Bearer sk-test]", v)
	}
	if v := got.HTTP.Headers["X-Old-Token"]; !v.Delete {
		t.Fatalf("X-Old-Token = %+v, want Delete=true", v)
	}
}

// TestRequest_AuthActionWireShape locks down the auth.http_proxy broker's
// request envelope: uuid and credential appear when set, and the whole thing
// round-trips through JSON without loss.
func TestRequest_AuthActionWireShape(t *testing.T) {
	req := Request{
		Version:    Version,
		Action:     ActionAuth,
		UUID:       "a1f3c9e2-uuid",
		Client:     "10.1.0.7",
		Proto:      "http",
		Credential: &Credential{Scheme: "Basic", Value: "YWxpY2U6czNjcmV0"},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got Request
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(req, got) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, req)
	}
	if got.Action != ActionAuth {
		t.Fatalf("Action = %q, want %q", got.Action, ActionAuth)
	}
}

// TestRequest_UUIDOmittedWhenEmpty verifies a client with no rule-file
// uuid yet (e.g. a not-yet-persisted mint) doesn't send a bogus empty
// "uuid" field to the broker.
func TestRequest_UUIDOmittedWhenEmpty(t *testing.T) {
	data, err := json.Marshal(Request{Version: Version, Action: ActionWebhook, Client: "10.1.0.7", Proto: "http"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, present := raw["uuid"]; present {
		t.Fatalf("wire JSON has a \"uuid\" key with an empty UUID: %s", data)
	}
}

// TestResponse_PrincipalWireShape locks down the auth.http_proxy broker's
// reply: principal round-trips, and is absent from the wire when unset (a
// webhook/header.fetch reply never carries one).
func TestResponse_PrincipalWireShape(t *testing.T) {
	data, err := json.Marshal(Response{Principal: "alice"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if raw["principal"] != "alice" {
		t.Fatalf("principal = %v, want \"alice\"", raw["principal"])
	}

	data2, err := json.Marshal(Response{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw2 map[string]any
	if err := json.Unmarshal(data2, &raw2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, present := raw2["principal"]; present {
		t.Fatalf("wire JSON has a \"principal\" key with no principal set: %s", data2)
	}
}
