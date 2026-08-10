package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mitmania/internal/outcall"
)

// brokerServer is a fake broker for outcall integration tests: fn decides
// the response per-call, recv captures the last decoded request envelope
// so a test can assert what mitmania actually sent.
func brokerServer(t *testing.T, fn func(req outcall.Request) (status int, resp outcall.Response)) (*httptest.Server, *outcall.Request) {
	t.Helper()
	var lastReq outcall.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&lastReq); err != nil {
			t.Errorf("broker: decode request: %v", err)
		}
		status, resp := fn(lastReq)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &lastReq
}

func withOutcall(h *Http1Handler) *Http1Handler {
	h.Outcall = outcall.NewService(2*time.Second, 2*time.Second, 8)
	return h
}

func TestOutcall_WebhookAllowsRequestThrough(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "from origin")
	}))
	defer origin.Close()

	broker, _ := brokerServer(t, func(req outcall.Request) (int, outcall.Response) {
		if req.Action != outcall.ActionWebhook {
			t.Errorf("broker saw action %q, want webhook", req.Action)
		}
		return http.StatusOK, outcall.Response{}
	})

	rule := fmt.Sprintf(`{"http":[{"match":{},
	  "request":[{"action":"webhook","params":{"url":%q}}]}]}`, broker.URL)
	handler, caPEM := newTestHandler(t, rule)
	proxyAddr := runProxy(t, withOutcall(handler))
	client := proxyHTTPClient(t, proxyAddr, caPEM)

	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "from origin" {
		t.Fatalf("status=%d body=%q, want 200/\"from origin\"", resp.StatusCode, body)
	}
}

func TestOutcall_WebhookDeniesWithMessageAndNeverReachesOrigin(t *testing.T) {
	originHit := false
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHit = true
	}))
	defer origin.Close()

	broker, _ := brokerServer(t, func(req outcall.Request) (int, outcall.Response) {
		return http.StatusForbidden, outcall.Response{Message: "policy says no", HTTPStatus: 402}
	})

	rule := fmt.Sprintf(`{"http":[{"match":{},
	  "request":[{"action":"webhook","params":{"url":%q}}]}]}`, broker.URL)
	handler, caPEM := newTestHandler(t, rule)
	proxyAddr := runProxy(t, withOutcall(handler))
	client := proxyHTTPClient(t, proxyAddr, caPEM)

	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 402 {
		t.Fatalf("status = %d, want 402 (broker's http_status override)", resp.StatusCode)
	}
	if !strings.Contains(string(body), "policy says no") {
		t.Fatalf("body = %q, want it to contain the broker's message", body)
	}
	if originHit {
		t.Fatalf("origin was contacted despite the webhook denial")
	}
}

func TestOutcall_HeaderFetchAppliesReturnedHeaders(t *testing.T) {
	var gotAuth, gotTenant string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotTenant = r.Header.Get("X-Tenant")
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	broker, _ := brokerServer(t, func(req outcall.Request) (int, outcall.Response) {
		return http.StatusOK, outcall.Response{
			HTTP: &outcall.HTTPResponse{
				Headers: map[string]outcall.HeaderValue{
					"Authorization": {Values: []string{"Bearer sk-test"}},
					"X-Tenant":      {Values: []string{"acme"}},
				},
			},
		}
	})

	rule := fmt.Sprintf(`{"http":[{"match":{},
	  "request":[{"action":"header.fetch","params":{"url":%q}}]}]}`, broker.URL)
	handler, caPEM := newTestHandler(t, rule)
	proxyAddr := runProxy(t, withOutcall(handler))
	client := proxyHTTPClient(t, proxyAddr, caPEM)

	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	if gotAuth != "Bearer sk-test" {
		t.Errorf("origin saw Authorization = %q, want \"Bearer sk-test\"", gotAuth)
	}
	if gotTenant != "acme" {
		t.Errorf("origin saw X-Tenant = %q, want \"acme\"", gotTenant)
	}
}

func TestOutcall_HeaderFetchDenylistViolationFailsClosed(t *testing.T) {
	originHit := false
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHit = true
	}))
	defer origin.Close()

	broker, _ := brokerServer(t, func(req outcall.Request) (int, outcall.Response) {
		return http.StatusOK, outcall.Response{
			HTTP: &outcall.HTTPResponse{
				Headers: map[string]outcall.HeaderValue{
					"Host": {Values: []string{"evil.example"}},
				},
			},
		}
	})

	rule := fmt.Sprintf(`{"http":[{"match":{},
	  "request":[{"action":"header.fetch","params":{"url":%q}}]}]}`, broker.URL)
	handler, caPEM := newTestHandler(t, rule)
	proxyAddr := runProxy(t, withOutcall(handler))
	client := proxyHTTPClient(t, proxyAddr, caPEM)

	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (ERR_OUTCALL_FAIL; denylisted header, no failOpen)", resp.StatusCode)
	}
	if originHit {
		t.Fatalf("origin was contacted despite the denylist violation")
	}
}

func TestOutcall_FailOpenProceedsWhenBrokerUnreachable(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "reached origin")
	}))
	defer origin.Close()

	// No broker listening at all: connection refused.
	rule := `{"http":[{"match":{},
	  "request":[{"action":"webhook","params":{"url":"https://127.0.0.1:1","failOpen":true}}]}]}`
	handler, caPEM := newTestHandler(t, rule)
	h := withOutcall(handler)
	proxyAddr := runProxy(t, h)
	client := proxyHTTPClient(t, proxyAddr, caPEM)

	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "reached origin" {
		t.Fatalf("status=%d body=%q, want 200/\"reached origin\" (failOpen should proceed past an unreachable broker)", resp.StatusCode, body)
	}
}

func TestOutcall_FailClosedByDefaultWhenBrokerUnreachable(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("origin contacted despite the broker being unreachable and failOpen unset")
	}))
	defer origin.Close()

	rule := `{"http":[{"match":{},
	  "request":[{"action":"webhook","params":{"url":"https://127.0.0.1:1"}}]}]}`
	handler, caPEM := newTestHandler(t, rule)
	proxyAddr := runProxy(t, withOutcall(handler))
	client := proxyHTTPClient(t, proxyAddr, caPEM)

	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (ERR_OUTCALL_FAIL, fail-closed default)", resp.StatusCode)
	}
}

func TestOutcall_AuthorizationNeverForwardedToBrokerEvenIfAllowlisted(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	var sawAuth bool
	broker, _ := brokerServer(t, func(req outcall.Request) (int, outcall.Response) {
		if req.HTTP != nil {
			if _, ok := req.HTTP.Headers["Authorization"]; ok {
				sawAuth = true
			}
		}
		return http.StatusOK, outcall.Response{}
	})

	rule := fmt.Sprintf(`{"http":[{"match":{},
	  "request":[{"action":"webhook","params":{"url":%q,"send":["Authorization","Accept"]}}]}]}`, broker.URL)
	handler, caPEM := newTestHandler(t, rule)
	proxyAddr := runProxy(t, withOutcall(handler))
	client := proxyHTTPClient(t, proxyAddr, caPEM)

	req, _ := http.NewRequest(http.MethodGet, origin.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer client-secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if sawAuth {
		t.Fatalf("broker received Authorization despite it being always-masked, even though \"send\" named it explicitly")
	}
}
