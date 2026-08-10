package control

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

func withOutcall(c *Control) *Control {
	c.Outcall = outcall.NewService(500*time.Millisecond, 500*time.Millisecond, 8)
	return c
}

func TestControl_PutRuleProbesOutcallAndRejectsOnUnreachableBroker(t *testing.T) {
	c, _ := newTestControl(t)
	base := runControlServer(t, withOutcall(c))

	doc := `{"http":[{"match":{},"request":[{"action":"webhook","params":{"url":"https://127.0.0.1:1"}}]}]}`
	req, _ := http.NewRequest(http.MethodPut, base+"/rules/10.0.0.20", strings.NewReader(doc))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT status = %d, want 400 (probe should fail against an unreachable broker); body=%s", resp.StatusCode, body)
	}

	// The rejected save must not have reached disk.
	getResp, err := http.Get(base + "/rules/10.0.0.20")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer getResp.Body.Close()
	getBody, _ := io.ReadAll(getResp.Body)
	if strings.TrimSpace(string(getBody)) != `{"http":[]}` {
		t.Fatalf("GET after rejected PUT = %s, want the no-file default (probe failure must not save)", getBody)
	}
}

func TestControl_PutRuleProbeSucceedsAndSaves(t *testing.T) {
	c, _ := newTestControl(t)

	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(outcall.Response{})
	}))
	defer broker.Close()

	base := runControlServer(t, withOutcall(c))
	doc := fmt.Sprintf(`{"http":[{"match":{},"request":[{"action":"webhook","params":{"url":%q}}]}]}`, broker.URL)

	req, _ := http.NewRequest(http.MethodPut, base+"/rules/10.0.0.21", strings.NewReader(doc))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT status = %d, want 204 (probe should succeed against a working broker); body=%s", resp.StatusCode, body)
	}

	getResp, err := http.Get(base + "/rules/10.0.0.21")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer getResp.Body.Close()
	getBody, _ := io.ReadAll(getResp.Body)
	if !strings.Contains(string(getBody), "webhook") {
		t.Fatalf("GET after successful PUT = %s, want the saved rule back", getBody)
	}
}

func TestControl_PutRuleValidateFalseSkipsProbe(t *testing.T) {
	c, _ := newTestControl(t)
	base := runControlServer(t, withOutcall(c))

	// Same unreachable broker as the rejection test above, but this time
	// with ?validate=false — must save despite the broker being down.
	doc := `{"http":[{"match":{},"request":[{"action":"webhook","params":{"url":"https://127.0.0.1:1"}}]}]}`
	req, _ := http.NewRequest(http.MethodPut, base+"/rules/10.0.0.22?validate=false", strings.NewReader(doc))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT status = %d, want 204 (?validate=false must skip the probe); body=%s", resp.StatusCode, body)
	}
}

func TestControl_PutRuleWithoutOutcallActionsIsUnaffected(t *testing.T) {
	c, _ := newTestControl(t) // no Outcall configured at all
	base := runControlServer(t, c)

	doc := `{"http":[{"match":{}}]}`
	req, _ := http.NewRequest(http.MethodPut, base+"/rules/10.0.0.23", strings.NewReader(doc))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT status = %d, want 204 (no outcall actions, nothing to probe)", resp.StatusCode)
	}
}
