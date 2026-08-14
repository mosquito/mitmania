package control

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mitmania/internal/cert"
	"mitmania/internal/flowsink"
	"mitmania/internal/rules"
	"mitmania/internal/storage"
)

func newTestControl(t *testing.T) (*Control, string) {
	t.Helper()
	return newTestControlWithLogger(t, nil)
}

// newTestControlWithLogger is newTestControl but also wires logger onto
// the returned Control — for tests asserting on the control-action log,
// which newTestControl's callers otherwise have no way to observe
// (Logger nil disables logAction entirely).
func newTestControlWithLogger(t *testing.T, logger *slog.Logger) (*Control, string) {
	t.Helper()
	dir := t.TempDir()
	ck := make([]byte, 32)
	for i := range ck {
		ck[i] = byte(i)
	}

	st, err := storage.NewPosixStorage(dir)
	if err != nil {
		t.Fatalf("NewPosixStorage: %v", err)
	}
	ca, err := cert.LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := cert.NewCertCache(st, ck, ca)
	store := rules.NewRuleStore(st)

	c := &Control{
		CA:     ca,
		Cache:  cache,
		Store:  store,
		Flow:   &flowsink.Counters{},
		Logger: logger,
	}
	return c, dir
}

// runControlServer starts c on a random loopback TCP port and returns its
// base URL, shutting the server down at test cleanup.
func runControlServer(t *testing.T, c *Control) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv := &http.Server{Handler: c.Handler()}
	go srv.Serve(ln)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})
	return "http://" + ln.Addr().String()
}

// TestControl_LogsControlActions verifies the control-action log covers
// every mutating route: a client rule create (PUT /rules/{ip}), a
// client rule delete, a rules/default replace, a rules/default rejection
// (invalid coverage), and flush-cache. Successes land at Info, failures
// at Warn — both visible at the default log level.
func TestControl_LogsControlActions(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c, _ := newTestControlWithLogger(t, logger)
	base := runControlServer(t, c)

	put := func(path, body string) *http.Response {
		req, _ := http.NewRequest(http.MethodPut, base+path+"?validate=false", strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT %s: %v", path, err)
		}
		resp.Body.Close()
		return resp
	}

	if resp := put("/rules/10.0.0.1", `{"http":[]}`); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /rules/10.0.0.1 status = %d, want 204", resp.StatusCode)
	}
	delReq, _ := http.NewRequest(http.MethodDelete, base+"/rules/10.0.0.1", nil)
	if resp, err := http.DefaultClient.Do(delReq); err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /rules/10.0.0.1: resp=%v err=%v", resp, err)
	} else {
		resp.Body.Close()
	}
	if resp := put("/rules/default", `{"0.0.0.0/0":{"http":[]},"::/0":{"http":[]}}`); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /rules/default status = %d, want 204", resp.StatusCode)
	}
	if resp := put("/rules/default", `{"0.0.0.0/0":{"http":[]}}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT /rules/default (incomplete) status = %d, want 400", resp.StatusCode)
	}
	flushReq, _ := http.NewRequest(http.MethodDelete, base+"/cache", nil)
	if resp, err := http.DefaultClient.Do(flushReq); err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /cache: resp=%v err=%v", resp, err)
	} else {
		resp.Body.Close()
	}

	out := buf.String()
	for _, want := range []string{
		`level=INFO msg="control action" remote=`,
		`action=put-rule target=10.0.0.1`,
		`action=delete-rule target=10.0.0.1`,
		`action=put-default target=default`,
		`level=WARN msg="control action failed"`,
		`action=flush-cache`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("control-action log missing %q; got:\n%s", want, out)
		}
	}
}

func TestControl_CAPEMAndDER(t *testing.T) {
	c, _ := newTestControl(t)
	base := runControlServer(t, c)

	resp, err := http.Get(base + "/ca.pem")
	if err != nil {
		t.Fatalf("GET /ca.pem: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatalf("/ca.pem body is not PEM: %s", body)
	}
	pemCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !pemCert.Equal(c.CA.Cert) {
		t.Fatalf("/ca.pem does not match the root CA")
	}

	resp2, err := http.Get(base + "/ca.der")
	if err != nil {
		t.Fatalf("GET /ca.der: %v", err)
	}
	defer resp2.Body.Close()
	derBody, _ := io.ReadAll(resp2.Body)
	derCert, err := x509.ParseCertificate(derBody)
	if err != nil {
		t.Fatalf("/ca.der body did not parse: %v", err)
	}
	if !derCert.Equal(c.CA.Cert) {
		t.Fatalf("/ca.der does not match the root CA")
	}
}

func TestControl_Stats(t *testing.T) {
	c, _ := newTestControl(t)
	c.Flow.ConnAccepted()
	c.Flow.ConnAccepted()
	c.Flow.RequestServed()
	base := runControlServer(t, c)

	resp, err := http.Get(base + "/stats")
	if err != nil {
		t.Fatalf("GET /stats: %v", err)
	}
	defer resp.Body.Close()
	var got statsResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ConnsAccepted != 2 || got.ConnsActive != 2 || got.Requests != 1 {
		t.Fatalf("stats = %+v", got)
	}
	if got.CacheEntries != 0 {
		t.Fatalf("CacheEntries = %d, want 0", got.CacheEntries)
	}
}

func TestControl_RulesRoundTripAndHotReload(t *testing.T) {
	c, _ := newTestControl(t)
	base := runControlServer(t, c)

	ip := "10.0.0.7"
	doc := `{"http":[{"match":{"host":"x"},"request":[{"action":"header.add","params":{"X-A":"1"}}]}]}`

	req, _ := http.NewRequest(http.MethodPut, base+"/rules/"+ip, strings.NewReader(doc))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT status = %d, want 204", resp.StatusCode)
	}

	getResp, err := http.Get(base + "/rules/" + ip)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer getResp.Body.Close()
	body, _ := io.ReadAll(getResp.Body)
	if !bytes.Equal(bytes.TrimSpace(body), []byte(doc)) {
		t.Fatalf("GET /rules/%s = %s, want %s", ip, body, doc)
	}

	// The proxy pipeline's own RuleEngine (separate from Control, which
	// only touches the RuleStore) must already reflect the new rules
	// without a restart — RuleEngine.Lookup notices the changed
	// mtime/size on its own.
	addr := mustParseAddr(t, ip)
	engine := rules.NewRuleEngine(c.Store)
	rs, err := engine.Lookup(context.Background(), addr)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	rule, matched := rs.LookupRequest(rules.MsgInput{ConnInput: rules.ConnInput{Host: "x"}})
	if !matched || len(rule.Request()) != 1 || rule.Request()[0].Name != "header.add" {
		t.Fatalf("engine did not pick up the PUT without a restart")
	}
}

func TestControl_PutRulesRejectsInvalid(t *testing.T) {
	c, _ := newTestControl(t)
	base := runControlServer(t, c)

	for _, doc := range []string{
		`not json`,
		`{"http":[{"match":{},"request":[{"action":"bogus"}]}]}`,
		`{"http":[{"match":{"host":"x","path":"/a"},"mitm":false}]}`,
	} {
		req, _ := http.NewRequest(http.MethodPut, base+"/rules/10.0.0.8", strings.NewReader(doc))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("doc %q: status = %d, want 400", doc, resp.StatusCode)
		}
	}
}

func TestControl_DeleteRule(t *testing.T) {
	c, _ := newTestControl(t)
	base := runControlServer(t, c)

	ip := "10.0.0.11"
	doc := `{"http":[{"match":{"host":"x"}}]}`

	putReq, _ := http.NewRequest(http.MethodPut, base+"/rules/"+ip, strings.NewReader(doc))
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT status = %d, want 204", putResp.StatusCode)
	}

	delReq, _ := http.NewRequest(http.MethodDelete, base+"/rules/"+ip, nil)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", delResp.StatusCode)
	}

	// GET after DELETE: back to the same "no rules" shape as a client that
	// never had a file — an empty HTTP rule list, not a 404.
	getResp, err := http.Get(base + "/rules/" + ip)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer getResp.Body.Close()
	body, _ := io.ReadAll(getResp.Body)
	if !bytes.Equal(bytes.TrimSpace(body), []byte(`{"http":[]}`)) {
		t.Fatalf("GET /rules/%s after DELETE = %s, want {\"http\":[]}", ip, body)
	}

	// The proxy's RuleEngine must also see the revocation immediately —
	// no separate reload step, same as the PUT hot-reload guarantee.
	addr := mustParseAddr(t, ip)
	engine := rules.NewRuleEngine(c.Store)
	rs, err := engine.Lookup(context.Background(), addr)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if _, _, matched := rs.LookupConn(rules.ConnInput{Host: "x", Proto: "https"}); matched {
		t.Fatalf("engine still matched a connection-phase rule after DELETE")
	}

	// Deleting an already-ruleless client is a no-op, not an error.
	delAgainReq, _ := http.NewRequest(http.MethodDelete, base+"/rules/"+ip, nil)
	delAgainResp, err := http.DefaultClient.Do(delAgainReq)
	if err != nil {
		t.Fatalf("DELETE (again): %v", err)
	}
	delAgainResp.Body.Close()
	if delAgainResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE (already gone) status = %d, want 204", delAgainResp.StatusCode)
	}
}

func TestControl_DeleteRuleInvalidIP(t *testing.T) {
	c, _ := newTestControl(t)
	base := runControlServer(t, c)

	req, _ := http.NewRequest(http.MethodDelete, base+"/rules/not-an-ip", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestControl_FlushCache(t *testing.T) {
	c, dir := newTestControl(t)
	base := runControlServer(t, c)

	// Seed a fake cache entry directly on disk to prove Flush actually
	// removes files, not just reports zero.
	sentinel := filepath.Join(dir, "leaf", "by-id", "sentinel.p12")
	if err := os.MkdirAll(filepath.Dir(sentinel), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sentinel, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodDelete, base+"/cache", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE /cache: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("cache file survived flush (stat err = %v)", err)
	}
}

func TestControl_SPAServedAtRoot(t *testing.T) {
	c, _ := newTestControl(t)
	base := runControlServer(t, c)

	resp, err := http.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "mitmania") {
		t.Fatalf("SPA body doesn't look right:\n%s", body)
	}
}

func TestControl_ListenAndServe_Unix(t *testing.T) {
	c, _ := newTestControl(t)
	sockPath := fmt.Sprintf("/tmp/mitmania-control-test-%d.sock", os.Getpid())
	os.Remove(sockPath)
	t.Cleanup(func() { os.Remove(sockPath) })

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- c.ListenAndServe(ctx, "unix", sockPath) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", sockPath)
		},
	}}
	resp, err := client.Get("http://unix/ca.pem")
	if err != nil {
		t.Fatalf("GET over unix socket: %v", err)
	}
	resp.Body.Close()

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket perm = %v, want 0600", info.Mode().Perm())
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ListenAndServe returned: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("ListenAndServe did not stop after ctx cancel")
	}
}

func mustParseAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestControl_DefaultRulesRoundTripAndHotReload mirrors
// TestControl_RulesRoundTripAndHotReload for GET/PUT /rules/default —
// the gapless CIDR-keyed table every client without a per-IP override
// resolves against, reached via RuleEngine.Lookup's fallback instead of a
// per-IP file.
func TestControl_DefaultRulesRoundTripAndHotReload(t *testing.T) {
	c, _ := newTestControl(t)
	base := runControlServer(t, c)

	doc := `{"0.0.0.0/0":{"uuid":"fixed-uuid","http":[{"match":{"host":"x"},"request":[{"action":"header.add","params":{"X-A":"1"}}]}]},"::/0":{"http":[]}}`

	req, _ := http.NewRequest(http.MethodPut, base+"/rules/default", strings.NewReader(doc))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT status = %d, want 204", resp.StatusCode)
	}

	getResp, err := http.Get(base + "/rules/default")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer getResp.Body.Close()
	body, _ := io.ReadAll(getResp.Body)
	if !bytes.Equal(bytes.TrimSpace(body), []byte(doc)) {
		t.Fatalf("GET /rules/default = %s, want %s", body, doc)
	}

	engine := rules.NewRuleEngine(c.Store)
	rs, err := engine.Lookup(context.Background(), netip.MustParseAddr("203.0.113.5"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rs.UUID() != "fixed-uuid" {
		t.Fatalf("UUID() = %q, want fixed-uuid", rs.UUID())
	}
	rule, matched := rs.LookupRequest(rules.MsgInput{ConnInput: rules.ConnInput{Host: "x"}})
	if !matched || len(rule.Request()) != 1 || rule.Request()[0].Name != "header.add" {
		t.Fatalf("engine did not pick up the PUT without a restart")
	}
}

// TestControl_PerIPOverrideWinsOverDefault verifies /rules/{ip} and
// /rules/default address genuinely separate storage, and that a per-IP
// override takes precedence over whatever rules/default would otherwise
// resolve for that same address.
func TestControl_PerIPOverrideWinsOverDefault(t *testing.T) {
	c, _ := newTestControl(t)
	base := runControlServer(t, c)

	const literal = "203.0.113.9"
	ipDoc := `{"uuid":"ip-uuid","http":[]}`
	defaultDoc := `{"0.0.0.0/0":{"uuid":"default-uuid","http":[]},"::/0":{"http":[]}}`

	for _, put := range []struct{ path, doc string }{
		{"/rules/" + literal, ipDoc},
		{"/rules/default", defaultDoc},
	} {
		req, _ := http.NewRequest(http.MethodPut, base+put.path, strings.NewReader(put.doc))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT %s: %v", put.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("PUT %s status = %d, want 204", put.path, resp.StatusCode)
		}
	}

	engine := rules.NewRuleEngine(c.Store)
	rs, err := engine.Lookup(context.Background(), netip.MustParseAddr(literal))
	if err != nil {
		t.Fatal(err)
	}
	if rs.UUID() != "ip-uuid" {
		t.Fatalf("UUID() = %q, want the per-IP override to win, not rules/default", rs.UUID())
	}
}

// TestControl_PutDefaultRejectsIncompleteCoverage verifies rules/default's
// save-time coverage obligation: a table missing v6 coverage entirely is
// rejected with 400, not silently written with a hole in it.
func TestControl_PutDefaultRejectsIncompleteCoverage(t *testing.T) {
	c, _ := newTestControl(t)
	base := runControlServer(t, c)

	req, _ := http.NewRequest(http.MethodPut, base+"/rules/default", strings.NewReader(`{"0.0.0.0/0":{"http":[]}}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a table missing v6 coverage", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("coverage")) {
		t.Fatalf("error body = %s, want it to name the coverage gap", body)
	}
}

// TestControl_PutDefaultEchoesCanonicalizedForm verifies that a PUT
// carrying a non-canonical mask ("/255.0.0.0" instead of "/8") and a
// second entry that normalizes to the SAME address/mask is stored (and
// echoed back by GET) in canonical, deduplicated form — the later
// duplicate winning, not appended as a second competing entry.
func TestControl_PutDefaultEchoesCanonicalizedForm(t *testing.T) {
	c, _ := newTestControl(t)
	base := runControlServer(t, c)

	submitted := `{
		"10.0.0.0/255.0.0.0": {"uuid":"stale",   "http":[]},
		"10.0.0.0/8":          {"uuid":"current", "http":[]},
		"0.0.0.0/0":           {"http":[]},
		"::/0":                {"http":[]}
	}`
	req, _ := http.NewRequest(http.MethodPut, base+"/rules/default", strings.NewReader(submitted))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT status = %d, want 204", resp.StatusCode)
	}

	getResp, err := http.Get(base + "/rules/default")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer getResp.Body.Close()
	body, _ := io.ReadAll(getResp.Body)

	if bytes.Contains(body, []byte("255.0.0.0")) {
		t.Fatalf("GET /rules/default = %s, want the sparse-mask literal normalized to /8", body)
	}
	if !bytes.Contains(body, []byte(`"10.0.0.0/8"`)) {
		t.Fatalf("GET /rules/default = %s, want a canonical 10.0.0.0/8 entry", body)
	}
	if !bytes.Contains(body, []byte(`"current"`)) || bytes.Contains(body, []byte(`"stale"`)) {
		t.Fatalf("GET /rules/default = %s, want only the later duplicate (\"current\") to survive", body)
	}

	engine := rules.NewRuleEngine(c.Store)
	rs, err := engine.Lookup(context.Background(), netip.MustParseAddr("10.1.2.3"))
	if err != nil {
		t.Fatal(err)
	}
	if rs.UUID() != "current" {
		t.Fatalf("Lookup(10.1.2.3).UUID() = %q, want current", rs.UUID())
	}
}

// TestControl_PutRuleRejectsInvalidAuthConfig verifies that a malformed
// hash or an unknown scheme in a rule file's auth config is a load-time
// rejection at PUT time, not just at runtime Lookup.
func TestControl_PutRuleRejectsInvalidAuthConfig(t *testing.T) {
	c, _ := newTestControl(t)
	base := runControlServer(t, c)

	doc := `{"auth":{"http_proxy":{"required":true}},"http":[]}`
	req, _ := http.NewRequest(http.MethodPut, base+"/rules/10.0.0.20", strings.NewReader(doc))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for required:true with no scheme configured", resp.StatusCode)
	}
}
