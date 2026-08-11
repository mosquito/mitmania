package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// testClusterKey mints a fresh, valid --cluster-key value: 32 random
// bytes, base64-encoded. config.Parse only requires >= 32 decoded bytes,
// so a random key per call means these tests never need (or risk
// colliding with) a real cluster's key.
func testClusterKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// testPermissiveDefault is the same "cover the whole address space,
// allow all egress" rules/default table internal/proxy's test suite
// seeds directly into storage (see testPermissiveDefault in
// internal/proxy/http1_test.go). Here it has to go through PUT
// /rules/default over the control API instead: run() bootstraps a fresh
// cluster with rules.BuiltinDefaultRuleset, whose egress buckets deny
// loopback/private ranges (the SSRF guard) -- without overriding it, a
// proxied request to a loopback httptest.Server would be denied by
// egress policy before it ever reached the origin.
const testPermissiveDefault = `{
	"0.0.0.0/0":{"http":[],"egress":[{"cidr":"0.0.0.0/0","action":"allow"},{"cidr":"::/0","action":"allow"}]},
	"::/0":{"http":[],"egress":[{"cidr":"0.0.0.0/0","action":"allow"},{"cidr":"::/0","action":"allow"}]}
}`

// waitForListener retries dialing network/address until something
// accepts the connection or timeout elapses. run() has no readiness
// signal of its own beyond "a listener is now accepting" -- this is the
// only way to know startup finished without guessing at a sleep duration.
func waitForListener(t *testing.T, network, address string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout(network, address, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s %s never became ready: %v", network, address, lastErr)
}

// shortControlSocket returns a --control unix:// path short enough for
// sun_path's ~104-byte limit (macOS/BSD; Linux is more permissive but
// still bounded). t.TempDir() nests under a directory named after the
// test, which routinely blows past that limit on its own -- os.MkdirTemp
// with no dir argument creates directly under os.TempDir() instead, with
// no such nesting, and is what actually keeps the resulting path short
// enough to bind.
func shortControlSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "mitmania-ctl-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "ctl.sock")
}

// controlClient builds an http.Client that dials sockPath over a unix
// socket for every request regardless of URL host, matching how an
// operator reaches a unix:// --control address.
func controlClient(sockPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
		Timeout: 5 * time.Second,
	}
}

// putRules issues PUT path over client (the control API) with body and
// fails the test unless the control API accepts it (204 No Content) --
// covers both PUT /rules/default and PUT /rules/{ip}.
func putRules(t *testing.T, client *http.Client, path, body string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, "http://unix"+path, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("NewRequest PUT %s: %v", path, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT %s status = %d, want 204; body=%s", path, resp.StatusCode, b)
	}
}

// terminateAndAwait sends the test process itself a real SIGTERM -- the
// exact signal run()'s signal.NotifyContext (main.go:58) is registered
// for -- and waits for run() to return on runErr, failing the test if it
// doesn't return within timeout (a regression here should fail fast
// rather than hang CI).
func terminateAndAwait(t *testing.T, runErr <-chan error, timeout time.Duration) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("Kill(SIGTERM): %v", err)
	}
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run() returned %v, want nil after graceful SIGTERM shutdown", err)
		}
	case <-time.After(timeout):
		t.Fatal("run() did not return within the timeout after SIGTERM")
	}
}

// TestRun_HTTPProxyEndToEndAndGracefulShutdown drives run() as a real
// process would: parse real CLI args, bind real listeners, authorize a
// client over the control API, and prove a proxied request actually
// completes -- before confirming a real SIGTERM (the same signal
// run() listens for via signal.NotifyContext) shuts it down cleanly.
func TestRun_HTTPProxyEndToEndAndGracefulShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	controlSock := shortControlSocket(t)
	const httpProxyAddr = "127.0.0.1:18128"

	args := []string{
		"--storage", "posix://" + tmpDir,
		"--control", "unix://" + controlSock,
		"--listen-http-proxy", "tcp://" + httpProxyAddr,
		"--cluster-key", testClusterKey(t),
		"--log-level", "error",
	}

	runErr := make(chan error, 1)
	go func() { runErr <- run(args) }()

	waitForListener(t, "unix", controlSock, 5*time.Second)
	waitForListener(t, "tcp", httpProxyAddr, 5*time.Second)

	client := controlClient(controlSock)
	putRules(t, client, "/rules/default", testPermissiveDefault)
	// The client dialing the proxy below does so from 127.0.0.1, so that
	// is the loopback client identity the connection-phase match needs an
	// authorized rule file for; an empty match{} matches any host/port/proto.
	putRules(t, client, "/rules/127.0.0.1", `{"http":[{"match":{}}]}`)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from origin, path=%s", r.URL.Path)
	}))
	defer origin.Close()

	proxyClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: httpProxyAddr})},
	}
	resp, err := proxyClient.Get(origin.URL + "/hi")
	if err != nil {
		t.Fatalf("proxied GET: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if want := "hello from origin, path=/hi"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}

	terminateAndAwait(t, runErr, 10*time.Second)
}

// TestRun_HTTPSProxyEndToEndAndGracefulShutdown covers listenHTTPSProxy:
// the TLS-terminated explicit listener wired up alongside the plain one
// whenever --listen-https-proxy is set (run() calls listenHTTPProxy
// unconditionally, so --listen-http-proxy stays configured too here --
// exercising an https-only node isn't this test's job). The request is
// routed through the TLS-terminated listener specifically, so both
// listenHTTPSProxy's self-cert setup and its own acceptLoop goroutine
// actually run.
func TestRun_HTTPSProxyEndToEndAndGracefulShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	controlSock := shortControlSocket(t)
	const httpProxyAddr = "127.0.0.1:18228"
	const httpsProxyAddr = "127.0.0.1:18229"

	args := []string{
		"--storage", "posix://" + tmpDir,
		"--control", "unix://" + controlSock,
		"--listen-http-proxy", "tcp://" + httpProxyAddr,
		"--listen-https-proxy", "tcp://" + httpsProxyAddr,
		"--cluster-key", testClusterKey(t),
		"--log-level", "error",
	}

	runErr := make(chan error, 1)
	go func() { runErr <- run(args) }()

	waitForListener(t, "unix", controlSock, 5*time.Second)
	waitForListener(t, "tcp", httpsProxyAddr, 5*time.Second)

	client := controlClient(controlSock)
	putRules(t, client, "/rules/default", testPermissiveDefault)
	putRules(t, client, "/rules/127.0.0.1", `{"http":[{"match":{}}]}`)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello via tls-terminated proxy, path=%s", r.URL.Path)
	}))
	defer origin.Close()

	proxyClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "https", Host: httpsProxyAddr}),
			// The listener's self-cert is exercised for real (a genuine TLS
			// handshake happens); its trust chain back to the CA is already
			// covered by internal/proxy/https_proxy_test.go, so verification
			// is skipped here rather than duplicated -- this test's job is
			// listenHTTPSProxy/acceptLoop wiring, not cert trust.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := proxyClient.Get(origin.URL + "/hi")
	if err != nil {
		t.Fatalf("proxied GET via https listener: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if want := "hello via tls-terminated proxy, path=/hi"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}

	terminateAndAwait(t, runErr, 10*time.Second)
}
