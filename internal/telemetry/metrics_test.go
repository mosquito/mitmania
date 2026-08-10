package telemetry

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSetupMetrics_EmptyURLDisabled(t *testing.T) {
	res, err := buildResource("")
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}
	mp, err := setupMetrics("", res)
	if err != nil {
		t.Fatalf("setupMetrics: %v", err)
	}
	defer mp.Shutdown(context.Background())

	if mp.Addr != "" {
		t.Errorf("Addr = %q, want empty (no scrape server when disabled)", mp.Addr)
	}
	if mp.Meter == nil {
		t.Fatalf("Meter is nil even when disabled — every instrument-creation call site must still work")
	}
	// NewMetrics + a recording call must not panic/error even with no
	// reader attached (measurements are simply discarded).
	m, err := NewMetrics(mp.Meter)
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	m.Request(context.Background(), "h1", "ok", "2xx", time.Millisecond)
}

func TestSetupMetrics_RejectsUnsupportedScheme(t *testing.T) {
	res, _ := buildResource("")
	if _, err := setupMetrics("otlp+grpc://127.0.0.1:4317", res); err == nil {
		t.Fatalf("expected an error for a scheme that isn't http:// or unix://")
	}
}

func TestSetupMetrics_ServesScrapeEndpoint(t *testing.T) {
	res, err := buildResource("")
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}
	mp, err := setupMetrics("http://127.0.0.1:0/metrics", res)
	if err != nil {
		t.Fatalf("setupMetrics: %v", err)
	}
	defer mp.Shutdown(context.Background())

	if mp.Addr == "" {
		t.Fatalf("Addr is empty, want the actual bound address")
	}

	m, err := NewMetrics(mp.Meter)
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	m.Request(context.Background(), "h1", "ok", "2xx", 15*time.Millisecond)

	resp, err := http.Get("http://" + mp.Addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "mitmania_requests_total") {
		t.Errorf("scrape body missing mitmania_requests_total; got:\n%s", body)
	}
}

func TestSetupMetrics_UnixSocketServesScrapeEndpoint(t *testing.T) {
	res, err := buildResource("")
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}
	// Not t.TempDir(): on macOS its nested-by-test-name path routinely
	// exceeds AF_UNIX's ~104-byte sun_path limit (same issue documented
	// elsewhere in this codebase, e.g. session's own unix-socket tests).
	sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("mitmania-otel-test-%d.sock", os.Getpid()))
	os.Remove(sockPath)
	t.Cleanup(func() { os.Remove(sockPath) })

	mp, err := setupMetrics("unix://"+sockPath, res)
	if err != nil {
		t.Fatalf("setupMetrics: %v", err)
	}
	defer mp.Shutdown(context.Background())

	client := http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sockPath)
		},
	}}
	resp, err := client.Get("http://unix/metrics")
	if err != nil {
		t.Fatalf("GET over unix socket: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestSetupMetrics_CustomPathHonored(t *testing.T) {
	res, _ := buildResource("")
	mp, err := setupMetrics("http://127.0.0.1:0/custom/scrape/path", res)
	if err != nil {
		t.Fatalf("setupMetrics: %v", err)
	}
	defer mp.Shutdown(context.Background())

	if mp.Path != "/custom/scrape/path" {
		t.Fatalf("Path = %q, want /custom/scrape/path", mp.Path)
	}
	resp, err := http.Get("http://" + mp.Addr + "/custom/scrape/path")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// The default "/metrics" must NOT also be served — the URL's path is
	// authoritative, not merely a suffix/alias.
	resp2, err := http.Get("http://" + mp.Addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Errorf("/metrics unexpectedly served alongside the custom path")
	}
}

func TestSetupMetrics_Shutdown_StopsScrapeServer(t *testing.T) {
	res, _ := buildResource("")
	mp, err := setupMetrics("http://127.0.0.1:0/metrics", res)
	if err != nil {
		t.Fatalf("setupMetrics: %v", err)
	}
	addr := mp.Addr

	if err := mp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if _, err := http.Get("http://" + addr + "/metrics"); err == nil {
		t.Fatalf("GET /metrics succeeded after Shutdown, want connection refused")
	}
}
