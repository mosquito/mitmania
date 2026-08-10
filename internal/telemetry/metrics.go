package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
)

// defaultScrapePath is used when --otel-metrics's URL has no path
// component (e.g. "http://127.0.0.1:9760" alone) — the common case where
// an operator doesn't care to customize it.
const defaultScrapePath = "/metrics"

// MetricsProvider bundles the SDK MeterProvider instruments are created
// from with the scrape HTTP server serving them (when enabled) — both
// share one lifecycle, tied to --otel-metrics.
type MetricsProvider struct {
	Provider *sdkmetric.MeterProvider
	Meter    metric.Meter

	// Addr is the scrape endpoint's actual bound address (host:port,
	// post-listen so a ":0" test bind resolves to its real port), empty
	// when metrics are disabled.
	Addr string
	// Path is the scrape endpoint's URL path (from --otel-metrics's URL,
	// default "/metrics"), empty when metrics are disabled.
	Path string

	srv *http.Server
}

// setupMetrics starts an HTTP scrape endpoint at the exact URL named by
// rawURL — the only supported metrics sink shape, deliberately a plain
// http:// (or unix://) URL rather than e.g. "prometheus://", which reads
// as ambiguous with Prometheus's OWN remote-write push protocol; this is
// pull-only, the literal URL a Prometheus server's scrape_configs (or a
// unix_http_sd-style local scraper) would target. Empty rawURL disables
// metrics entirely but still returns a fully usable MeterProvider (just
// with no reader attached, so every recorded measurement is simply
// discarded) — every instrument-creation call site works unconditionally
// regardless of whether metrics are enabled, mirroring how a nil
// *slog.Logger disables logging elsewhere in this codebase without every
// call site needing a nil check.
func setupMetrics(rawURL string, res *sdkresource.Resource) (*MetricsProvider, error) {
	if rawURL == "" {
		mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res))
		return &MetricsProvider{Provider: mp, Meter: mp.Meter("mitmania")}, nil
	}

	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "unix") {
		return nil, fmt.Errorf("telemetry: --otel-metrics: unsupported scheme in %q (need http://host:port/path or unix:///path/to.sock)", rawURL)
	}

	var network, addr, path string
	switch u.Scheme {
	case "http":
		if u.Host == "" {
			return nil, fmt.Errorf("telemetry: --otel-metrics: %q needs a host:port to bind", rawURL)
		}
		network, addr = "tcp", u.Host
		path = u.Path
	case "unix":
		// url.Parse splits "unix:///path/to.sock" into Host="" Path="/path/to.sock" —
		// same convention config.ParseAddr/storage.Open already use for
		// unix:// elsewhere in this codebase. A unix socket has no
		// natural syntax for ALSO carrying an HTTP request path, so the
		// scrape path is always defaultScrapePath here.
		if u.Path == "" {
			return nil, fmt.Errorf("telemetry: --otel-metrics: %q needs a socket path", rawURL)
		}
		network, addr = "unix", u.Path
		if err := os.Remove(addr); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("telemetry: --otel-metrics: clear stale socket %s: %w", addr, err)
		}
	}
	if path == "" {
		path = defaultScrapePath
	}

	registry := prometheus.NewRegistry()
	// WithoutScopeInfo: this process has exactly one meter/scope ("mitmania")
	// for the whole lifetime of the program, so the exporter's default
	// otel_scope_name/otel_scope_schema_url/otel_scope_version labels on
	// every single series are pure noise — always the same value (or
	// always empty), never discriminating anything (caught via a live
	// scrape during manual testing).
	exporter, err := otelprometheus.New(otelprometheus.WithRegisterer(registry), otelprometheus.WithoutScopeInfo())
	if err != nil {
		return nil, fmt.Errorf("telemetry: prometheus exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter), sdkmetric.WithResource(res))

	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, fmt.Errorf("telemetry: --otel-metrics: listen %s %s: %w", network, addr, err)
	}
	if network == "unix" {
		if err := os.Chmod(addr, 0o600); err != nil {
			ln.Close()
			return nil, fmt.Errorf("telemetry: --otel-metrics: chmod %s: %w", addr, err)
		}
	}
	mux := http.NewServeMux()
	mux.Handle(path, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln) //nolint:errcheck // ErrServerClosed on clean Shutdown is expected, nothing else to do with it

	return &MetricsProvider{
		Provider: mp,
		Meter:    mp.Meter("mitmania"),
		Addr:     ln.Addr().String(),
		Path:     path,
		srv:      srv,
	}, nil
}

// Shutdown stops the scrape server (if running) and flushes/closes the
// MeterProvider.
func (p *MetricsProvider) Shutdown(ctx context.Context) error {
	var err error
	if p.srv != nil {
		err = p.srv.Shutdown(ctx)
	}
	if shutdownErr := p.Provider.Shutdown(ctx); shutdownErr != nil && err == nil {
		err = shutdownErr
	}
	return err
}
