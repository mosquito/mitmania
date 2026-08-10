// Package telemetry wires mitmania's OpenTelemetry metrics and traces —
// off by default, each signal enabled only by its own sink flag. Logs
// stay on the separate slog pipeline (--log-level/--log-format, see
// cmd/mitmania); this package never touches them.
package telemetry

import (
	"context"
	"fmt"
	"time"
)

// Config is the subset of config.Config Setup needs — a narrow local
// type (not an import of internal/config) so this package stays a leaf
// dependency, same reasoning as proxy.CertFactory's own narrow interface
// onto *cert.CertFactory.
type Config struct {
	MetricsURL  string  // --otel-metrics
	TracesURL   string  // --otel-traces
	Resource    string  // --otel-resource
	SampleRatio float64 // --otel-sample-ratio

	SpoolMaxSize int           // --otel-spool-max-size, bytes (file:// traces sink rotation)
	SpoolMaxAge  time.Duration // --otel-spool-max-age (file:// traces sink rotation)
}

// Providers bundles everything Setup produces: the metrics and traces
// providers plus the ready-to-use *Metrics instrument set built from the
// metrics provider's meter. All three are nil-safe at every call site
// (see Metrics' own doc comment) so wiring telemetry through the rest of
// the codebase never needs an "is telemetry enabled" branch.
type Providers struct {
	Metrics *MetricsProvider
	Traces  *TracesProvider
	M       *Metrics

	// MetricsAddr is the prometheus scrape endpoint's bound address, or
	// "" if --otel-metrics wasn't given — surfaced here so main.go can
	// log it without reaching into Metrics.
	MetricsAddr string
}

// Setup builds the resource, metrics provider (+ *Metrics instruments),
// and traces provider from cfg — the single entry point cmd/mitmania
// calls at startup. Every field of the returned Providers is safe to use
// even when both sinks are disabled (cfg.MetricsURL == cfg.TracesURL ==
// ""): instruments/spans are simply created and immediately discarded,
// never exported anywhere, so call sites never special-case "telemetry
// off."
func Setup(ctx context.Context, cfg Config) (*Providers, error) {
	res, err := buildResource(cfg.Resource)
	if err != nil {
		return nil, fmt.Errorf("telemetry: --otel-resource: %w", err)
	}

	mp, err := setupMetrics(cfg.MetricsURL, res)
	if err != nil {
		return nil, err
	}
	metrics, err := NewMetrics(mp.Meter)
	if err != nil {
		mp.Shutdown(ctx)
		return nil, err
	}

	tp, err := setupTraces(ctx, cfg.TracesURL, cfg.SampleRatio, res, cfg.SpoolMaxSize, cfg.SpoolMaxAge)
	if err != nil {
		mp.Shutdown(ctx)
		return nil, err
	}

	return &Providers{Metrics: mp, Traces: tp, M: metrics, MetricsAddr: mp.Addr}, nil
}

// Shutdown flushes and closes both providers, collecting errors from
// each rather than stopping at the first.
func (p *Providers) Shutdown(ctx context.Context) error {
	var errs []error
	if err := p.Metrics.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := p.Traces.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("telemetry: shutdown: %v", errs)
}
