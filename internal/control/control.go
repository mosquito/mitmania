// Package control implements mitmania's control API: an HTTP server,
// reachable over a unix socket or tcp, exposing CA/cache/rule management
// and stats — plus a small embedded SPA for the same, since the JSON API
// alone isn't pleasant to drive by hand.
package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"mitmania/internal/cert"
	"mitmania/internal/flowsink"
	"mitmania/internal/outcall"
	"mitmania/internal/rules"
)

// maxRuleFileBytes bounds a PUT /rules/{ip} request body — rule files are
// small, hand-authored JSON, not a place to accept unbounded input.
const maxRuleFileBytes = 1 << 20 // 1 MiB

// Control wires the control API to the subsystems it manages. Shutdown is
// process-level (signal-triggered, see cmd/mitmania) — there's no HTTP
// endpoint for it; killing the process is enough.
type Control struct {
	CA    *cert.CA
	Cache *cert.CertCache
	Store *rules.RuleStore
	Flow  *flowsink.Counters // nil is fine: /stats reports zeros

	// Outcall backs the load-time probe every webhook/header.fetch action
	// gets on PUT /rules/{ip} — nil disables the probe entirely,
	// same as passing ?validate=false on every request, since there'd be
	// nothing to probe with.
	Outcall *outcall.Service

	// Logger, if set, receives one record per mutating control-API call
	// (rule PUT/DELETE, cache flush) — nil disables it, same convention
	// as Http1Handler.Logger.
	Logger *slog.Logger
}

// logAction writes one control-API record if Logger is configured — the
// control-plane analog of Http1Handler's access log: who changed what,
// and whether it succeeded. err is omitted from the record when nil.
func (c *Control) logAction(r *http.Request, action, target string, err error) {
	if c.Logger == nil {
		return
	}
	attrs := []any{
		slog.String("remote", r.RemoteAddr),
		slog.String("action", action),
		slog.String("target", target),
	}
	if err != nil {
		attrs = append(attrs, slog.String("err", err.Error()))
		c.Logger.Warn("control action failed", attrs...)
		return
	}
	c.Logger.Info("control action", attrs...)
}

// Handler returns the control API's http.Handler: the JSON/plain-text
// management routes registered below, plus the embedded SPA at "/" and
// its assets.
func (c *Control) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ca.pem", c.handleCAPEM)
	mux.HandleFunc("GET /ca.der", c.handleCADER)
	mux.HandleFunc("GET /stats", c.handleStats)
	mux.HandleFunc("GET /rules/default", c.handleGetDefault)
	mux.HandleFunc("PUT /rules/default", c.handlePutDefault)
	mux.HandleFunc("GET /rules/{ip}", c.handleGetRule)
	mux.HandleFunc("PUT /rules/{ip}", c.handlePutRule)
	mux.HandleFunc("DELETE /rules/{ip}", c.handleDeleteRule)
	mux.HandleFunc("DELETE /cache", c.handleFlushCache)
	mux.Handle("GET /", spaHandler())
	return mux
}

// ListenAndServe binds network/address (e.g. "unix", "/run/mitmania.sock",
// or "tcp", "127.0.0.1:5555" — both network types are supported) and
// serves until ctx is canceled, then shuts down gracefully.
func (c *Control) ListenAndServe(ctx context.Context, network, address string) error {
	if network == "unix" {
		if err := os.Remove(address); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("control: clear stale socket %s: %w", address, err)
		}
	}

	ln, err := net.Listen(network, address)
	if err != nil {
		return fmt.Errorf("control: listen %s %s: %w", network, address, err)
	}
	if network == "unix" {
		if err := os.Chmod(address, 0o600); err != nil {
			ln.Close()
			return fmt.Errorf("control: chmod %s: %w", address, err)
		}
	}

	srv := &http.Server{Handler: c.Handler()}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		if c.Logger != nil {
			c.Logger.Info("control API shutting down")
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
