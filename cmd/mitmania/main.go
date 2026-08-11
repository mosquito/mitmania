// Command mitmania is an intercepting MITM proxy.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"mitmania/internal/cert"
	"mitmania/internal/config"
	"mitmania/internal/control"
	"mitmania/internal/flowsink"
	"mitmania/internal/outcall"
	"mitmania/internal/proxy"
	"mitmania/internal/rules"
	"mitmania/internal/session"
	"mitmania/internal/storage"
	"mitmania/internal/telemetry"
)

// version is set via -ldflags "-X main.version=..." at build time (see
// Makefile); left as the zero value for `go run`/`go build` without flags.
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, config.ErrHelp) {
			// config.Parse already printed usage.
			return
		}
		fmt.Fprintln(os.Stderr, "mitmania:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := config.Parse(args)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel, cfg.LogFormat)
	log.Info("starting", "version", version)
	logConfig(log, cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tp, err := telemetry.Setup(ctx, telemetry.Config{
		MetricsURL:   cfg.OtelMetrics,
		TracesURL:    cfg.OtelTraces,
		Resource:     cfg.OtelResource,
		SampleRatio:  cfg.OtelSampleRatio,
		SpoolMaxSize: cfg.OtelSpoolMaxSize,
		SpoolMaxAge:  cfg.OtelSpoolMaxAge,
	})
	if err != nil {
		return fmt.Errorf("telemetry: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tp.Shutdown(shutdownCtx); err != nil {
			log.Warn("telemetry shutdown", "err", err)
		}
	}()
	if tp.MetricsAddr != "" {
		log.Info("telemetry: metrics scrape listening", "address", tp.MetricsAddr, "path", tp.Metrics.Path)
	}

	store, err := storage.Open(cfg.Storage)
	if err != nil {
		return fmt.Errorf("--storage: %w", err)
	}
	// WithTelemetry must wrap the raw store (before WithLogging or any
	// other decorator) — it identifies the concrete backend via a type
	// switch that only sees through to *PosixStorage/*S3Storage on the
	// undecorated value (see WithTelemetry's own doc comment).
	store = storage.WithTelemetry(store, tp.M, tp.Traces.Tracer)
	store = storage.WithLogging(store, log)

	ca, err := cert.LoadOrGenerateCA(ctx, store, cfg.ClusterKey, cert.WithCALogger(log))
	if err != nil {
		return fmt.Errorf("root CA: %w", err)
	}
	caAction := "loaded existing"
	if ca.Generated {
		caAction = "generated new"
	}
	fp := sha256.Sum256(ca.Cert.Raw)
	log.Info("root CA ready", "action", caAction, "subject", ca.Cert.Subject.String(), "fingerprint_sha256", fmt.Sprintf("%x", fp))

	cache := cert.NewCertCache(store, cfg.ClusterKey, ca, cert.WithCacheLogger(log))
	keys := cert.DetKeyDeriver{ClusterKey: cfg.ClusterKey}
	factory := cert.NewCertFactory(ca, cache, keys, cert.WithFactoryLogger(log), cert.WithFactoryMetrics(tp.M), cert.WithFactoryTracer(tp.Traces.Tracer))

	ruleStore := rules.NewRuleStore(store)
	if err := ruleStore.EnsureDefault(ctx); err != nil {
		return fmt.Errorf("rules/default: %w", err)
	}
	engine := rules.NewRuleEngine(ruleStore, rules.WithLogger(log), rules.WithMetrics(tp.M), rules.WithTracer(tp.Traces.Tracer))
	flow := &flowsink.Counters{}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})

	outcallSvc := outcall.NewService(cfg.OutcallConnectTimeout, cfg.OutcallReadTimeout, cfg.OutcallMaxInflight, outcall.WithLogger(log), outcall.WithMetrics(tp.M), outcall.WithTracer(tp.Traces.Tracer))

	handler := &proxy.Http1Handler{
		TLS:                 &proxy.TLSService{Factory: factory, Metrics: tp.M},
		Rules:               engine,
		Outcall:             outcallSvc,
		Flow:                flow,
		Logger:              log,
		NoAccessLog:         cfg.NoAccessLogs,
		CAPEM:               caPEM,
		HeaderLimit:         cfg.HTTPHeaderLimit,
		BodyWindow:          cfg.HTTPBodyWindow,
		ReadTimeout:         cfg.HTTPReadTimeout,
		HTTP2ConnectTimeout: cfg.HTTP2ConnectTimeout,
		HTTP2ConnectTries:   cfg.HTTP2ConnectTries,
		HTTP2ReadTimeout:    cfg.HTTP2ReadTimeout,
		Metrics:             tp.M,
		Tracer:              tp.Traces.Tracer,
		TrustedProxies:      cfg.TrustedProxies,
	}
	dispatcher := &proxy.Dispatcher{
		Selector: &proxy.Selector{Default: handler},
		Dialer:   proxy.NewUpstreamDialer(cfg.HTTPConnectTimeout, cfg.HTTPConnectTries, proxy.WithDialerLogger(log), proxy.WithDialerMetrics(tp.M), proxy.WithDialerTracer(tp.Traces.Tracer)),
		Metrics:  tp.M,
		Tracer:   tp.Traces.Tracer,
	}

	ctrl := &control.Control{
		CA:      ca,
		Cache:   cache,
		Store:   ruleStore,
		Outcall: outcallSvc,
		Flow:    flow,
		Logger:  log,
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := ctrl.ListenAndServe(ctx, cfg.Control.Network(), cfg.Control.String()); err != nil {
			log.Error("control API stopped", "err", err)
			stop()
		}
	}()

	// Every data listener is independently optional now (config.Parse only
	// requires at least one of the four) — bind whichever are configured,
	// each in the same acquire-then-register-cleanup-then-run-accept-loop
	// shape, so adding --listen-http-tproxy/--listen-http-redirect didn't
	// need a special case beyond their own listenX functions.
	var listeners []session.Acceptor
	closeAll := func() {
		for _, a := range listeners {
			a.Close()
		}
	}

	if cfg.HTTPProxy != nil {
		acceptor, err := listenHTTPProxy(cfg.HTTPProxy)
		if err != nil {
			stop()
			closeAll()
			wg.Wait()
			return fmt.Errorf("listen --listen-http-proxy: %w", err)
		}
		log.Info("explicit proxy listening", "network", cfg.HTTPProxy.Network(), "address", cfg.HTTPProxy.String())
		listeners = append(listeners, acceptor)
	}

	if cfg.HTTPSProxy != nil {
		acceptor, err := listenHTTPSProxy(ctx, cfg.HTTPSProxy, factory)
		if err != nil {
			stop()
			closeAll()
			wg.Wait()
			return fmt.Errorf("listen --listen-https-proxy: %w", err)
		}
		log.Info("https proxy listening", "network", cfg.HTTPSProxy.Addr.Network(), "address", cfg.HTTPSProxy.Addr.String(), "cn", cfg.HTTPSProxy.Names[0], "names", cfg.HTTPSProxy.Names)
		listeners = append(listeners, acceptor)
	}

	if cfg.HTTPTProxy != nil {
		acceptor, err := listenTProxy(cfg.HTTPTProxy)
		if err != nil {
			stop()
			closeAll()
			wg.Wait()
			return fmt.Errorf("listen --listen-http-tproxy: %w", err)
		}
		log.Info("tproxy listening", "network", cfg.HTTPTProxy.Network(), "address", cfg.HTTPTProxy.String())
		listeners = append(listeners, acceptor)
	}

	if cfg.HTTPRedirect != nil {
		acceptor, err := listenRedirect(cfg.HTTPRedirect)
		if err != nil {
			stop()
			closeAll()
			wg.Wait()
			return fmt.Errorf("listen --listen-http-redirect: %w", err)
		}
		log.Info("redirect listening", "network", cfg.HTTPRedirect.Network(), "address", cfg.HTTPRedirect.String())
		listeners = append(listeners, acceptor)
	}

	log.Info("control API listening", "network", cfg.Control.Network(), "address", cfg.Control.String())

	for _, acceptor := range listeners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			acceptor.Close()
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			acceptLoop(ctx, acceptor, dispatcher, log)
		}()
	}

	wg.Wait()
	return nil
}

// newLogger builds mitmania's structured logger at --log-level's
// configured verbosity and --log-format's output shape (plain/json/cat),
// rendering level names via config.LevelName rather than slog's default
// abbreviations.
func newLogger(level slog.Level, format string) *slog.Logger {
	replaceAttr := func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.LevelKey {
			if lvl, ok := a.Value.Any().(slog.Level); ok {
				a.Value = slog.StringValue(config.LevelName(lvl))
			}
		}
		return a
	}
	opts := &slog.HandlerOptions{Level: level, ReplaceAttr: replaceAttr}

	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	case "cat":
		return slog.New(&catHandler{level: level, w: os.Stderr, mu: &sync.Mutex{}})
	default: // "plain"
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
}

// catHandler is --log-format=cat: the message followed by its fields as
// plain "key=value" pairs, space-separated — no timestamp, level, or
// quoting/escaping machinery. Only the two built-ins (time, level) are
// dropped; every attr passed to the log call (and any bound via .With)
// still prints — a record with its fields stripped entirely isn't
// readable, just shorter. For quick manual tailing/piping where the
// usual structured framing is more noise than signal, but the data
// itself still matters.
type catHandler struct {
	level slog.Leveler
	w     io.Writer
	mu    *sync.Mutex
	attrs []slog.Attr // accumulated via WithAttrs
}

func (h *catHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *catHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	for _, a := range h.attrs {
		writeCatAttr(&b, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeCatAttr(&b, a)
		return true
	})
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func writeCatAttr(b *strings.Builder, a slog.Attr) {
	if a.Equal(slog.Attr{}) {
		return
	}
	b.WriteByte(' ')
	b.WriteString(a.Key)
	b.WriteByte('=')
	fmt.Fprintf(b, "%v", a.Value.Any())
}

func (h *catHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &catHandler{level: h.level, w: h.w, mu: h.mu, attrs: merged}
}

func (h *catHandler) WithGroup(string) slog.Handler { return h } // no grouped attrs anywhere in this codebase

// logConfig logs the complete, effective configuration at Info level —
// one line per phase/subsystem, so an operator can see the whole startup
// picture without cross-referencing flags to defaults by hand. Anything
// URL-embedded that could be a credential (--storage's s3://KEY:SECRET@...)
// is masked first; cfg.ClusterKey itself is never logged, in any form,
// full stop — it's not a URL, so it isn't reachable through maskURL, and
// nothing here reads that field to log it some other way.
func logConfig(log *slog.Logger, cfg *config.Config) {
	log.Info("config: storage", "url", maskURL(cfg.Storage))
	httpProxy := "(disabled)"
	if cfg.HTTPProxy != nil {
		httpProxy = cfg.HTTPProxy.Network() + "://" + cfg.HTTPProxy.String()
	}
	httpsProxy := "(disabled)"
	if cfg.HTTPSProxy != nil {
		httpsProxy = cfg.HTTPSProxy.Addr.Network() + "://" + cfg.HTTPSProxy.Addr.String() + " (cn=" + strings.Join(cfg.HTTPSProxy.Names, ",") + ")"
	}
	tproxy := "(disabled)"
	if cfg.HTTPTProxy != nil {
		tproxy = cfg.HTTPTProxy.Network() + "://" + cfg.HTTPTProxy.String()
	}
	redirect := "(disabled)"
	if cfg.HTTPRedirect != nil {
		redirect = cfg.HTTPRedirect.Network() + "://" + cfg.HTTPRedirect.String()
	}
	log.Info("config: listeners", "http_proxy", httpProxy, "https_proxy", httpsProxy, "http_tproxy", tproxy, "http_redirect", redirect, "control", cfg.Control.Network()+"://"+cfg.Control.String())
	log.Info("config: http framing", "header_limit", cfg.HTTPHeaderLimit, "body_window", cfg.HTTPBodyWindow)
	log.Info("config: http upstream", "connect_timeout", cfg.HTTPConnectTimeout, "read_timeout", cfg.HTTPReadTimeout, "connect_tries", cfg.HTTPConnectTries)
	log.Info("config: http2 upstream", "connect_timeout", cfg.HTTP2ConnectTimeout, "read_timeout", cfg.HTTP2ReadTimeout, "connect_tries", cfg.HTTP2ConnectTries)
	log.Info("config: outcall", "connect_timeout", cfg.OutcallConnectTimeout, "read_timeout", cfg.OutcallReadTimeout, "max_inflight", cfg.OutcallMaxInflight)
	trustedProxies := "(disabled)"
	if len(cfg.TrustedProxies) > 0 {
		parts := make([]string, len(cfg.TrustedProxies))
		for i, p := range cfg.TrustedProxies {
			parts[i] = p.String()
		}
		trustedProxies = strings.Join(parts, ",")
	}
	log.Info("config: trusted proxies", "cidrs", trustedProxies)
	log.Info("config: logging", "level", config.LevelName(cfg.LogLevel), "format", cfg.LogFormat, "access_logs", !cfg.NoAccessLogs)

	otelMetrics, otelTraces := "(disabled)", "(disabled)"
	if cfg.OtelMetrics != "" {
		otelMetrics = maskURL(cfg.OtelMetrics)
	}
	if cfg.OtelTraces != "" {
		otelTraces = maskURL(cfg.OtelTraces)
	}
	log.Info("config: telemetry", "metrics", otelMetrics, "traces", otelTraces, "sample_ratio", cfg.OtelSampleRatio,
		"propagate_upstream", cfg.OtelPropagateUpstream, "continue_client", cfg.OtelContinueClient, "resource", cfg.OtelResource)
}

// maskURL redacts a URL's userinfo (username and password alike — an S3
// access key ID is sensitive enough on its own to mask, not just the
// secret key) before it's ever logged, replacing it with the literal,
// unmistakably-a-placeholder marker "<REDACTED>". Built by hand rather
// than via url.User/URL.String() — that path percent-encodes the angle
// brackets into "%3CREDACTED%3E", which reads like noise, not a marker.
// A URL with no userinfo (e.g. posix:///path) passes through unchanged.
// A raw value that doesn't even parse as a URL is masked outright rather
// than logged verbatim, since there's no way to know whether it *would*
// have contained a credential.
func maskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<REDACTED>"
	}
	if u.User == nil {
		return u.String()
	}
	masked := *u
	masked.User = nil
	prefix := u.Scheme + "://"
	return prefix + "<REDACTED>@" + strings.TrimPrefix(masked.String(), prefix)
}

func listenHTTPProxy(addr *config.Addr) (session.Acceptor, error) {
	ln, err := net.Listen(addr.Network(), addr.String())
	if err != nil {
		return nil, err
	}
	return session.NewHTTPProxyAcceptor(ln, "http_proxy"), nil
}

// listenHTTPSProxy binds --listen-https-proxy as a TLS-terminating
// listener wrapping the same HTTPProxyAcceptor used by the plain
// --listen-http-proxy path: tls.Listener already satisfies net.Listener,
// so no new Acceptor type is needed, and the resulting sessions flow
// through the identical Dispatcher/Http1Handler pipeline. The listener's
// own identity cert is minted once (or served from cache) via
// CertFactory.SelfCert, keyed on the URL's repeatable ?cn= (default
// ["Internal Proxy"]) and persisted in the same leaf cache used for any
// MITM'd leaf.
func listenHTTPSProxy(ctx context.Context, addr *config.HTTPSProxyAddr, factory *cert.CertFactory) (session.Acceptor, error) {
	leaf, err := factory.SelfCert(ctx, addr.Names)
	if err != nil {
		return nil, fmt.Errorf("self-cert for %v: %w", addr.Names, err)
	}

	ln, err := net.Listen(addr.Addr.Network(), addr.Addr.String())
	if err != nil {
		return nil, err
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	return session.NewHTTPProxyAcceptor(tlsLn, "https_proxy"), nil
}

// listenRedirect binds --listen-http-redirect: an ordinary listener (no
// special socket options needed to bind it — REDIRECT's DNAT rewriting
// happens entirely on the kernel/nftables side before the connection is
// even accepted), wrapped in session.RedirectAcceptor to recover each
// connection's true pre-NAT destination via SO_ORIGINAL_DST. Linux-only;
// see internal/session/redirect_acceptor_linux.go and its _other.go
// build-tagged stub.
func listenRedirect(addr *config.Addr) (session.Acceptor, error) {
	ln, err := net.Listen(addr.Network(), addr.String())
	if err != nil {
		return nil, err
	}
	return session.NewRedirectAcceptor(ln, "http_redirect")
}

// listenTProxy binds --listen-http-tproxy via session.ListenTProxy, not
// plain net.Listen — unlike REDIRECT, TPROXY needs IP_TRANSPARENT set on
// the listening socket itself before bind (see ListenTProxy's doc
// comment), the prerequisite for the kernel to deliver a connection
// whose destination isn't this listener's own address at all.
// Linux-only; see internal/session/tproxy_acceptor_linux.go and its
// _other.go build-tagged stub.
func listenTProxy(addr *config.Addr) (session.Acceptor, error) {
	ln, err := session.ListenTProxy(addr.Network(), addr.String())
	if err != nil {
		return nil, err
	}
	return session.NewTProxyAcceptor(ln, "http_tproxy")
}

func acceptLoop(ctx context.Context, acceptor session.Acceptor, dispatcher *proxy.Dispatcher, log *slog.Logger) {
	for {
		sess, err := acceptor.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Error("accept", "err", err)
			continue
		}
		go dispatcher.Handle(ctx, sess)
	}
}
