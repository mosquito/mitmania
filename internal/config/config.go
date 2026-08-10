package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/alecthomas/kong"
)

const minClusterKeyBytes = 32

// ErrHelp is returned by Parse when --help (or -h) was requested and its
// text already printed to stdout — callers should treat this as a clean
// exit(0), not a real error.
var ErrHelp = errors.New("config: help requested")

// storageSchemes are the URL schemes --storage accepts; each backend
// parses the rest of its own URL shape itself (storage.Open) — Parse only
// fails fast on a scheme that's obviously not one of them.
var storageSchemes = map[string]bool{"posix": true, "s3": true}

// defaultStorageURL resolves --storage's default per the XDG Base
// Directory spec: posix://$XDG_CACHE_HOME/mitmania, falling back to
// posix://$HOME/.cache/mitmania when XDG_CACHE_HOME is unset or (per
// spec) not an absolute path.
func defaultStorageURL() string {
	if xdg := os.Getenv("XDG_CACHE_HOME"); filepath.IsAbs(xdg) {
		return "posix://" + filepath.Join(xdg, "mitmania")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return "posix://" + filepath.Join(home, ".cache", "mitmania")
}

// defaultControlPath resolves --control's default socket path:
// $XDG_RUNTIME_DIR/mitmania.sock. Unlike XDG_CACHE_HOME, the spec defines no
// filesystem fallback for XDG_RUNTIME_DIR — it's meant to be tmpfs-backed
// with specific ownership/permissions set up by the session manager (e.g.
// systemd-logind), not something safe to synthesize a path for. So when
// it's unset (or not absolute), there is no default: the caller must pass
// --control explicitly.
func defaultControlPath() string {
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "mitmania.sock")
	}
	return ""
}

// Config is mitmania's fully parsed and validated CLI configuration.
type Config struct {
	// Storage is a validated (scheme-checked, not yet opened) --storage
	// URL: "posix:///path" or "s3://KEY:SECRET@host/?bucket=...
	// &region=...". storage.Open(cfg.Storage) does the actual parsing of
	// everything past the scheme and constructs the backend — kept out
	// of config, which only validates flag shape, same division as every
	// other flag here.
	Storage string

	HTTPProxy    *Addr           // --listen-http-proxy; explicit CONNECT/absolute-form proxy
	HTTPSProxy   *HTTPSProxyAddr // --listen-https-proxy; TLS-terminated explicit proxy (opt-in)
	HTTPTProxy   *Addr           // --listen-http-tproxy; not yet implemented
	HTTPRedirect *Addr           // --listen-http-redirect; not yet implemented

	Control Addr // --control

	ClusterKey []byte

	// HTTPHeaderLimit and HTTPBodyWindow are Http1Handler's own framing
	// bounds — protocol-specific, not core config, but parsed here
	// alongside everything else.
	HTTPHeaderLimit int // --http-header-limit, bytes
	HTTPBodyWindow  int // --http-body-window, bytes

	// Upstream connect/read timeouts and connect retry counts. h1 and h2
	// get independent knobs: an h1 read deadline is per-connection, an h2
	// read timeout is per-stream (one h2 connection multiplexes many
	// concurrent streams with independent lifetimes) — different
	// mechanisms, so different flags.
	HTTPConnectTimeout  time.Duration // --http-timeout-connect, seconds
	HTTPReadTimeout     time.Duration // --http-timeout-read, seconds
	HTTPConnectTries    int           // --http-connect-tries
	HTTP2ConnectTimeout time.Duration // --http2-timeout-connect, seconds
	HTTP2ReadTimeout    time.Duration // --http2-timeout-read, seconds
	HTTP2ConnectTries   int           // --http2-connect-tries

	// Outcall (broker) timeouts and concurrency — their own flags,
	// not inherited from --http-*: the broker is expected to answer in
	// milliseconds, so a slow one is an incident, not a wait.
	OutcallConnectTimeout time.Duration // --outcall-timeout-connect, seconds
	OutcallReadTimeout    time.Duration // --outcall-timeout-read, seconds
	OutcallMaxInflight    int           // --outcall-max-inflight

	LogLevel  slog.Level // --log-level: debug/info/warning/error/critical
	LogFormat string     // --log-format: plain/json/cat

	// NoAccessLogs disables just the per-request/per-tunnel access log —
	// every other log record (storage, control, cert, rules,
	// upstream dial/reconnect) is unaffected; this is a volume knob for
	// the one record type that's genuinely one-per-request, not a way to
	// go quiet generally (--log-level already does that).
	NoAccessLogs bool // --no-access-logs

	// Telemetry: OpenTelemetry metrics + traces, off by default —
	// each signal is enabled only when its own sink flag is given. Kept as
	// raw, scheme-validated strings/values here, same division of labor
	// as Storage: config only checks the scheme is one internal/telemetry
	// recognizes, so a full "bad host" or "missing path" error surfaces
	// from Setup, not duplicated here.
	OtelMetrics  string // --otel-metrics: "" (disabled), "http://host:port/path", or "unix:///path/to.sock"
	OtelTraces   string // --otel-traces: "" (disabled), otlp+grpc://, otlp+http://, file://, or stdout://
	OtelResource string // --otel-resource: raw "k=v,k2=v2", parsed by internal/telemetry

	OtelSampleRatio       float64       // --otel-sample-ratio, head sampling (parent-based), [0,1]
	OtelPropagateUpstream bool          // --otel-propagate-upstream
	OtelContinueClient    bool          // --otel-continue-client
	OtelSpoolMaxSize      int           // --otel-spool-max-size, bytes (file:// trace spool rotation)
	OtelSpoolMaxAge       time.Duration // --otel-spool-max-age (file:// trace spool rotation)

	// TrustedProxies names the fronting proxy/LB peers whose
	// X-Forwarded-For/X-Real-IP are honored to recover the real client IP
	// on the explicit listeners — nil (the default) disables recovery
	// entirely, using the accepted socket's peer address verbatim like
	// every listener did before this existed.
	TrustedProxies []netip.Prefix // --trusted-proxies
}

// cliFlags is mitmania's Kong flag grammar: names, short forms, help text,
// and static defaults (shown automatically in --help). Kong also derives
// a MITMANIA_* environment variable for every flag (e.g. --cluster-key ->
// MITMANIA_CLUSTER_KEY) via DefaultEnvars in Parse.
//
// Fields stay loosely typed (string) wherever mitmania has its own decoding
// beyond what Kong does natively — Addr parsing, ParseSize's k/m/g
// suffixes, base64 — so all of that validation logic (and its exact error
// wording) is unchanged from before this migrated off the stdlib flag
// package; Kong only replaces how argv/env become these raw values.
// storage and control default to values that depend on the runtime
// environment (XDG_CACHE_HOME / XDG_RUNTIME_DIR), which a static `default`
// tag can't express — they're left without one and resolved by Parse.
type cliFlags struct {
	Storage string `name:"storage" short:"s" help:"State backend URL for CA, leaf cert cache, and rule files: posix:///path (default $XDG_CACHE_HOME/mitmania, or $HOME/.cache/mitmania), or s3://KEY:SECRET@host/?bucket=...&region=...."`

	ListenHTTPProxy    string `name:"listen-http-proxy" help:"Explicit HTTP(S) proxy address, e.g. tcp://*:3128."`
	ListenHTTPSProxy   string `name:"listen-https-proxy" help:"TLS-terminated explicit proxy address, e.g. tcp://*:443 (port defaults to 443 if omitted); repeatable ?cn=...&cn=... sets its own certificate's identity (first value CN, full list SAN set), default \"Internal Proxy\"."`
	ListenHTTPTProxy   string `name:"listen-http-tproxy" help:"Transparent TPROXY address (not yet implemented)."`
	ListenHTTPRedirect string `name:"listen-http-redirect" help:"Transparent REDIRECT address (not yet implemented)."`

	Control string `name:"control" short:"c" help:"Control API address (default $XDG_RUNTIME_DIR/mitmania.sock; required if XDG_RUNTIME_DIR is unset); may also be tcp://host:port."`

	ClusterKey string `name:"cluster-key" short:"k" help:"Base64-encoded cluster key, >=32 decoded bytes."`

	HTTPHeaderLimit string `name:"http-header-limit" default:"64k" help:"Http1Handler: max bytes for request/status line + headers."`
	HTTPBodyWindow  string `name:"http-body-window" default:"64k" help:"Http1Handler: bytes of body tee'd for inspection before streaming through untouched."`

	HTTPTimeoutConnect int `name:"http-timeout-connect" default:"2" help:"h1: upstream TCP+TLS dial budget, seconds."`
	HTTPTimeoutRead    int `name:"http-timeout-read" default:"60" help:"h1: deadline for the upstream response to start, seconds."`
	HTTPConnectTries   int `name:"http-connect-tries" default:"3" help:"h1: upstream connect attempts before giving up."`

	// Explicit env tags: Kong's DefaultEnvars splits "http2" into "http"+"2"
	// (camelCase digit-boundary rule), which would otherwise derive the
	// surprising MITMANIA_HTTP_2_TIMEOUT_CONNECT instead of the expected
	// MITMANIA_HTTP2_TIMEOUT_CONNECT.
	HTTP2TimeoutConnect int `name:"http2-timeout-connect" default:"2" env:"MITMANIA_HTTP2_TIMEOUT_CONNECT" help:"h2: budget for the upstream h2 preface/SETTINGS exchange, seconds."`
	HTTP2TimeoutRead    int `name:"http2-timeout-read" default:"60" env:"MITMANIA_HTTP2_TIMEOUT_READ" help:"h2: per-stream RoundTrip deadline, seconds."`
	HTTP2ConnectTries   int `name:"http2-connect-tries" default:"3" env:"MITMANIA_HTTP2_CONNECT_TRIES" help:"h2: upstream connection attempts before giving up."`

	OutcallTimeoutConnect int `name:"outcall-timeout-connect" default:"1" help:"Outcall broker: dial budget, seconds."`
	OutcallTimeoutRead    int `name:"outcall-timeout-read" default:"2" help:"Outcall broker: response deadline, seconds."`
	OutcallMaxInflight    int `name:"outcall-max-inflight" default:"64" help:"Outcall broker: process-wide concurrent outcalls."`

	LogLevel     string `name:"log-level" default:"info" help:"Log verbosity: debug, info, warning, error, or critical."`
	LogFormat    string `name:"log-format" default:"plain" help:"Log output format: plain, json (collectors/storage, e.g. VictoriaLogs), or cat (bare message only — no timestamp, level, or fields)."`
	NoAccessLogs bool   `name:"no-access-logs" help:"Disable the per-request/per-tunnel access log; every other log record is unaffected."`

	OtelMetrics  string `name:"otel-metrics" help:"Metrics sink, off unless set: http://host:port/path (pull scrape endpoint at that exact URL) or unix:///path/to.sock — the only supported metrics sinks."`
	OtelTraces   string `name:"otel-traces" help:"Traces sink, off unless set: otlp+grpc://host:4317, otlp+http://host:4318, file:///path/ (JSONL spool), or stdout://."`
	OtelResource string `name:"otel-resource" default:"service.name=mitmania" help:"Extra OTLP resource attributes (k=v,k2=v2,...); node/instance id merged in automatically."`

	OtelSampleRatio       float64 `name:"otel-sample-ratio" default:"0.1" help:"Head sampling ratio for traces (parent-based), 0.0-1.0. Metrics are never sampled."`
	OtelPropagateUpstream bool    `name:"otel-propagate-upstream" help:"Inject W3C traceparent into forwarded upstream requests (off = stealth)."`
	OtelContinueClient    bool    `name:"otel-continue-client" help:"Adopt a client-supplied traceparent as parent instead of a fresh root span."`
	OtelSpoolMaxSize      string  `name:"otel-spool-max-size" default:"128m" help:"file:// traces sink: rotate to a new spool file once it reaches this size."`
	// time.Duration, not int-seconds like --http-timeout-*: matches the
	// documented "1h"-style default exactly, and Kong parses
	// time.Duration fields natively via time.ParseDuration.
	OtelSpoolMaxAge time.Duration `name:"otel-spool-max-age" default:"1h" help:"file:// traces sink: rotate to a new spool file once the current one is this old."`

	TrustedProxies string `name:"trusted-proxies" help:"Comma-separated CIDRs/IPs: peers whose X-Forwarded-For/X-Real-IP are honored to recover the real client IP on explicit listeners. Default empty — recovery off, peer address used verbatim."`
}

// Parse parses and validates mitmania's CLI flags (argv, plus auto-derived
// MITMANIA_* environment variables — flags given on the command line win).
func Parse(args []string) (cfg *Config, err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(helpExit); ok {
				cfg, err = nil, ErrHelp
				return
			}
			panic(r)
		}
	}()

	var cli cliFlags
	parser, kerr := kong.New(&cli,
		kong.Name("mitmania"),
		kong.Description("Intercepting HTTP/HTTPS MITM proxy."),
		kong.DefaultEnvars("MITMANIA"),
		kong.Exit(func(int) { panic(helpExit{}) }),
	)
	if kerr != nil {
		return nil, kerr
	}
	if _, kerr := parser.Parse(args); kerr != nil {
		return nil, kerr
	}

	resolvedStorage := cli.Storage
	if resolvedStorage == "" {
		resolvedStorage = defaultStorageURL()
	}
	if resolvedStorage == "" {
		return nil, fmt.Errorf("--storage is required (could not determine a default: $HOME is unset)")
	}
	storageURL, err := url.Parse(resolvedStorage)
	if err != nil {
		return nil, fmt.Errorf("--storage: invalid URL %q: %w", resolvedStorage, err)
	}
	if !storageSchemes[storageURL.Scheme] {
		return nil, fmt.Errorf("--storage: unsupported scheme %q (need posix:// or s3://)", storageURL.Scheme)
	}
	result := &Config{Storage: resolvedStorage}

	if cli.ClusterKey == "" {
		return nil, fmt.Errorf("--cluster-key is required")
	}
	key, err := base64.StdEncoding.DecodeString(cli.ClusterKey)
	if err != nil {
		return nil, fmt.Errorf("--cluster-key: invalid base64: %w", err)
	}
	if len(key) < minClusterKeyBytes {
		return nil, fmt.Errorf("--cluster-key: decoded key is %d bytes, need >= %d", len(key), minClusterKeyBytes)
	}
	result.ClusterKey = key

	if cli.ListenHTTPTProxy != "" {
		return nil, fmt.Errorf("--listen-http-tproxy: not yet implemented")
	}
	if cli.ListenHTTPRedirect != "" {
		return nil, fmt.Errorf("--listen-http-redirect: not yet implemented")
	}

	if cli.ListenHTTPProxy != "" {
		addr, err := ParseAddr(cli.ListenHTTPProxy)
		if err != nil {
			return nil, fmt.Errorf("--listen-http-proxy: %w", err)
		}
		if addr.Scheme != "tcp" && addr.Scheme != "unix" {
			return nil, fmt.Errorf("--listen-http-proxy: scheme %q not supported (need tcp:// or unix://)", addr.Scheme)
		}
		result.HTTPProxy = &addr
	}

	if cli.ListenHTTPSProxy != "" {
		httpsAddr, err := ParseHTTPSProxyAddr(cli.ListenHTTPSProxy)
		if err != nil {
			return nil, fmt.Errorf("--listen-https-proxy: %w", err)
		}
		result.HTTPSProxy = &httpsAddr
	}

	if result.HTTPProxy == nil && result.HTTPSProxy == nil {
		return nil, fmt.Errorf("no data listeners configured: set --listen-http-proxy or --listen-https-proxy")
	}

	controlSpec := cli.Control
	if controlSpec == "" {
		path := defaultControlPath()
		if path == "" {
			return nil, fmt.Errorf("--control is required ($XDG_RUNTIME_DIR is unset, and the XDG spec defines no safe fallback for it)")
		}
		controlSpec = "unix://" + path
	}
	controlAddr, err := ParseAddr(controlSpec)
	if err != nil {
		return nil, fmt.Errorf("--control: %w", err)
	}
	if controlAddr.Scheme != "tcp" && controlAddr.Scheme != "unix" {
		return nil, fmt.Errorf("--control: scheme %q not supported (need tcp:// or unix://)", controlAddr.Scheme)
	}
	result.Control = controlAddr

	headerLimit, err := ParseSize(cli.HTTPHeaderLimit)
	if err != nil {
		return nil, fmt.Errorf("--http-header-limit: %w", err)
	}
	if headerLimit <= 0 {
		return nil, fmt.Errorf("--http-header-limit: must be > 0, got %q", cli.HTTPHeaderLimit)
	}
	result.HTTPHeaderLimit = headerLimit

	bodyWindow, err := ParseSize(cli.HTTPBodyWindow)
	if err != nil {
		return nil, fmt.Errorf("--http-body-window: %w", err)
	}
	if bodyWindow < 0 {
		return nil, fmt.Errorf("--http-body-window: must be >= 0, got %q", cli.HTTPBodyWindow)
	}
	result.HTTPBodyWindow = bodyWindow

	if err := parsePositiveSeconds("http-timeout-connect", cli.HTTPTimeoutConnect, &result.HTTPConnectTimeout); err != nil {
		return nil, err
	}
	if err := parsePositiveSeconds("http-timeout-read", cli.HTTPTimeoutRead, &result.HTTPReadTimeout); err != nil {
		return nil, err
	}
	if err := parsePositiveInt("http-connect-tries", cli.HTTPConnectTries, &result.HTTPConnectTries); err != nil {
		return nil, err
	}
	if err := parsePositiveSeconds("http2-timeout-connect", cli.HTTP2TimeoutConnect, &result.HTTP2ConnectTimeout); err != nil {
		return nil, err
	}
	if err := parsePositiveSeconds("http2-timeout-read", cli.HTTP2TimeoutRead, &result.HTTP2ReadTimeout); err != nil {
		return nil, err
	}
	if err := parsePositiveInt("http2-connect-tries", cli.HTTP2ConnectTries, &result.HTTP2ConnectTries); err != nil {
		return nil, err
	}

	if err := parsePositiveSeconds("outcall-timeout-connect", cli.OutcallTimeoutConnect, &result.OutcallConnectTimeout); err != nil {
		return nil, err
	}
	if err := parsePositiveSeconds("outcall-timeout-read", cli.OutcallTimeoutRead, &result.OutcallReadTimeout); err != nil {
		return nil, err
	}
	if err := parsePositiveInt("outcall-max-inflight", cli.OutcallMaxInflight, &result.OutcallMaxInflight); err != nil {
		return nil, err
	}

	level, err := ParseLogLevel(cli.LogLevel)
	if err != nil {
		return nil, fmt.Errorf("--log-level: %w", err)
	}
	result.LogLevel = level

	format, err := ParseLogFormat(cli.LogFormat)
	if err != nil {
		return nil, fmt.Errorf("--log-format: %w", err)
	}
	result.LogFormat = format

	result.NoAccessLogs = cli.NoAccessLogs

	if cli.OtelMetrics != "" {
		u, err := url.Parse(cli.OtelMetrics)
		if err != nil || (u.Scheme != "http" && u.Scheme != "unix") {
			return nil, fmt.Errorf("--otel-metrics: unsupported scheme in %q (need http://host:port/path or unix:///path/to.sock)", cli.OtelMetrics)
		}
	}
	result.OtelMetrics = cli.OtelMetrics

	if cli.OtelTraces != "" {
		u, err := url.Parse(cli.OtelTraces)
		if err != nil || !otelTraceSchemes[u.Scheme] {
			return nil, fmt.Errorf("--otel-traces: unsupported scheme in %q (need otlp+grpc://, otlp+http://, file://, or stdout://)", cli.OtelTraces)
		}
	}
	result.OtelTraces = cli.OtelTraces

	result.OtelResource = cli.OtelResource

	if cli.OtelSampleRatio < 0 || cli.OtelSampleRatio > 1 {
		return nil, fmt.Errorf("--otel-sample-ratio: must be in [0,1], got %v", cli.OtelSampleRatio)
	}
	result.OtelSampleRatio = cli.OtelSampleRatio

	result.OtelPropagateUpstream = cli.OtelPropagateUpstream
	result.OtelContinueClient = cli.OtelContinueClient

	spoolMaxSize, err := ParseSize(cli.OtelSpoolMaxSize)
	if err != nil {
		return nil, fmt.Errorf("--otel-spool-max-size: %w", err)
	}
	if spoolMaxSize <= 0 {
		return nil, fmt.Errorf("--otel-spool-max-size: must be > 0, got %q", cli.OtelSpoolMaxSize)
	}
	result.OtelSpoolMaxSize = spoolMaxSize

	if cli.OtelSpoolMaxAge <= 0 {
		return nil, fmt.Errorf("--otel-spool-max-age: must be > 0, got %q", cli.OtelSpoolMaxAge)
	}
	result.OtelSpoolMaxAge = cli.OtelSpoolMaxAge

	trustedProxies, err := ParseTrustedProxies(cli.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("--trusted-proxies: %w", err)
	}
	result.TrustedProxies = trustedProxies

	return result, nil
}

// otelTraceSchemes are the URL schemes --otel-traces accepts;
// plain http:// and unix:// (--otel-metrics' pull-only scrape schemes)
// are deliberately absent — there's no traces equivalent of a scrape
// endpoint, so given to --otel-traces either fails fast here rather than
// being silently ignored.
var otelTraceSchemes = map[string]bool{"otlp+grpc": true, "otlp+http": true, "file": true, "stdout": true}

// helpExit is panicked (and recovered in Parse) by the kong.Exit hook when
// --help/-h was handled — Kong's help flag calls Exit(0) directly from
// within Parse rather than returning an error, so overriding Exit is the
// documented way to intercept it without process-exiting from inside a
// library call. See kong's own help_test.go for the same pattern.
type helpExit struct{}

func parsePositiveSeconds(flagName string, seconds int, out *time.Duration) error {
	if seconds <= 0 {
		return fmt.Errorf("--%s: must be > 0, got %d", flagName, seconds)
	}
	*out = time.Duration(seconds) * time.Second
	return nil
}

func parsePositiveInt(flagName string, n int, out *int) error {
	if n <= 0 {
		return fmt.Errorf("--%s: must be > 0, got %d", flagName, n)
	}
	*out = n
	return nil
}
