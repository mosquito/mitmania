package outcall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/singleflight"

	"mitmania/internal/telemetry"
)

// maxResponseBytes bounds a broker response body — it's a small JSON
// envelope, not a place to accept unbounded input (mirrors the rule
// file's own maxRuleFileBytes bound in internal/control).
const maxResponseBytes = 64 << 10

// ErrOverCapacity is returned by Do, without ever reaching the network,
// when --outcall-max-inflight is already exhausted: over the cap the
// request fails rather than queues.
var ErrOverCapacity = errors.New("outcall: over --outcall-max-inflight capacity")

// DeniedError means the broker was reached and gave a coherent refusal —
// a parsed non-2xx response — as opposed to every other error Do returns,
// which means "the broker is broken," not "the broker said no": failure
// always separates from refusal. Only DeniedError is exempt from an
// action's failOpen: a refusal is a decision, not an outage.
type DeniedError struct {
	Message    string
	HTTPStatus int // 0 if the broker didn't override it
}

func (e *DeniedError) Error() string {
	if e.Message != "" {
		return "outcall: denied: " + e.Message
	}
	return "outcall: denied"
}

// Target identifies a broker's transport: either Socket+Path
// (unix) or URL (https) — mutual exclusivity and shape are validated at
// rule-compile time (internal/rules), not here.
type Target struct {
	Socket string // unix socket path
	Path   string // request path over Socket; "/" default applied at compile time
	URL    string // https URL, when not Socket-based
}

func (t Target) key() string {
	if t.Socket != "" {
		return "unix:" + t.Socket
	}
	return "url:" + t.URL
}

// requestURL returns the URL string to POST to and, for a unix-socket
// target, the fixed placeholder Host header "mitmania.local" — the
// socket addresses nothing, so there's no real host to name.
func (t Target) requestURL() (url, hostHeader string) {
	if t.Socket != "" {
		return "http://mitmania.local" + t.Path, "mitmania.local"
	}
	return t.URL, ""
}

// cacheEntry is one broker response held under its Cache-Control-derived
// freshness window — freshness is left entirely to the broker's own
// headers, mitmania keeps no TTL of its own. denied distinguishes a
// cached refusal from a cached allow — both are cacheable, since caching
// headers govern the whole envelope, verdict included.
type cacheEntry struct {
	resp   Response
	denied bool
	status int // http_status as it should be reported to the client, when denied

	etag string

	freshUntil                time.Time
	staleWhileRevalidateUntil time.Time
	staleIfErrorUntil         time.Time
	mustRevalidate            bool
}

func (e *cacheEntry) fresh(now time.Time) bool     { return now.Before(e.freshUntil) }
func (e *cacheEntry) withinSWR(now time.Time) bool { return now.Before(e.staleWhileRevalidateUntil) }
func (e *cacheEntry) withinSIE(now time.Time) bool { return now.Before(e.staleIfErrorUntil) }

func (e *cacheEntry) result() (*Response, error) {
	if e.denied {
		return nil, &DeniedError{Message: e.resp.Message, HTTPStatus: e.status}
	}
	r := e.resp
	return &r, nil
}

// Service is mitmania's OutcallService: one process-wide broker
// client, an RFC 9111-subset in-memory cache, and a concurrency cap.
type Service struct {
	connectTimeout time.Duration
	readTimeout    time.Duration
	sem            chan struct{}
	log            *slog.Logger

	// metrics/tracer back the OpenTelemetry outcall.* signals (total,
	// inflight, duration, cache.total; an "outcall" span per Do call) —
	// nil-safe, same convention as log.
	metrics *telemetry.Metrics
	tracer  trace.Tracer

	clientsMu sync.Mutex
	clients   map[string]*http.Client

	cacheMu sync.Mutex
	cache   map[string]*cacheEntry

	sf singleflight.Group
}

// ServiceOption configures NewService.
type ServiceOption func(*Service)

// WithLogger enables Debug-level per-call logging and Info/Warn on
// deny/fail — nil (the default) disables it.
func WithLogger(log *slog.Logger) ServiceOption {
	return func(s *Service) { s.log = log }
}

// WithMetrics enables the OpenTelemetry outcall.* metrics — nil (the
// default) leaves them unrecorded.
func WithMetrics(m *telemetry.Metrics) ServiceOption {
	return func(s *Service) { s.metrics = m }
}

// WithTracer enables an "outcall" child span per Do call — nil
// (the default) leaves tracing off.
func WithTracer(t trace.Tracer) ServiceOption {
	return func(s *Service) { s.tracer = t }
}

// NewService returns an outcall Service. connectTimeout/readTimeout bound
// a single broker call (--outcall-timeout-connect/-read); maxInflight
// caps concurrent in-flight broker calls process-wide
// (--outcall-max-inflight).
func NewService(connectTimeout, readTimeout time.Duration, maxInflight int, opts ...ServiceOption) *Service {
	s := &Service{
		connectTimeout: connectTimeout,
		readTimeout:    readTimeout,
		sem:            make(chan struct{}, maxInflight),
		clients:        map[string]*http.Client{},
		cache:          map[string]*cacheEntry{},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Do performs (or serves from cache) one outcall. cacheKey is opaque,
// derived by the caller from the compiled action — URL plus a hash of
// its params, never request fields; target says where to
// send it. A non-nil, non-*DeniedError error means the broker is
// unreachable or answered incoherently — callers apply the action's own
// failOpen to that case, never to a *DeniedError.
func (s *Service) Do(ctx context.Context, cacheKey string, target Target, req Request) (*Response, error) {
	now := time.Now()
	start := time.Now()
	action := string(req.Action)

	if s.tracer != nil {
		var span trace.Span
		ctx, span = s.tracer.Start(ctx, "outcall", trace.WithAttributes(
			attribute.String("action", action), attribute.String("key", cacheKey)))
		defer span.End()
	}
	s.metrics.OutcallInflight(ctx, 1)
	defer s.metrics.OutcallInflight(ctx, -1)

	s.cacheMu.Lock()
	entry := s.cache[cacheKey]
	s.cacheMu.Unlock()

	if entry != nil && entry.fresh(now) {
		s.debug("cache hit (fresh)", cacheKey, target, 0, nil)
		s.metrics.OutcallCache(ctx, "hit")
		s.metrics.OutcallDuration(ctx, action, "hit", time.Since(start))
		resp, err := entry.result()
		s.recordVerdict(ctx, action, err)
		return resp, err
	}

	if entry != nil && !entry.mustRevalidate && entry.withinSWR(now) {
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), s.connectTimeout+s.readTimeout)
			defer cancel()
			s.call(bgCtx, cacheKey, target, req, entry)
		}()
		s.debug("cache hit (stale, revalidating in background)", cacheKey, target, 0, nil)
		s.metrics.OutcallCache(ctx, "hit")
		s.metrics.OutcallDuration(ctx, action, "hit", time.Since(start))
		resp, err := entry.result()
		s.recordVerdict(ctx, action, err)
		return resp, err
	}

	resp, err := s.call(ctx, cacheKey, target, req, entry)
	if err != nil {
		_, isDenied := errors.AsType[*DeniedError](err)
		if !isDenied && entry != nil && entry.withinSIE(now) {
			s.debug("outcall failed, serving stale (stale-if-error)", cacheKey, target, 0, err)
			// Closest of the metrics' fixed hit/miss/revalidate
			// cache-result vocabulary: this IS serving cached data, just
			// triggered by a broker failure rather than freshness.
			s.metrics.OutcallCache(ctx, "hit")
			resp2, err2 := entry.result()
			s.recordVerdict(ctx, action, err2)
			return resp2, err2
		}
	}
	s.recordVerdict(ctx, action, err)
	return resp, err
}

// recordVerdict records outcall.total's result label: allow (success),
// deny (a coherent broker refusal, *DeniedError), or fail (anything else
// — network/timeout/parse/over-capacity; failure always separates from
// refusal).
func (s *Service) recordVerdict(ctx context.Context, action string, err error) {
	result := "allow"
	if err != nil {
		result = "fail"
		if _, ok := errors.AsType[*DeniedError](err); ok {
			result = "deny"
		}
	}
	s.metrics.OutcallResult(ctx, action, result)
}

// call performs the actual HTTP round trip, singleflighted per cacheKey
// so concurrent callers (a fresh miss, or several requests hitting the
// same stale entry) coalesce into one broker call — the same pattern
// CertFactory uses to coalesce concurrent cert mints for the same SNI.
func (s *Service) call(ctx context.Context, cacheKey string, target Target, req Request, prior *cacheEntry) (*Response, error) {
	v, err, _ := s.sf.Do(cacheKey, func() (any, error) {
		return s.doHTTP(ctx, cacheKey, target, req, prior)
	})
	if err != nil {
		return nil, err
	}
	return v.(*Response), nil
}

func (s *Service) doHTTP(ctx context.Context, cacheKey string, target Target, req Request, prior *cacheEntry) (*Response, error) {
	action := string(req.Action)
	netStart := time.Now()

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.debug("over capacity", cacheKey, target, 0, ErrOverCapacity)
		return nil, ErrOverCapacity
	}

	client := s.clientFor(target)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("outcall: encode request: %w", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, s.connectTimeout+s.readTimeout)
	defer cancel()

	url, hostHeader := target.requestURL()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("outcall: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if hostHeader != "" {
		httpReq.Host = hostHeader
	}
	if prior != nil && prior.etag != "" {
		httpReq.Header.Set("If-None-Match", prior.etag)
	}
	// The broker is our own dependency, not client traffic passing
	// through us — always propagate traceparent, regardless of
	// --otel-propagate-upstream (which only gates traffic forwarded to
	// upstream on the client's behalf).
	telemetry.InjectAlways(ctx, httpReq.Header)

	start := time.Now()
	httpResp, err := client.Do(httpReq)
	if err != nil {
		s.debug("call failed", cacheKey, target, time.Since(start), err)
		s.metrics.OutcallDuration(ctx, action, "miss", time.Since(netStart))
		return nil, fmt.Errorf("outcall: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode == http.StatusNotModified && prior != nil {
		s.refresh(cacheKey, prior, httpResp.Header, time.Now())
		s.debug("revalidated (304)", cacheKey, target, time.Since(start), nil)
		s.metrics.OutcallCache(ctx, "revalidate")
		s.metrics.OutcallDuration(ctx, action, "revalidate", time.Since(netStart))
		return prior.result()
	}

	data, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("outcall: read response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("outcall: response body exceeds %d bytes", maxResponseBytes)
	}

	var envResp Response
	if len(data) > 0 {
		if ct := httpResp.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
			return nil, fmt.Errorf("outcall: unexpected response content-type %q", ct)
		}
		if err := json.Unmarshal(data, &envResp); err != nil {
			return nil, fmt.Errorf("outcall: unparseable response body: %w", err)
		}
	}

	denied := httpResp.StatusCode < 200 || httpResp.StatusCode >= 300
	s.store(cacheKey, envResp, denied, httpResp.StatusCode, httpResp.Header, time.Now())
	s.metrics.OutcallCache(ctx, "miss")
	s.metrics.OutcallDuration(ctx, action, "miss", time.Since(netStart))

	if denied {
		s.debug("denied", cacheKey, target, time.Since(start), nil)
		return nil, &DeniedError{Message: envResp.Message, HTTPStatus: envResp.HTTPStatus}
	}
	s.debug("allowed", cacheKey, target, time.Since(start), nil)
	return &envResp, nil
}

func (s *Service) clientFor(target Target) *http.Client {
	key := target.key()

	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	if c, ok := s.clients[key]; ok {
		return c
	}

	dialer := &net.Dialer{Timeout: s.connectTimeout}
	transport := &http.Transport{ResponseHeaderTimeout: s.readTimeout}
	if target.Socket != "" {
		socket := target.Socket
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		}
	} else {
		transport.DialContext = dialer.DialContext
	}

	client := &http.Client{Transport: transport}
	s.clients[key] = client
	return client
}

// store caches resp under cacheKey per its Cache-Control/Expires, per
// parseFreshness's rules — including a denied verdict, since caching
// headers govern the whole envelope, verdict included. A
// non-cacheable response (no-store, or no freshness signal at all) is
// not stored; a stale entry already present for cacheKey is dropped.
func (s *Service) store(cacheKey string, resp Response, denied bool, status int, header http.Header, now time.Time) {
	fr := parseFreshness(header, now)

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if !fr.cacheable {
		delete(s.cache, cacheKey)
		return
	}
	s.cache[cacheKey] = &cacheEntry{
		resp:                      resp,
		denied:                    denied,
		status:                    status,
		etag:                      header.Get("ETag"),
		freshUntil:                now.Add(fr.freshFor),
		staleWhileRevalidateUntil: now.Add(fr.freshFor + fr.staleWhileRevalidate),
		staleIfErrorUntil:         now.Add(fr.freshFor + fr.staleIfError),
		mustRevalidate:            fr.mustRevalidate,
	}
}

// refresh handles a 304: freshness alone is renewed from the
// revalidation response's headers, the cached body/verdict is untouched —
// a 304 refreshes only freshness, where a 200 replaces the whole cached
// entry atomically.
func (s *Service) refresh(cacheKey string, prior *cacheEntry, header http.Header, now time.Time) {
	fr := parseFreshness(header, now)

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if !fr.cacheable {
		delete(s.cache, cacheKey)
		return
	}
	updated := *prior
	updated.freshUntil = now.Add(fr.freshFor)
	updated.staleWhileRevalidateUntil = now.Add(fr.freshFor + fr.staleWhileRevalidate)
	updated.staleIfErrorUntil = now.Add(fr.freshFor + fr.staleIfError)
	updated.mustRevalidate = fr.mustRevalidate
	if et := header.Get("ETag"); et != "" {
		updated.etag = et
	}
	s.cache[cacheKey] = &updated
}

func (s *Service) debug(msg, cacheKey string, target Target, elapsed time.Duration, err error) {
	if s.log == nil {
		return
	}
	attrs := []any{"key", cacheKey}
	if target.Socket != "" {
		attrs = append(attrs, "socket", target.Socket, "path", target.Path)
	} else {
		attrs = append(attrs, "url", target.URL)
	}
	if elapsed > 0 {
		attrs = append(attrs, "elapsed", elapsed)
	}
	if err != nil {
		attrs = append(attrs, "err", err.Error())
	}
	s.log.Debug("outcall: "+msg, attrs...)
}
