package storage

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"mitmania/internal/telemetry"
)

// WithTelemetry wraps next so every Storage call records the
// OpenTelemetry storage.op.duration histogram and a "storage" child
// span. If next also implements Linker, the returned Storage does too,
// for the same reason WithLogging preserves it.
//
// Call this on the value storage.Open returns BEFORE wrapping it with
// anything else (WithLogging included) — BackendName below identifies
// next's concrete backend type via a type switch, which only sees
// through to *PosixStorage/*S3Storage on the UNDECORATED value; wrapping
// order otherwise silently degrades the backend label to "unknown"
// (caught via a live scrape during manual testing, where a posix backend
// showed up labeled "unknown" because WithTelemetry had been applied
// after WithLogging).
func WithTelemetry(next Storage, m *telemetry.Metrics, t trace.Tracer) Storage {
	base := &telemetryStorage{next: next, metrics: m, tracer: t, backend: BackendName(next)}
	if linker, ok := next.(Linker); ok {
		return &telemetryLinkerStorage{telemetryStorage: base, linker: linker}
	}
	return base
}

// BackendName identifies s's concrete backend for the storage.op.duration
// metric's "backend" label — a plain type switch rather than a new
// required Storage method, since only this package's two concrete types
// need naming and a future backend is just another case here. Exported so
// a caller composing WithTelemetry with other decorators (WithLogging)
// can compute it from the undecorated value up front — see WithTelemetry's
// doc comment for why that ordering matters.
func BackendName(s Storage) string {
	switch s.(type) {
	case *PosixStorage:
		return "posix"
	case *S3Storage:
		return "s3"
	default:
		return "unknown"
	}
}

type telemetryStorage struct {
	next    Storage
	metrics *telemetry.Metrics
	tracer  trace.Tracer
	backend string
}

func (s *telemetryStorage) span(ctx context.Context, op string) (context.Context, trace.Span) {
	if s.tracer == nil {
		return ctx, nil
	}
	return s.tracer.Start(ctx, "storage", trace.WithAttributes(
		attribute.String("op", op), attribute.String("backend", s.backend)))
}

func (s *telemetryStorage) record(ctx context.Context, span trace.Span, op string, start time.Time, err error) {
	result := "ok"
	if err != nil {
		result = "error"
		if span != nil {
			span.RecordError(err)
		}
	}
	if span != nil {
		span.End()
	}
	s.metrics.StorageOp(ctx, op, s.backend, result, time.Since(start))
}

func (s *telemetryStorage) Get(ctx context.Context, key string) ([]byte, Version, error) {
	ctx, span := s.span(ctx, "get")
	start := time.Now()
	data, v, err := s.next.Get(ctx, key)
	s.record(ctx, span, "get", start, err)
	return data, v, err
}

func (s *telemetryStorage) Put(ctx context.Context, key string, data []byte) error {
	ctx, span := s.span(ctx, "put")
	start := time.Now()
	err := s.next.Put(ctx, key, data)
	s.record(ctx, span, "put", start, err)
	return err
}

func (s *telemetryStorage) Delete(ctx context.Context, key string) error {
	ctx, span := s.span(ctx, "delete")
	start := time.Now()
	err := s.next.Delete(ctx, key)
	s.record(ctx, span, "delete", start, err)
	return err
}

func (s *telemetryStorage) DeletePrefix(ctx context.Context, prefix string) error {
	ctx, span := s.span(ctx, "delete_prefix")
	start := time.Now()
	err := s.next.DeletePrefix(ctx, prefix)
	s.record(ctx, span, "delete_prefix", start, err)
	return err
}

func (s *telemetryStorage) Stat(ctx context.Context, key string) (Version, error) {
	ctx, span := s.span(ctx, "stat")
	start := time.Now()
	v, err := s.next.Stat(ctx, key)
	s.record(ctx, span, "stat", start, err)
	return v, err
}

func (s *telemetryStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	ctx, span := s.span(ctx, "list")
	start := time.Now()
	entries, err := s.next.List(ctx, prefix)
	s.record(ctx, span, "list", start, err)
	return entries, err
}

// telemetryLinkerStorage is telemetryStorage plus an instrumented
// Symlink — see WithTelemetry's doc for why this needs to be a distinct
// type rather than telemetryStorage unconditionally implementing Linker.
type telemetryLinkerStorage struct {
	*telemetryStorage
	linker Linker
}

func (s *telemetryLinkerStorage) Symlink(ctx context.Context, key, targetKey string) error {
	ctx, span := s.span(ctx, "symlink")
	start := time.Now()
	err := s.linker.Symlink(ctx, key, targetKey)
	s.record(ctx, span, "symlink", start, err)
	return err
}
