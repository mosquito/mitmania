package storage

import (
	"context"
	"log/slog"
	"time"
)

// WithLogging wraps next so every Storage call is logged at Debug level
// (key, outcome, elapsed) — --log-level debug gives full visibility into
// storage access with zero logging code in any individual backend.
// Applies uniformly to whatever backend is configured (posix, s3, a
// future one) since it wraps the interface, not a concrete type.
//
// If next also implements Linker, the returned Storage does too (its
// Symlink calls logged the same way) — CertCache's own
// storage.(Linker) type assertion must still see that capability through
// the wrapper, or a posix backend would silently lose its names/ index
// the moment logging is enabled.
func WithLogging(next Storage, log *slog.Logger) Storage {
	base := &loggingStorage{next: next, log: log}
	if linker, ok := next.(Linker); ok {
		return &loggingLinkerStorage{loggingStorage: base, linker: linker}
	}
	return base
}

type loggingStorage struct {
	next Storage
	log  *slog.Logger
}

func (s *loggingStorage) Get(ctx context.Context, key string) ([]byte, Version, error) {
	start := time.Now()
	data, v, err := s.next.Get(ctx, key)
	s.debug("get", key, time.Since(start), err, slog.Int("bytes", len(data)))
	return data, v, err
}

func (s *loggingStorage) Put(ctx context.Context, key string, data []byte) error {
	start := time.Now()
	err := s.next.Put(ctx, key, data)
	s.debug("put", key, time.Since(start), err, slog.Int("bytes", len(data)))
	return err
}

func (s *loggingStorage) Delete(ctx context.Context, key string) error {
	start := time.Now()
	err := s.next.Delete(ctx, key)
	s.debug("delete", key, time.Since(start), err)
	return err
}

func (s *loggingStorage) DeletePrefix(ctx context.Context, prefix string) error {
	start := time.Now()
	err := s.next.DeletePrefix(ctx, prefix)
	s.debug("delete_prefix", prefix, time.Since(start), err)
	return err
}

func (s *loggingStorage) Stat(ctx context.Context, key string) (Version, error) {
	start := time.Now()
	v, err := s.next.Stat(ctx, key)
	s.debug("stat", key, time.Since(start), err)
	return v, err
}

func (s *loggingStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	start := time.Now()
	entries, err := s.next.List(ctx, prefix)
	s.debug("list", prefix, time.Since(start), err, slog.Int("entries", len(entries)))
	return entries, err
}

func (s *loggingStorage) debug(op, key string, elapsed time.Duration, err error, extra ...slog.Attr) {
	attrs := make([]any, 0, 8+2*len(extra))
	attrs = append(attrs, slog.String("op", op), slog.String("key", key), slog.Duration("elapsed", elapsed))
	for _, a := range extra {
		attrs = append(attrs, a)
	}
	if err != nil {
		attrs = append(attrs, slog.String("err", err.Error()))
	}
	s.log.Debug("storage access", attrs...)
}

// loggingLinkerStorage is loggingStorage plus a logged Symlink — see
// WithLogging's doc for why this needs to be a distinct type rather than
// loggingStorage unconditionally implementing Linker.
type loggingLinkerStorage struct {
	*loggingStorage
	linker Linker
}

func (s *loggingLinkerStorage) Symlink(ctx context.Context, key, targetKey string) error {
	start := time.Now()
	err := s.linker.Symlink(ctx, key, targetKey)
	s.debug("symlink", key, time.Since(start), err, slog.String("target", targetKey))
	return err
}
