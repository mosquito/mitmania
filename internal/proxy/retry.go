package proxy

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// withRetries runs attempt up to tries times, each bounded by timeout via
// a derived context, returning the first success or the last error once
// every attempt has failed. tries <= 0 is a misconfiguration and returns an
// error rather than silently "succeeding" with attempt never having run —
// config.Parse enforces tries >= 1 for every CLI-sourced value, but this
// guards any other caller (tests included) that builds a zero-value config
// struct directly instead of going through Parse.
//
// log/label are for Debug-level per-attempt tracing (every dial retry in
// the proxy is opaque without this — access logging only records the
// final outcome, not individual attempts); log may be nil to
// disable it, same convention as Http1Handler.Logger.
func withRetries[T any](ctx context.Context, log *slog.Logger, label string, tries int, timeout time.Duration, attempt func(context.Context) (T, error)) (T, error) {
	var zero T
	if tries <= 0 {
		return zero, errors.New("withRetries: tries must be >= 1")
	}
	var lastErr error
	for i := 0; i < tries; i++ {
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		v, err := attempt(attemptCtx)
		cancel()
		if err == nil {
			if log != nil && i > 0 {
				log.Debug("upstream connect succeeded after retry", "op", label, "attempt", i+1, "tries", tries)
			}
			return v, nil
		}
		lastErr = err
		if log != nil {
			log.Debug("upstream connect attempt failed", "op", label, "attempt", i+1, "tries", tries, "err", err.Error())
		}
	}
	if log != nil {
		log.Debug("upstream connect exhausted retries", "op", label, "tries", tries, "err", lastErr.Error())
	}
	return zero, lastErr
}
