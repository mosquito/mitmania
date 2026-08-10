package proxy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWithRetries_SucceedsFirstTry(t *testing.T) {
	calls := 0
	v, err := withRetries(context.Background(), nil, "test", 3, time.Second, func(ctx context.Context) (int, error) {
		calls++
		return 42, nil
	})
	if err != nil {
		t.Fatalf("withRetries: %v", err)
	}
	if v != 42 {
		t.Fatalf("v = %d, want 42", v)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (should not retry after success)", calls)
	}
}

func TestWithRetries_SucceedsAfterFailures(t *testing.T) {
	calls := 0
	v, err := withRetries(context.Background(), nil, "test", 3, time.Second, func(ctx context.Context) (int, error) {
		calls++
		if calls < 3 {
			return 0, errors.New("transient failure")
		}
		return 7, nil
	})
	if err != nil {
		t.Fatalf("withRetries: %v", err)
	}
	if v != 7 {
		t.Fatalf("v = %d, want 7", v)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}

func TestWithRetries_ExhaustsAndReturnsLastError(t *testing.T) {
	calls := 0
	_, err := withRetries(context.Background(), nil, "test", 3, time.Second, func(ctx context.Context) (int, error) {
		calls++
		return 0, errors.New("failure #" + string(rune('0'+calls)))
	})
	if err == nil {
		t.Fatalf("expected an error after exhausting retries")
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
	if err.Error() != "failure #3" {
		t.Fatalf("err = %v, want the last attempt's error", err)
	}
}

func TestWithRetries_EachAttemptGetsAFreshTimeout(t *testing.T) {
	var deadlines []time.Time
	_, err := withRetries(context.Background(), nil, "test", 3, 10*time.Millisecond, func(ctx context.Context) (int, error) {
		dl, ok := ctx.Deadline()
		if !ok {
			t.Fatalf("attempt context has no deadline")
		}
		deadlines = append(deadlines, dl)
		return 0, errors.New("fail")
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(deadlines) != 3 {
		t.Fatalf("got %d deadlines, want 3", len(deadlines))
	}
	for i := 1; i < len(deadlines); i++ {
		if !deadlines[i].After(deadlines[i-1]) {
			t.Fatalf("deadline %d (%v) is not after deadline %d (%v) — attempts should get independent timeouts", i, deadlines[i], i-1, deadlines[i-1])
		}
	}
}

func TestWithRetries_OneTryMeansNoRetry(t *testing.T) {
	calls := 0
	_, err := withRetries(context.Background(), nil, "test", 1, time.Second, func(ctx context.Context) (int, error) {
		calls++
		return 0, errors.New("fail")
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}
