package outcall

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func testService(t *testing.T) *Service {
	t.Helper()
	return NewService(2*time.Second, 2*time.Second, 8)
}

func jsonHandler(t *testing.T, fn func(r *http.Request, calls int32) (status int, body any, headers map[string]string)) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		status, body, headers := fn(r, n)
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			json.NewEncoder(w).Encode(body)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestService_AllowNotCachedWithoutFreshnessHeaders(t *testing.T) {
	srv, calls := jsonHandler(t, func(r *http.Request, n int32) (int, any, map[string]string) {
		return http.StatusOK, Response{}, nil
	})
	svc := testService(t)
	target := Target{URL: srv.URL}

	for i := 0; i < 3; i++ {
		_, err := svc.Do(context.Background(), "k1", target, Request{Version: Version, Action: ActionWebhook})
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if got := atomic.LoadInt32(calls); got != 3 {
		t.Fatalf("calls = %d, want 3 (no freshness header -> never cached)", got)
	}
}

func TestService_DeniedReturnsMessageAndStatus(t *testing.T) {
	srv, _ := jsonHandler(t, func(r *http.Request, n int32) (int, any, map[string]string) {
		return http.StatusForbidden, Response{Message: "no thanks", HTTPStatus: 402}, nil
	})
	svc := testService(t)
	target := Target{URL: srv.URL}

	_, err := svc.Do(context.Background(), "k2", target, Request{Version: Version, Action: ActionWebhook})
	if err == nil {
		t.Fatalf("Do: expected DeniedError, got nil")
	}
	denied, ok := err.(*DeniedError)
	if !ok {
		t.Fatalf("Do: err = %v (%T), want *DeniedError", err, err)
	}
	if denied.Message != "no thanks" || denied.HTTPStatus != 402 {
		t.Fatalf("denied = %+v, want message=%q status=402", denied, "no thanks")
	}
}

func TestService_CachesAllowUnderMaxAge(t *testing.T) {
	srv, calls := jsonHandler(t, func(r *http.Request, n int32) (int, any, map[string]string) {
		return http.StatusOK, Response{Message: fmt.Sprintf("call-%d", n)}, map[string]string{"Cache-Control": "max-age=60"}
	})
	svc := testService(t)
	target := Target{URL: srv.URL}

	resp1, err := svc.Do(context.Background(), "k3", target, Request{Version: Version, Action: ActionWebhook})
	if err != nil {
		t.Fatalf("Do (1): %v", err)
	}
	resp2, err := svc.Do(context.Background(), "k3", target, Request{Version: Version, Action: ActionWebhook})
	if err != nil {
		t.Fatalf("Do (2): %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("calls = %d, want 1 (second Do should be a cache hit)", got)
	}
	if resp1.Message != resp2.Message {
		t.Fatalf("resp1=%q resp2=%q, want identical (served from cache)", resp1.Message, resp2.Message)
	}
}

func TestService_CachesDeniedVerdictToo(t *testing.T) {
	srv, calls := jsonHandler(t, func(r *http.Request, n int32) (int, any, map[string]string) {
		return http.StatusForbidden, Response{Message: "denied"}, map[string]string{"Cache-Control": "max-age=60"}
	})
	svc := testService(t)
	target := Target{URL: srv.URL}

	if _, err := svc.Do(context.Background(), "k4", target, Request{Version: Version, Action: ActionWebhook}); err == nil {
		t.Fatalf("Do (1): expected denial")
	}
	if _, err := svc.Do(context.Background(), "k4", target, Request{Version: Version, Action: ActionWebhook}); err == nil {
		t.Fatalf("Do (2): expected denial (from cache)")
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("calls = %d, want 1 (cached denial should not re-call)", got)
	}
}

func TestService_MustRevalidateWithETagSends304(t *testing.T) {
	srv, calls := jsonHandler(t, func(r *http.Request, n int32) (int, any, map[string]string) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			return http.StatusNotModified, nil, map[string]string{"Cache-Control": "max-age=0, must-revalidate", "ETag": `"v1"`}
		}
		return http.StatusOK, Response{Message: "fresh-mint"}, map[string]string{"Cache-Control": "max-age=0, must-revalidate", "ETag": `"v1"`}
	})
	svc := testService(t)
	target := Target{URL: srv.URL}

	resp1, err := svc.Do(context.Background(), "k5", target, Request{Version: Version, Action: ActionHeaderFetch})
	if err != nil {
		t.Fatalf("Do (1): %v", err)
	}
	resp2, err := svc.Do(context.Background(), "k5", target, Request{Version: Version, Action: ActionHeaderFetch})
	if err != nil {
		t.Fatalf("Do (2): %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Fatalf("calls = %d, want 2 (must-revalidate: max-age=0 forces a round trip every time)", got)
	}
	if resp1.Message != "fresh-mint" || resp2.Message != "fresh-mint" {
		t.Fatalf("resp1=%+v resp2=%+v, want the original body preserved across a 304 (not merged/blanked)", resp1, resp2)
	}
}

func TestService_StaleWhileRevalidateServesStaleAndRefreshesInBackground(t *testing.T) {
	srv, calls := jsonHandler(t, func(r *http.Request, n int32) (int, any, map[string]string) {
		return http.StatusOK, Response{Message: fmt.Sprintf("v%d", n)}, map[string]string{"Cache-Control": "max-age=0, stale-while-revalidate=60"}
	})
	svc := testService(t)
	target := Target{URL: srv.URL}

	resp1, err := svc.Do(context.Background(), "k6", target, Request{Version: Version, Action: ActionWebhook})
	if err != nil {
		t.Fatalf("Do (1): %v", err)
	}
	if resp1.Message != "v1" {
		t.Fatalf("resp1 = %+v, want v1", resp1)
	}

	// Immediately stale (max-age=0) but within the SWR window: must serve
	// the (now stale) cached entry synchronously and kick a background
	// revalidation, not block on a fresh network round trip.
	resp2, err := svc.Do(context.Background(), "k6", target, Request{Version: Version, Action: ActionWebhook})
	if err != nil {
		t.Fatalf("Do (2): %v", err)
	}
	if resp2.Message != "v1" {
		t.Fatalf("resp2 = %+v, want v1 (stale-while-revalidate serves the stale entry synchronously)", resp2)
	}

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(calls) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Fatalf("calls = %d, want 2 (background revalidation never fired)", got)
	}
}

func TestService_MalformedBodyIsNotDeniedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{not json"))
	}))
	t.Cleanup(srv.Close)
	svc := testService(t)
	target := Target{URL: srv.URL}

	_, err := svc.Do(context.Background(), "k7", target, Request{Version: Version, Action: ActionWebhook})
	if err == nil {
		t.Fatalf("Do: expected an error for malformed body")
	}
	if _, ok := err.(*DeniedError); ok {
		t.Fatalf("Do: malformed body must not surface as *DeniedError (failure != refusal): %v", err)
	}
}

func TestService_OverCapacityFailsWithoutQueueing(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{})
	}))
	t.Cleanup(srv.Close)

	svc := NewService(2*time.Second, 2*time.Second, 1) // maxInflight=1
	target := Target{URL: srv.URL}

	errCh := make(chan error, 2)
	go func() {
		_, err := svc.Do(context.Background(), "k8a", target, Request{Version: Version, Action: ActionWebhook})
		errCh <- err
	}()
	<-started // first call is now holding the one inflight slot

	go func() {
		_, err := svc.Do(context.Background(), "k8b", target, Request{Version: Version, Action: ActionWebhook})
		errCh <- err
	}()

	err1 := <-errCh
	close(release)
	err2 := <-errCh

	var sawOverCapacity bool
	for _, err := range []error{err1, err2} {
		if err == ErrOverCapacity {
			sawOverCapacity = true
		}
	}
	if !sawOverCapacity {
		t.Fatalf("neither call got ErrOverCapacity with maxInflight=1 and two concurrent distinct-key calls: %v, %v", err1, err2)
	}
}

func TestService_UnixSocketTransport(t *testing.T) {
	// Not t.TempDir(): its nested-by-test-name path routinely exceeds
	// sockaddr_un's ~104-byte limit on macOS once combined with a
	// filename, which fails the Listen below with nothing wrong in the
	// code under test.
	dir, err := os.MkdirTemp("", "oc")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "broker.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "mitmania.local" {
			t.Errorf("Host = %q, want mitmania.local", r.Host)
		}
		if r.URL.Path != "/decide" {
			t.Errorf("Path = %q, want /decide", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{})
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	svc := testService(t)
	target := Target{Socket: socketPath, Path: "/decide"}

	if _, err := svc.Do(context.Background(), "k9", target, Request{Version: Version, Action: ActionWebhook}); err != nil {
		t.Fatalf("Do over unix socket: %v", err)
	}
}
