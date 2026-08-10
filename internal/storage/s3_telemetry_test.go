package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestS3Storage_RequestsCarryTraceparent doesn't need a real S3-compatible
// backend: it only needs to observe that the traceparent header reaches
// the wire on an S3 API call, which a fake HTTP server can do just as
// well as a real one — the call itself is expected to fail (this isn't a
// real S3 protocol responder), only the header is being checked.
func TestS3Storage_RequestsCarryTraceparent(t *testing.T) {
	var gotTraceparent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gotTraceparent == "" {
			gotTraceparent = r.Header.Get("traceparent")
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	st, err := Open("s3://key:secret@" + host + "/?bucket=mitmania&region=us-east-1&secure=false")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer tp.Shutdown(context.Background())
	ctx, span := tp.Tracer("test").Start(context.Background(), "caller")
	defer span.End()

	// Expected to fail (srv isn't a real S3 responder) — only the header
	// that reached the wire is under test.
	st.Put(ctx, "some/key", []byte("v"))

	if gotTraceparent == "" {
		t.Fatalf("S3 request carried no traceparent header — s3:// calls are mitmania's own dependency and must always propagate traceparent, regardless of --otel-propagate-upstream")
	}
}
