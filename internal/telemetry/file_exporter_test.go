package telemetry

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/protobuf/encoding/protojson"

	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

func TestFileSpanExporter_WritesValidOTLPJSONLines(t *testing.T) {
	dir := t.TempDir()
	res, err := buildResource("")
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}

	exporter, err := newFileSpanExporter(dir, 128<<20, time.Hour)
	if err != nil {
		t.Fatalf("newFileSpanExporter: %v", err)
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter), sdktrace.WithResource(res))
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	_, span := tracer.Start(context.Background(), "test-span")
	span.SetAttributes()
	span.End()

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("spool dir has %d files, want 1: %v", len(files), files)
	}

	f, err := os.Open(filepath.Join(dir, files[0].Name()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var lines int
	for scanner.Scan() {
		lines++
		var req collectortracepb.ExportTraceServiceRequest
		if err := protojson.Unmarshal(scanner.Bytes(), &req); err != nil {
			t.Fatalf("line %d is not valid OTLP-JSON: %v\nline: %s", lines, err, scanner.Text())
		}
		if len(req.ResourceSpans) != 1 {
			t.Fatalf("ResourceSpans = %d, want 1", len(req.ResourceSpans))
		}
		rs := req.ResourceSpans[0]
		if len(rs.ScopeSpans) != 1 || len(rs.ScopeSpans[0].Spans) != 1 {
			t.Fatalf("ScopeSpans/Spans shape = %#v, want exactly one span", rs.ScopeSpans)
		}
		gotName := rs.ScopeSpans[0].Spans[0].Name
		if gotName != "test-span" {
			t.Errorf("span name = %q, want test-span", gotName)
		}
		if len(rs.Resource.Attributes) == 0 {
			t.Errorf("resource attributes empty, want service.name/service.instance.id present")
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if lines != 1 {
		t.Fatalf("spool file has %d lines, want 1", lines)
	}
}

func TestFileSpanExporter_RotatesOnSize(t *testing.T) {
	dir := t.TempDir()
	res, _ := buildResource("")

	// A tiny max size guarantees every single span's line exceeds it,
	// forcing a rotation before every write after the first.
	exporter, err := newFileSpanExporter(dir, 1, time.Hour)
	if err != nil {
		t.Fatalf("newFileSpanExporter: %v", err)
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter), sdktrace.WithResource(res))
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	for range 3 {
		_, span := tracer.Start(context.Background(), "span")
		span.End()
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("spool dir has %d files, want 3 (one per rotated write)", len(files))
	}
}

func TestFileSpanExporter_EmptyBatchIsNoOp(t *testing.T) {
	dir := t.TempDir()
	exporter, err := newFileSpanExporter(dir, 128<<20, time.Hour)
	if err != nil {
		t.Fatalf("newFileSpanExporter: %v", err)
	}
	if err := exporter.ExportSpans(context.Background(), nil); err != nil {
		t.Fatalf("ExportSpans(nil): %v", err)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, f := range files {
		info, err := f.Info()
		if err != nil {
			t.Fatalf("Info: %v", err)
		}
		if info.Size() != 0 {
			t.Errorf("file %s has size %d, want 0 (no spans exported)", f.Name(), info.Size())
		}
	}
}
