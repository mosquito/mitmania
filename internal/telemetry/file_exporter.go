package telemetry

import (
	"context"
	"fmt"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// fileSpanExporter is the file:// traces sink named by --otel-traces:
// every ExportSpans batch becomes one line of real OTLP-JSON (spansToOTLP + protojson)
// appended to a rotating spool directory — genuinely ingestible by an
// otel-collector filelog receiver + OTLP-JSON parser, not a
// debug-shaped approximation of one.
type fileSpanExporter struct {
	rf *rotatingFile
}

func newFileSpanExporter(dir string, maxSize int, maxAge time.Duration) (*fileSpanExporter, error) {
	rf, err := newRotatingFile(dir, maxSize, maxAge)
	if err != nil {
		return nil, err
	}
	return &fileSpanExporter{rf: rf}, nil
}

func (e *fileSpanExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	if len(spans) == 0 {
		return nil
	}
	req := spansToOTLP(spans)
	line, err := marshalOTLPJSON(req)
	if err != nil {
		return fmt.Errorf("telemetry: marshal OTLP-JSON: %w", err)
	}
	return e.rf.WriteLine(line)
}

func (e *fileSpanExporter) Shutdown(_ context.Context) error {
	return e.rf.Close()
}
