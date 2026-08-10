package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
)

// defaultServiceName is service.name's value when --otel-resource doesn't
// override it — the same generic-by-default posture as the root CA's own
// non-descriptive Subject and the https-proxy listener's default CN
// ("Internal Proxy"): identifying detail is opt-in, not assumed.
const defaultServiceName = "mitmania"

// nodeID is a random identifier minted once per process — merged into
// every Resource as service.instance.id so multiple mitmania processes
// sharing one --otel-resource config (e.g. a fleet of interchangeable
// mitmania nodes behind the same collector) are still distinguishable in
// telemetry, without requiring an operator to hand-assign one.
var nodeID = newNodeID()

func newNodeID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is effectively unrecoverable elsewhere in
		// this codebase too (cert key generation would already have
		// failed); a fixed fallback here just avoids a hard panic for a
		// non-security-sensitive correlation id.
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

// buildResource parses --otel-resource's "k=v,k2=v2" syntax into a
// Resource: service.name defaults to defaultServiceName but is
// overridden if raw sets it explicitly; service.instance.id is always
// nodeID, not overridable (it exists specifically to distinguish
// processes sharing identical config).
func buildResource(raw string) (*resource.Resource, error) {
	attrs := map[string]string{"service.name": defaultServiceName}
	for _, pair := range splitNonEmpty(raw, ',') {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("invalid attribute %q (want k=v)", pair)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "" {
			return nil, fmt.Errorf("invalid attribute %q (empty key)", pair)
		}
		attrs[k] = v
	}

	kvs := make([]attribute.KeyValue, 0, len(attrs)+1)
	for k, v := range attrs {
		kvs = append(kvs, attribute.String(k, v))
	}
	kvs = append(kvs, attribute.String("service.instance.id", nodeID))

	return resource.NewSchemaless(kvs...), nil
}

func splitNonEmpty(s string, sep byte) []string {
	if s == "" {
		return nil
	}
	var out []string
	for part := range strings.SplitSeq(s, string(sep)) {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
