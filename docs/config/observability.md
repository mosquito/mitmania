# Telemetry and logging

Structured stderr logging is always on. `--log-format` selects `plain`, `json`, or `cat`; `--no-access-logs` suppresses only the per-request/per-tunnel record. Storage URLs and rule secrets are redacted or omitted from logged fields.

Telemetry is off until a sink is configured:

- `--otel-metrics http://host:port/path` exposes Prometheus metrics;
- `--otel-traces otlp+grpc://...` or `otlp+http://...` pushes traces;
- `--otel-traces file:///path/` writes a rotating JSONL spool;
- `--otel-traces stdout://` is useful for local diagnosis.

Client trace parenting and upstream `traceparent` propagation are both off by default. Enable them only when revealing trace linkage is acceptable.

See [Monitoring and dashboards](../ops/monitoring.md) and the [metrics catalog](../reference/metrics.md).

