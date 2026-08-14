# Metrics catalog

Names below are OpenTelemetry names; Prometheus commonly renders dots as underscores and appends unit/type suffixes.

| Family | Type | Labels |
| --- | --- | --- |
| `mitmania.connections.active` | up/down counter | `listener`, `transport` |
| `mitmania.connections.total` | counter | `listener`, `transport` |
| `mitmania.requests.total` | counter | `proto`, `outcome`, `status_class`, `verdict`, `mitm` |
| `mitmania.request.duration` | histogram, seconds | `proto` |
| `mitmania.bytes.streamed` | counter, bytes | `direction` |
| `mitmania.upstream.dials.total` | counter | `result` |
| `mitmania.upstream.dial.duration` | histogram, seconds | `proto`, `result` |
| `mitmania.upstream.ttfb` | histogram, seconds | `proto` |
| `mitmania.upstream.reconnects.total` | counter | `reason` |
| `mitmania.tls.handshake.duration` | histogram, seconds | `leg`, `result` |
| `mitmania.cert.mints.total` | counter | `kind` |
| `mitmania.cert.cache.total` | counter | `result` |
| `mitmania.cert.duration` | histogram, seconds | `op`, `cache_result` |
| `mitmania.rules.compiles.total` | counter | `result` |
| `mitmania.rules.active_clients` | up/down counter | none |
| `mitmania.rules.compile.duration` | histogram, seconds | `result` |
| `mitmania.outcall.total` | counter | `action`, `result` |
| `mitmania.outcall.inflight` | up/down counter | none |
| `mitmania.outcall.duration` | histogram, seconds | `action`, `cache_result` |
| `mitmania.outcall.cache.total` | counter | `result` |
| `mitmania.storage.op.duration` | histogram, seconds | `op`, `backend`, `result` |

No family labels by client IP, `uuid`, host, URL, or principal; that avoids attacker-controlled cardinality. Use traces and access logs for those dimensions.

`verdict` (`allow`/`deny`) and `mitm` (`true`/`false`/`unknown`) are coarser groupings derived from `outcome` — `sum by (verdict)` or `sum by (mitm)` without regex-matching the full `outcome` vocabulary (see [The access record](logs.md) for its values). `mitm` is `unknown` whenever the connection-phase mitm decision either hadn't been made yet (an auth/protocol failure ahead of connection-phase rule matching) or isn't recoverable from `outcome` alone (`forwarding-denied`/`resolve-fail`/`connect-fail` can each happen on either a `mitm:true` or `mitm:false` path) — never guessed.

```promql
histogram_quantile(0.95,
  sum by (le) (rate(mitmania_request_duration_seconds_bucket[5m])))
```

_Implementation source: `internal/telemetry/instruments.go`._

