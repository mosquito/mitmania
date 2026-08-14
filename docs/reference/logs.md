# Log fields

Structured stderr logging is always on; `--log-format` selects `plain`, `json`, or `cat`. `--no-access-logs` suppresses only the `access` record below — operational records (upstream reconnects, verify-on-hit warnings, startup) still emit. Storage URLs and rule secrets are redacted from all records.

## The `access` record

One record per request or tunnel, message `access`, level `info`.

| Field | Always | Meaning |
| --- | --- | --- |
| `client` | yes | Source identity used for rule selection (recovered client IP behind a trusted proxy) |
| `acceptor` | yes | Which listener/transport accepted the connection |
| `method` | yes | HTTP method, or `CONNECT` for a tunnel; empty when the request never parsed |
| `url` | yes | Absolute request URL, or the CONNECT authority |
| `outcome` | yes | Same vocabulary as `requests.total`'s `outcome` label — see below |
| `verdict` | yes | `allow`/`deny`, derived from `outcome` — same as `requests.total`'s `verdict` label |
| `mitm` | yes | `true`/`false`/`unknown`, derived from `outcome` — same as `requests.total`'s `mitm` label; `unknown` when the connection-phase mitm decision wasn't yet made or isn't recoverable from `outcome` alone |
| `elapsed` | yes | Total handling time |
| `dst` | when resolved | Pinned upstream literal `ip:port`; absent before/without resolution (e.g. an early `no-match`) |
| `principal` | when authenticated | The `auth.http_proxy` identity, for attribution only — it does not select rules |
| `status` | when an HTTP status exists | Absent for raw splices and pre-response failures |
| `error` | on failure | Opaque failure detail; do not parse it for classification — use `outcome`/`status` |

Because `outcome`/`verdict`/`mitm` are identical to their metric labels, a log-based alert and a metric alert classify a request the same way. Key `outcome` values:

- `ok` — forwarded (or spliced) successfully.
- `no-match` — no connection-phase rule matched; client got 511.
- `denied` — a `connection: {"accept": false}` rule rejected the connection outright, before any dial or TLS termination; client got 403 on explicit listeners, a silent close on transparent ones.
- `block` — a rule blocked it (no upstream contacted).
- `forwarding-denied` — egress policy or the self-listener guard denied the resolved destination.
- `auth-required` / `auth-failed` — proxy-auth gate outcomes.
- `misdirected-authority`, `invalid-request`, `invalid-request-shape`, `headers-too-large`, `unsupported-absolute-scheme` — request-shape rejections.
- `empty-connection` — the connection closed before a single byte arrived (health checks, a client racing several connections and abandoning the losers); distinct from `invalid-request`, which means bytes arrived but didn't parse.
- `client-read-timeout` — the client never delivered a complete first request/ClientHello within `--http-timeout-client-read`; client got 408.
- `splice (mitm:false)` — a raw tunnel was opened; no `status`.

## Building alerts and dashboards

Alert on `outcome` transitions the metrics can't dimension per-client: e.g. a single `client` producing sustained `auth-failed`, or `forwarding-denied` for a `dst` you expected to allow. Group by `acceptor` to separate explicit-proxy from transparent traffic. The high-cardinality fields (`client`, `url`, `principal`, `dst`) live only here and in traces — never on metrics.

_Source: `internal/proxy` (`http1.go`, `http2.go`, `transparent.go`, `auth.go`)._
