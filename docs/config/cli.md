# CLI and flags

Every flag has an automatically derived `MITMANIA_*` environment variable; a command-line value wins. Run `mitmania --help` for the authoritative defaults in your build.

| Area | Flags |
| --- | --- |
| Shared state | `-s, --storage`; `-k, --cluster-key`; `-c, --control` |
| Listeners | `--listen-http-proxy`; `--listen-https-proxy`; `--listen-http-tproxy`; `--listen-http-redirect` (transparent, Linux-only) |
| HTTP bounds | `--http-header-limit` (`64k`); `--http-body-window` (`64k`) |
| HTTP/1 timeouts | `--http-timeout-connect`; `--http-timeout-read`; `--http-timeout-client-read` (`30s`); `--http-connect-tries` |
| HTTP/2 timeouts | `--http2-timeout-connect`; `--http2-timeout-read`; `--http2-connect-tries` |
| Brokers | `--outcall-timeout-connect`; `--outcall-timeout-read`; `--outcall-max-inflight` |
| Identity | `--trusted-proxies` |
| Logs | `--log-level`; `--log-format`; `--no-access-logs` |
| Telemetry | `--otel-metrics`; `--otel-traces`; `--otel-resource`; sampling, propagation, and spool flags |

Address values are URL-like: `tcp://HOST:PORT` or `unix:///path`; `*` means all IPv4 and IPv6 interfaces. `clusterKey` is base64 and must decode to at least 32 bytes. When `XDG_RUNTIME_DIR` is unset, supply `--control` explicitly.

!!! note "Applies to v1"
    At least one data listener is required; a configuration with none of the four listener flags set fails at startup. `--listen-http-tproxy`/`--listen-http-redirect` are Linux-only and reject a `unix://` address (see [the FAQ](../faq.md) for why).

