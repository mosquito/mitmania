# CLI and flags

Every flag has an automatically derived `MITMANIA_*` environment variable; a command-line value wins. Run `mitmania --help` for the authoritative defaults in your build.

| Area | Flags |
| --- | --- |
| Shared state | `-s, --storage`; `-k, --cluster-key`; `-c, --control` |
| Listeners | `--listen-http-proxy`; `--listen-https-proxy`; reserved transparent listener flags |
| HTTP bounds | `--http-header-limit` (`64k`); `--http-body-window` (`64k`) |
| HTTP/1 timeouts | `--http-timeout-connect`; `--http-timeout-read`; `--http-connect-tries` |
| HTTP/2 timeouts | `--http2-timeout-connect`; `--http2-timeout-read`; `--http2-connect-tries` |
| Brokers | `--outcall-timeout-connect`; `--outcall-timeout-read`; `--outcall-max-inflight` |
| Identity | `--trusted-proxies` |
| Logs | `--log-level`; `--log-format`; `--no-access-logs` |
| Telemetry | `--otel-metrics`; `--otel-traces`; `--otel-resource`; sampling, propagation, and spool flags |

Address values are URL-like: `tcp://HOST:PORT` or `unix:///path`; `*` means all IPv4 and IPv6 interfaces. `clusterKey` is base64 and must decode to at least 32 bytes. When `XDG_RUNTIME_DIR` is unset, supply `--control` explicitly.

!!! note "Applies to v1"
    The transparent TPROXY and REDIRECT flags appear in help but are not implemented. A zero-data-listener configuration fails at startup.

