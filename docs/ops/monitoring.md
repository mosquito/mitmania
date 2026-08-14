# Monitoring and dashboards

Expose a Prometheus endpoint with `--otel-metrics http://127.0.0.1:9464/metrics`, then scrape that exact path. The [metrics catalog](../reference/metrics.md) is the full instrument list; this page is the subset worth alerting on and how to read it.

## Import the Grafana dashboard

The repository includes two importable dashboards for the full metric catalog. Both cover fleet load, final policy outcomes, upstream health, Storage, rules, certificates, TLS, and broker outcalls:

- [Grafana dashboard for Prometheus](../assets/mitmania-grafana.json) uses Grafana's built-in Prometheus data source.
- [Grafana dashboard for VictoriaMetrics](../assets/mitmania-victoriametrics-grafana.json) uses the official [`victoriametrics-metrics-datasource`](https://docs.victoriametrics.com/victoriametrics/integrations/grafana/datasource/) plugin. Its queries use the PromQL subset of MetricsQL, so the panels have the same semantics as the Prometheus version.

1. Configure Prometheus, vmagent, or VictoriaMetrics' native scraper to scrape every mitmania node's metrics endpoint.
2. In Grafana, import the JSON file matching the metrics backend.
3. Select the backend data source when Grafana prompts for `DS_PROMETHEUS` or `DS_VICTORIAMETRICS`.
4. Use the dashboard's **Scrape job** and **Instance** variables to select the fleet or node to inspect.
5. If `--outcall-max-inflight` is not its default of `64`, set **Outcall capacity** to the configured value so the saturation gauge is accurate.

For single-node VictoriaMetrics, point its Grafana data source at `http://<victoriametrics>:8428`. For a cluster, use the vmselect query endpoint `http://<vmselect>:8481/select/<tenant>/prometheus`.

The dashboard treats `splice (mitm:false)` as successful raw encrypted traffic and `empty-connection` as neutral listener churn. It keeps `no-match`, `forwarding-denied`, authentication failures, and deliberate rule blocks distinct so policy behavior is not confused with upstream failure. Panels for message-phase TTFB, bytes, TLS termination, certificates, and outcalls remain empty until those paths are exercised; that is expected on a pure `mitm:false` deployment.

## Signals that matter

| Watch | Metric (label values) | Healthy | Alert when — and why |
| --- | --- | --- | --- |
| Request errors | `requests.total` `outcome` | mostly `ok`; steady `block`/`no-match` from policy | non-`ok` ratio climbs. A `no-match` spike is a rule-coverage gap sending clients 511; `auth-failed`/`forwarding-denied` spikes are a client or trusted-proxy misconfig |
| Latency | `request.duration` p95/p99 | dominated by `upstream.dial.duration` + `upstream.ttfb`; the proxy itself adds only mint + handshake | p95 grows while upstream latency does not — the proxy, not the origin, is the cost |
| Upstream health | `upstream.dials.total` `result` | `ok` | `timeout`/`refused`/`dns`/`tls` rising is an origin or egress-path problem, not the proxy. Don't page the proxy team for a `refused` spike |
| Cert path | `cert.cache.total` `result`; `cert.mints.total` `kind` | hit ratio `(hotmap+storage)/all` high and stable; `kind="leaf"` mints only on genuinely new/renewed chains | hit ratio collapses with mints rising = self-heal in progress ([runbooks](runbooks.md)) or a churning working set. `kind="fallback"` rising = upstreams failing after CONNECT, so clients get error pages over TLS |
| Rules | `rules.compiles.total` `result="error"` | zero | any nonzero = a node loaded a rule file from Storage it cannot compile; that client keeps its prior in-memory set |
| Outcalls | `outcall.total` `result`; `outcall.inflight` | `allow`/`deny` from real decisions; inflight well under `--outcall-max-inflight` | `result="fail"` rising = broker unreachable or over capacity. Under the default fail-closed this **denies** traffic, not just slows it. `inflight` near the limit is saturation, which itself starts failing closed |
| Storage | `storage.op.duration` p95, `result` | low, stable | p95 or non-`ok` climbing (especially `backend="s3"`) slows cache reads and rule loads fleet-wide |
| Load | `connections.active` | tracks known client count | flat-lining at a ceiling is an fd or accept limit |

`outcall.total`'s result vocabulary is `allow`/`deny`/`fail` — there is no `ok`. Alert on `result="fail"`, never `result!="ok"`.

## Example alerts

Overall error ratio (raise the floor to your normal `block`/`no-match` volume):

```promql
sum(rate(mitmania_requests_total{outcome!="ok"}[5m]))
  / sum(rate(mitmania_requests_total[5m])) > 0.05
```

Broker failures — each denies a request under the default fail-closed:

```promql
sum(rate(mitmania_outcall_total{result="fail"}[5m])) > 0.1
```

Outcall saturation (substitute your configured `--outcall-max-inflight`):

```promql
max(mitmania_outcall_inflight) / <outcall-max-inflight> > 0.8
```

Rule compile failure on any node:

```promql
sum(rate(mitmania_rules_compiles_total{result="error"}[5m])) > 0
```

Cert-cache miss ratio — a sustained jump can be a CA/`clusterKey` mismatch self-healing; cross-check the [runbooks](runbooks.md):

```promql
sum(rate(mitmania_cert_cache_total{result="miss"}[5m]))
  / sum(rate(mitmania_cert_cache_total[5m])) > 0.5
```

Prometheus normalizes OpenTelemetry dots to underscores and appends unit/type suffixes. Check your exporter output before copying selectors. The metric families deliberately carry no client-IP, principal, or URL labels — for those dimensions use the [access log](../reference/logs.md) and traces.
