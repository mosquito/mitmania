# Capacity and sizing

A node's own inputs are just Storage, `clusterKey`, and its listeners — sizing is about the three resources that scale with load.

## Memory: the leaf-cert hot-map

Each process keeps parsed synthetic chains (no private keys — those are re-derived per call) in an in-memory hot-map, in front of the durable `leaf/` cache. It has no TTL eviction: entries drop only when they fail verify-on-hit. So node memory scales with the **number of distinct upstream chains that node observes between restarts**, not with client count. Size for the distinct-origin working set; restart reclaims it. `rules.active_clients` similarly tracks the count of compiled rule sets held in memory.

## Latency budget

`request.duration` is, in order: upstream dial (`upstream.dial.duration`) + response wait (`upstream.ttfb`) + a cert mint only on a cache miss + both TLS handshakes (`tls.handshake.duration`, legs `client` and `upstream`). A cache hit adds sub-millisecond to low-single-digit-millisecond overhead; the origin dominates. Bodies are always streamed, so per-request memory is bounded by `--http-header-limit` and `--http-body-window` (64k each by default), independent of payload size.

## Outcall concurrency

`--outcall-max-inflight` is a single process-wide limit across every broker action combined. At the limit, further outcalls fail — and under the default fail-closed that means **denied requests**, not queuing. Size it at or above your peak count of concurrent requests that hit `webhook`/`header.fetch` rules, and alert at 80% of it (see [monitoring](monitoring.md)). Per-call `--outcall-timeout-connect`/`--outcall-timeout-read` bound how long each in-flight slot is held.

## Scaling out

Nodes are stateless and interchangeable; add them behind the L4 balancer with the same Storage URL and `clusterKey`. No node-to-node traffic, no rebalancing — a new node warms its own hot-map from Storage on first use.
