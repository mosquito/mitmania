# Runbooks

Incident response for the failure modes this architecture actually has. Every node is interchangeable and state is shared, so most of these self-heal — the operator's job is to recognize the signal and not overreact.

## A node's CA or clusterKey is out of sync

**Symptom.** On the affected node: `WARN cert cache: hot-map entry failed verify-on-hit, treating as a miss` (and the `storage` variant), rising `cert.cache.total{result="miss"}`, rising `cert.mints.total{kind="leaf"}`. Clients keep working.

**What it is.** Verify-on-hit re-derives each cached leaf key and re-checks the chain against the *current* CA before serving; a mismatch is treated as a miss and the leaf is re-minted. A `.tuple` fingerprint change also triggers a best-effort `leaf/` wipe. This is the designed self-heal after a CA or `clusterKey` change — **not** an error. It converges without coordination.

**Action.** None, if you intended the CA/`clusterKey` change: let it settle, expect a transient mint/miss bump and slightly higher latency. If you did **not** change either, one node has stale inputs (wrong `clusterKey`, or an old `ca.p12` snapshot) — reconcile that node's inputs against the fleet, then it converges on its own.

## Leaf cache grows or looks stale

**Not a correctness risk.** There is no TTL and no freshness check by design: MITM dials upstream every connection, so a renewed origin chain has a new fingerprint, a new cache id, and a natural miss. Verify-on-hit guarantees a stale entry is never served. Growth is the only concern, and the in-process hot-map is bounded by the *distinct-origin working set*, not by client count.

**To reclaim durable `leaf/` space** (e.g. after mass certificate churn), issue `DELETE /cache` on the control socket; entries re-mint on demand. Never manually delete `rules/` while doing so.

## A broker is unreachable

**Symptom.** `outcall.total{result="fail"}` rising; requests routed through a `webhook`/`header.fetch` action start being **denied**, not merely delayed.

**Know this first.** The default is fail-closed. A broker outage is a partial outage of *traffic that touches broker rules*, immediately. `outcall.inflight` pinned at `--outcall-max-inflight` produces the same denials from saturation alone.

**Action.** Restore the broker (socket/network policy/capacity). Only if availability explicitly outweighs containment for that rule, set `failOpen:true` on it — deliberately, per the hardening checklist. Raise `--outcall-max-inflight` if the failures are saturation, not the broker being down.

## Storage (S3) outage

**Symptom.** `storage.op.duration{backend="s3"}` latency/error climb.

**Blast radius.** Running nodes degrade gracefully: cache reads fall through to re-mint (the CA is already in memory), and rule loads fall back to the last compiled in-memory set. What **stops**: control-plane writes (rule/CA/cache changes) and **cold-start of new nodes** (they cannot read `ca.p12`). So during an S3 outage, do not roll or scale up the fleet — existing nodes keep serving.

**Action.** Restore Storage. Defer deploys and autoscaling until it is healthy.

## rules/default fails coverage validation

**Symptom.** A `PUT /rules/default` returns 400 naming the rejected condition (typically the gapless-coverage obligation for ordinary prefixes).

**What it is.** An incomplete default table is rejected outright; the previously saved complete table stays in force. You are never left with no default.

**Action.** Fix the submitted table so v4 and v6 ordinary prefixes each cover the whole space, then re-PUT. **Never `DELETE rules/default`** to "start over" — replace it with another complete table. Sparse (non-contiguous mask) entries are pure overrides and exempt from coverage in both directions; a gap is always in an ordinary prefix.
