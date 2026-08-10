# Upgrades and consistency

Upgrade nodes behind the load balancer one at a time. Keep old and new versions compatible with the shared certificate clone format and rule schema for the entire overlap window.

Storage propagation is eventual and generation-less: a control-plane write is atomic in the backend, but nodes notice the new version on later connections. Revocation is therefore not an instantaneous fleet barrier. Drain long-lived connections when a policy change must take effect promptly.

When a release changes `cloneFormatVersion`, clear the leaf cache with `DELETE /cache` at the documented point in the rollout. Never delete `rules/default`; replace it with another complete table.

## What is safe to change live

| Change | Rollout |
| --- | --- |
| Binary version | One node at a time behind the LB, keeping clone-format and rule-schema compatible for the whole overlap window |
| Rule files (`rules/ip`, `rules/default`) | Any time; converge via Storage versioning. Replace `rules/default` only with another complete table — never delete it |
| Per-node flags (timeouts, limits, listeners, telemetry) | Per node; no coordination |
| Signing CA | Rolling — verify-on-hit self-heals each node's cache — **but distribute client trust before serving new leaves** (see [runbooks](runbooks.md), [secret rotation](../security/secret-ops.md)) |
| `cloneFormatVersion` bump | Rolling, then `DELETE /cache` at the documented point |
| `clusterKey` | **Not** rolling — a fleet flag-day; mixed keys leave nodes unable to decrypt `ca.p12` (see [secret rotation](../security/secret-ops.md)) |

Do not roll or scale the fleet during a Storage outage: running nodes degrade gracefully, but new nodes cannot cold-start without `ca.p12`.

