# Secret rotation and recovery

Procedures for the operator, complementing the principles in [Secrets at rest](secrets.md) and [CA management](../ops/ca.md).

## Rotate clusterKey

`clusterKey` is two things at once: the key that decrypts `ca.p12` **and** the derivation input for every leaf private key. A node with the new key cannot read a `ca.p12` still encrypted under the old one, so this is a **coordinated flag-day, not a rolling change**. Sequence: re-encrypt `ca.p12` in Storage under the new key, distribute the new key to every node, then `DELETE /cache` so leaves re-mint under the new derivation. No per-leaf rotation job exists because leaf keys are never stored. Clients pin the CA, not leaf keys, so the leaf-key change is transparent.

## If clusterKey leaks

Treat the signing CA as compromised. `clusterKey` is the one secret that turns durable encrypted or derivable material into signing capability: whoever has it can decrypt `ca.p12` and derive any leaf key. Rotating `clusterKey` alone is insufficient — the CA private key itself is exposed. Stand up a **new** signing CA under a **new** `clusterKey`, distribute the new trust anchor, remove trust in the old CA at every client, and `DELETE /cache`. Until old trust is withdrawn, forged leaves remain valid to clients.

## Rotate broker credentials

Broker tokens and injected credentials live inside rule files (stored `0600`, masked in logs and `/stats`). Rotate by `PUT`ting the updated rule file through the control API: its load-time probe validates the new credential by actually calling the broker, so a bad rotation is rejected at save time, not at first request. Roll the broker side and the rule side together. Use `?validate=false` only to break a deliberate bootstrap ordering where the broker starts after the rule.

## Back up and restore Storage

Back up the Storage backend and escrow `clusterKey` **separately** — a Storage backup without the key is unusable by design (`ca.p12` won't decrypt, leaves won't derive), which is exactly what protects it.

- **Must back up:** `ca/ca.p12` and `rules/` (`rules/ip/*`, `rules/default`).
- **Skip:** `leaf/` — the leaf cache regenerates on demand; backing it up only ages faster.
- **Restore:** restore Storage, provide `clusterKey` to the nodes, and they resume. Ensure the restored `rules/default` is a complete (gapless) table, or the first control-plane write over it will be rejected.
