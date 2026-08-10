# Control plane vs. data plane

mitmania is the **data plane**: a fleet of interchangeable nodes that carry and enforce traffic. It has no opinion about *why* a rule says what it says, and no built-in notion of who's allowed to change one — that's a control plane's job, and mitmania doesn't ship one. Anything that can write to `Storage` or call the control socket qualifies: a human with `curl`, a GitOps reconciler, a CMDB exporter, a Terraform provider.

## Why this split is real, not aspirational

- **Rule selection is a pure function of network facts.** Which file governs a connection depends only on the client's address — never on an authenticated principal or any application-layer identity. `auth.http_proxy` *attributes* a connection (the principal is logged) but never *selects* its rules. See [identity, rules & phases](identity-rules.md).
- **Zero per-node state.** A node's entire input is `{storage URL, clusterKey, listener addresses}`. Rule files are just blobs in `Storage`; nothing is baked into a node beyond that.
- **Convergence without a sync protocol.** Nodes pick up new state through `Storage`'s own change-versioning — no gossip, no leader, no bespoke RPC a control plane has to speak. Write the state; the fleet converges. See [distributed operation](distributed.md).
- **One narrow, stable interface.** The `Storage` keyspace (`ca/`, `leaf/`, `rules/`) and the control socket (`PUT /rules/{ip}`, `PUT /rules/default`, `DELETE /cache`) are the whole surface. Nothing else needs to know mitmania exists.

## The one deferral seam

Outcalls (`webhook`, `header.fetch`) let a rule ask an external broker for a per-request decision or credential — the single place mitmania defers a real-time decision to something else, and it's deliberately bounded: no retries, fail-closed by default, validated by actually calling the broker at load time. This is the data plane calling out to a policy control plane mid-request, not a backdoor into rule selection. See [outcalls (brokers)](../config/outcalls.md).

Next: [drive a broker as your policy control plane](../usecases/broker.md), or the [rule-file schema](../reference/rule-schema.md) if you're the one writing the state.
