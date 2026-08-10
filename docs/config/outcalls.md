# Outcalls to brokers

`webhook` asks whether a request may continue. `header.fetch` asks for headers to add. Each action targets exactly one Unix socket or HTTP URL, has bounded connect/read timeouts, and participates in a process-wide inflight limit.

Sensitive request headers are masked and bodies are never sent. A `webhook` is not retried. A secret fetch may use broker-directed caching, always namespaced by the effective rule file's `uuid`. `failOpen` must be set explicitly; the default fails closed.

Saving a rule through the control API performs a validation-only broker call and discards its response. Use `?validate=false` only to break a controlled bootstrap dependency.

!!! danger "Security"
    Scope brokers by socket permissions, network policy, proxied client `uuid`, and destination. Never treat masking in logs as a substitute for restricting the broker's authority.

See the exact [broker wire format](../reference/wire-format.md).

