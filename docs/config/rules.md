# Rule files

A rule file governs one source address or one bucket of `rules/default`:

--8<-- "tested/rules/get-started.json"

Per-IP overrides are managed with `GET`, `PUT`, and `DELETE /rules/{ip}`. The default table is a complete JSON object keyed by IPv4 and IPv6 prefixes or sparse masks and is managed with `GET` and `PUT /rules/default`. A per-IP override wins; otherwise the most specific matching default bucket supplies the whole effective rule file.

`PUT` validates strict JSON, compiles matches/actions, validates egress and auth, and probes outcalls unless `?validate=false` is present. Changes become visible on a later connection; there is no reload signal.

!!! warning
    Omitting `egress` from a per-IP override inherits the covering default bucket. Supplying `"egress": []` denies every destination. The two forms are intentionally different.

See the exhaustive [rule-file schema](../reference/rule-schema.md) and the two rule phases in [Identity, rules, and phases](../concepts/identity-rules.md).
