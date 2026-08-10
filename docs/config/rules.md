# Rule files

A rule file governs one source: either one client address, as a per-IP
override, or one bucket of the default table. The two use the identical
JSON shape.

--8<-- "tested/rules/get-started.json"

## Per-IP overrides

Per-IP overrides are managed with `GET`, `PUT`, and `DELETE /rules/{ip}`. An
override replaces the entire effective rule file for that client and always
wins over the default table.

`PUT` validates strict JSON, compiles matches/actions, validates egress and
auth, and probes outcalls unless `?validate=false` is present. Changes become
visible on a later connection; there is no reload signal.

!!! warning
    Omitting `egress` from a per-IP override inherits the egress list of the
    default-table bucket that covers this client. Supplying `"egress": []`
    denies every destination. The two forms are intentionally different.

## The default table

Every client **without** a per-IP override resolves against `rules/default`, a
gapless table keyed by IPv4/IPv6 prefixes or sparse masks and managed with
`GET` and `PUT /rules/default`. It has its own ranking, coverage rules, and
bootstrap seed — see [The default rule table](default-ruleset.md).

See the exhaustive [rule-file schema](../reference/rule-schema.md) and the two rule phases in [Identity, rules, and phases](../concepts/identity-rules.md).
