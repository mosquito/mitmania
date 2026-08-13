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

## Rule lookup caching

Every connection resolves its effective rule file by checking Storage's cheap version fingerprint first — no full read — and only re-reads/recompiles when that fingerprint changed. `--rules-cache-ttl` (seconds, default `1`; `0` disables) bounds how long a resolved lookup is trusted before even checking that fingerprint again. A per-client override, "confirmed no override" (falls back to `rules/default`), and the default table itself each carry their own independent window. Within the window, a lookup returns straight from memory with no Storage call at all; once it elapses, the next lookup reconfirms — and, if the fingerprint is still unchanged, the window slides forward from that point rather than expiring on a fixed schedule.

With a non-zero TTL, a lookup that's still within its window keeps serving its last-known-good result even if Storage becomes temporarily unreachable, instead of failing every connection the instant Storage blips. With `--rules-cache-ttl 0`, caching is off entirely: every connection reconfirms against Storage, and a Storage error always fails the lookup closed — the original, still-default-adjacent-but-more-cautious behavior for anyone who wants it.

Independently of the TTL, recompiling a file's `http[]`/`egress[]`/`auth` is itself skipped whenever a reconfirmed reload turns out to be byte-for-byte identical to what's already compiled — e.g. a redundant re-apply of the same content, or (for `rules/default`) an edit to a different bucket in the same blob. This compares full content, never just `uuid`, so it can never mask a genuine edit.
