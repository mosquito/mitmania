# Rule-file schema

The machine-readable schema used by documentation tooling is [rule-file.schema.json](../tested/schema/rule-file.schema.json). The Go test suite additionally decodes and compiles every file in `docs/tested/rules` through the production rule engine.

## Top level

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `uuid` | string | minted when possible | proxied client's stable broker/cache identity |
| `auth` | object | auth not required | protocol authentication namespaces |
| `egress` | array | inherit default bucket | resolved-address policy; present empty denies all |
| `http` | array | required | ordered HTTP rule chain |

## HTTP rule

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `match` | object | all omitted fields wildcard | `host`, `port`, `proto`, `path`, `method`, `header`, `status` |
| `mitm` | boolean | `true` | false selects a connection-phase splice |
| `request` | action array | empty | ordered request actions |
| `response` | action array | empty | ordered response actions |

Action objects have required string `action` and optional object `params`. Supported names and phases are listed in [Matching and actions](../config/actions.md). Egress objects require `cidr` and `action`, with optional `port` and `proto`. Auth fields are listed in [Client authentication](../config/auth.md).

## Load-time rejection

Strict control-API loading rejects unknown JSON fields, malformed JSON, invalid CIDRs/ports, actions other than `allow`/`deny`, malformed auth hashes, invalid glob/regex syntax, unknown or phase-inapplicable actions, malformed action parameters, and outcalls without exactly one target. `raise`/`block` cannot appear in `response`; a `mitm:false` rule cannot use message-phase match fields.

!!! warning
    `status` is accepted for schema compatibility but is not evaluated by the current two-pass engine. Do not author policy that depends on it.

!!! note
    The rule engine notices a changed Storage key on its own (no explicit reload endpoint — see [Rule lookup caching](../config/rules.md#rule-lookup-caching)) and always picks up a genuine content edit, regardless of `uuid`. As a pure performance optimization it skips recompiling when the reloaded content turns out to be byte-identical to what's already compiled (e.g. a redundant re-apply, or an edit to a different `rules/default` bucket in the same blob) — this never masks a real change, since it compares full content, not just `uuid`.

## `rules/default`

`rules/default` wraps this same per-file shape in an object keyed by address/mask entries, one bucket per key. Each bucket value is a full rule file and is validated exactly as a per-IP file is.

| Aspect | Behavior |
| --- | --- |
| Key syntax | `addr/N` (decimal prefix length) or `addr/mask` (literal mask in the family's notation, contiguous or sparse) |
| Normalization | out-of-mask address bits cleared; a contiguous literal mask stored as `/N`; keys that normalize to the same entry collapse, last one wins |
| Ranking | one list per family, sorted by mask value descending; first match wins (subsumes but is not identical to longest-prefix-match) |
| Coverage | plain-prefix entries must jointly cover all of IPv4 and all of IPv6, no gaps; sparse-mask entries are exempt |
| Persisted form | `PUT` stores the canonical (normalized) form; `GET` echoes it verbatim |

A coverage gap is rejected at `PUT` time, naming the missing range, e.g. `rules/default: v4 coverage gap: 128.0.0.0-255.255.255.255 not covered`. See [The default rule table](../config/default-ruleset.md) for worked examples and the bootstrap seed.

