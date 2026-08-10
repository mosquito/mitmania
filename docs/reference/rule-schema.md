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

`rules/default` wraps this same shape in a source-prefix object and additionally rejects prefix coverage gaps for either IPv4 or IPv6.

