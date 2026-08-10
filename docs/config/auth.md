# Client authentication

`auth.http_proxy` applies only to explicit listeners and supports local Basic credentials, local Bearer credentials, or a broker. Set `required:true` to fail missing credentials with `407`.

| Field | Meaning |
| --- | --- |
| `required` | require a valid `Proxy-Authorization` header |
| `realm` | Basic challenge realm |
| `basic[]` | `user` plus canonical Argon2id PHC `hash` |
| `bearer[]` | principal `id` plus `sha256:<hex>` hash |
| `broker` | exactly one of `socket` or `url`, with optional `path` |

Successful credentials are stripped before forwarding. Transparent traffic governed by an auth-required rule fails closed because it has no proxy-auth exchange.

!!! warning
    Authentication binds a principal to logs and broker envelopes; it does not replace the source-IP-selected effective rule file or proxied client `uuid`.

