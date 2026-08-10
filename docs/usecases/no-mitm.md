# Policy proxy without MITM

Use `mitm:false` when the proxy should authorize a connection without decrypting it. The client negotiates TLS directly with the real origin through a raw **splice**.

## What still works

- top-down connection-phase matching on `host`, `port`, and `proto`;
- per-client effective rule files and proxied client `uuid`;
- resolved-address `egress[]` policy, including DNS-rebinding protection;
- explicit proxy authentication;
- one access-log record per tunnel, plus metrics and traces.

--8<-- "tested/rules/docker-egress.json"

Apply it with `PUT /rules/{client-ip}`. Requests to either named origin on port 443 are spliced. An unlisted origin matches no rule and receives `511` before an upstream socket is opened.

## What you give up

Encrypted method, path, headers, and body remain invisible. Consequently, message-phase matching, header/credential injection, body replacement, and broker decisions about individual encrypted requests are unavailable. A `mitm:false` rule cannot contain message-phase match fields or mutation blocks.

!!! warning
    `mitm:false` authorizes a tunnel to the matched authority. It does not make payload claims. Keep `egress[]` deny-first and use an external firewall to prevent direct egress.

Next: [run the Docker tutorial](../tutorials/egress-docker.md) or learn [identity and rule phases](../concepts/identity-rules.md).

