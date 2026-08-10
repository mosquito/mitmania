# Identity, rules, and phases

The **proxied client `uuid`** is the stable identity stored at the top of an effective rule file and sent to brokers. Rule selection itself begins with the client's source IP: a per-IP override wins; otherwise the best matching `rules/default` bucket becomes effective.

On an explicit listener behind an approved proxy, `--trusted-proxies` lets mitmania recover the client IP from `X-Forwarded-For` or `X-Real-IP`. Proxy authentication gates the already-selected file and records a principal; it does not select a different rule file.

Within `http[]`, rules are ordered and first-match-wins:

1. connection phase sees `host`, `port`, and `proto` and decides MITM versus splice;
2. message phase, when intercepted, also sees `path`, `method`, and request headers;
3. only the selected rule's ordered request and response pipelines execute.

Keep narrow matches above broad ones. End with `{"match": {}}` only when an explicit catch-all is intended.

See [Rule files](../config/rules.md), [Client authentication](../config/auth.md), and [Load balancing and identity](../ops/lb-identity.md).

