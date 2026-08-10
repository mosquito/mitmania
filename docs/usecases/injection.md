# Header and credential injection

**Who and why:** agent and platform teams keep upstream credentials out of sandboxes. A broker supplies request headers for one proxied client and destination.

**MITM required?** Yes for HTTPS, because headers are inside TLS.

Match the narrowest origin, then use `header.fetch` or static `header.add`/`header.set`. The broker receives the effective rule file's `uuid`; returned framing, addressing, hop-by-hop, and proxy-auth headers are rejected.

The client never sees the injected token, but the proxy and broker handle it in memory. Scope broker permissions and cache lifetime narrowly. Continue with the [broker-token tutorial](../tutorials/broker-token.md) or [Outcalls configuration](../config/outcalls.md).

