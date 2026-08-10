# Broker wire format

All broker calls are HTTP POST requests using wire version 1.

```json
{
  "version": 1,
  "action": "webhook",
  "uuid": "proxied-client-id",
  "client": "192.0.2.10",
  "proto": "http",
  "dst": "203.0.113.20:443",
  "http": {
    "method": "GET",
    "url": "https://api.example.test/v1",
    "headers": {"Accept": ["application/json"]}
  }
}
```

`uuid` is logical identity from the effective rule file; `client` is the observed/recovered source IP and never substitutes for it. `dst` is the resolved and pinned address. `http.headers` contains only the action's `send` allowlist, with authorization, proxy-authorization, and cookie values masked.

| Action | Extra request | 2xx response |
| --- | --- | --- |
| `webhook` | `http` | empty body or envelope; continue |
| `header.fetch` | `http` | `{"http":{"headers":{"Authorization":["Bearer …"]}}}` |
| `auth` | `credential:{scheme,value}` | `{"principal":"name"}` |

A non-2xx broker response denies. Its JSON `message` becomes the human error and `http_status` may select the client status; otherwise mitmania returns `403 ERR_OUTCALL_DENIED`. Unreachable, timed-out, malformed, or forbidden-header responses become `502 ERR_OUTCALL_FAIL` unless that action explicitly sets `failOpen:true`.

For `header.fetch`, a JSON `null` header value deletes it. Brokers may not set `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Upgrade`, or `TE`; proxy-only headers are stripped by the HTTP pipeline.

Cache behavior follows a constrained HTTP model driven by `Cache-Control`, `Expires`, `ETag`, and conditional validation. Cache partitions include the effective `uuid` and compiled action identity. A rule PUT probe never seeds the serving cache.

