# Per-client rules with proxy authentication

!!! warning "Identity model correction"
    Proxy authentication does not select per-principal rule files in v1. It gates the effective source-IP rule file and records a principal. Two clients collapsed onto one source IP therefore share that file and proxied client `uuid`, even when their principals differ.

Behind an SNAT load balancer, preserve distinct rule selection with a trusted source-recovery path (`--trusted-proxies` plus validated forwarding headers) or a source-preserving L4 balancer. Use `auth.http_proxy` to gate and attribute those rules, not to re-key them.

See [Load balancing and client identity](../ops/lb-identity.md) and [Client authentication](../config/auth.md).

