# Egress firewall and SSRF guard

**Who and why:** operators front an application's outbound traffic to deny loopback, private, link-local, and metadata addresses even when an allowed hostname resolves to them.

**MITM required?** No. Egress policy runs after the connection rule and before any upstream dial, including on `mitm:false` splices.

Use ordered `egress[]` entries to make narrow exceptions before broad denies. Every address returned by the one pinned DNS resolution must be allowed; a mixed public/private response is rejected. An empty list or fall-through denies.

You get DNS-rebinding resistance and `403 ERR_FORWARDING_DENIED` audit events. You do not get a replacement for the firewall that blocks clients from bypassing the proxy.

Next: [configure egress](../config/egress.md) or [follow the Docker tutorial](../tutorials/egress-docker.md).

If the workload cannot be configured with `HTTP_PROXY`/`HTTPS_PROXY`, the intended transparent deployment steers its traffic with nftables. See [Transparent interception](transparent.md) for the REDIRECT and TPROXY choices.
