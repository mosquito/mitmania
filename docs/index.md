# mitmania

**A stateless data plane for egress, scaled horizontally with near-zero per-node state.** A node needs only the shared storage URL, the out-of-band `clusterKey`, and its listener addresses. The signing CA, cached leaf identities, and effective rule files live behind shared Storage.

mitmania controls outbound HTTP and HTTPS from containers, VMs, and sandboxes. It can authenticate clients, constrain resolved destinations, audit tunnels, intercept TLS, mutate traffic, and ask brokers for decisions or credentials. It does not decide organizational policy itself — see [control plane vs. data plane](concepts/control-plane.md) for what that split means and who owns which side of it.

!!! tip "Interception is optional"
    Start with a policy proxy using `mitm:false`. TLS remains end-to-end and no CA installation is required. You still get client identity, connection-phase rules, egress controls, access logs, and metrics. See [Policy proxy without MITM](usecases/no-mitm.md).

## Pick your path

| I want to… | Start here |
| --- | --- |
| Run one useful node | [Get started](start/install.md) |
| Choose a deployment pattern | [Use cases](usecases/index.md) |
| Evaluate containment and trust | [Security](security/threat-model.md) |

## When not to use it

Do not use mitmania as the only containment boundary: a firewall must prevent clients from reaching the network directly. It is not a general-purpose reverse proxy, a packet firewall, or a shipped implementation of the design's future SSH, IMAP, HTTP/3, Redis, or PostgreSQL handlers.

