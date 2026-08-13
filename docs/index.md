# mitmania

[Source on GitHub](https://github.com/mosquito/mitmania) · [Releases](https://github.com/mosquito/mitmania/releases)

**A stateless data plane for egress, scaled horizontally with near-zero per-node state.** A node needs only the shared storage URL, the out-of-band `clusterKey`, and its listener addresses. The signing CA, cached leaf identities, and effective rule files live behind shared Storage.

mitmania controls outbound HTTP and HTTPS from containers, VMs, and sandboxes. It can authenticate clients, constrain resolved destinations, audit tunnels, intercept TLS, mutate traffic, and ask brokers for decisions or credentials. It does not decide organizational policy itself — see [control plane vs. data plane](concepts/control-plane.md) for what that split means and who owns which side of it.

!!! tip "Interception is optional"
    Start with a policy proxy using `mitm:false`. TLS remains end-to-end and no CA installation is required. You still get client identity, connection-phase rules, egress controls, access logs, and metrics. See [Policy proxy without MITM](usecases/no-mitm.md).

## Who it's for

- **Platform and infrastructure engineers** who need one forward proxy that every container, VM, or CI/agent sandbox in a fleet can share, with declarative per-client and fleet-wide rules instead of per-host configuration.
- **Security and SRE teams** who need an egress firewall / SSRF guard, an audited record of outbound tunnels, or a way to constrain what an untrusted or AI-agent workload can reach — without owning policy decisions themselves; that stays with whatever writes to `Storage`.
- **Anyone running a horizontally-scaled fleet** who wants nodes to be interchangeable: point a new node at the same `Storage` and `clusterKey`, and it serves the same policy as every other node, with no coordination step.

## Features

- **Policy proxy without MITM.** `mitm:false` splices the tunnel: TLS stays end-to-end, no CA install needed, and you still get client identity, connection-phase rules, egress control, access logs, and metrics.
- **On-demand TLS interception.** When a rule intercepts, mitmania *clones* the real certificate chain (subject, full SAN set, validity, key usage copied verbatim) and re-signs it under its own CA, so certificate validity and behavior match the origin.
- **Egress firewall / SSRF guard**, evaluated independently of host-based rules, with resolved addresses pinned after a single DNS resolution to prevent rebinding.
- **Sparse-mask and CIDR rule addressing**, so a single fleet-wide default table can key policy on a prefix or on a non-contiguous field carved out of an address block — see [the default rule table](config/default-ruleset.md).
- **Mutation**: block, rewrite, redact, and inject headers or credentials, bounded and streaming rather than buffering whole bodies.
- **Bring your own CA** — load an existing sub-CA (chain validated fully at load) instead of mitmania's generated one.
- **Client authentication** (`auth.http_proxy`) that attributes a connection without ever selecting which rule file governs it.
- **Outcalls**: defer a per-request decision or credential lookup to an external broker, bounded and fail-closed.
- **Observability**: OpenTelemetry metrics and traces plus structured access logs, stealth by default.

## Use cases

| Goal | MITM? | CA install? |
| --- | --- | --- |
| [Policy proxy](usecases/no-mitm.md) | No | No |
| [Egress firewall / SSRF guard](usecases/egress.md) | No | No |
| [Authenticated proxy](usecases/auth-proxy.md) | Optional | Only with MITM |
| [AI agents: inject credentials without exposing them](usecases/injection.md) | Yes | Yes |
| [Block, rewrite, redact](usecases/mutation.md) | Usually | Yes for HTTPS |
| [Contain an agent or sandbox](usecases/containment.md) | Optional | Only with MITM |
| [Transparent interception (TPROXY/REDIRECT)](usecases/transparent.md) | Optional | Only with MITM |
| [Central policy via broker](usecases/broker.md) | Yes | Yes for HTTPS |
| [Debug and inspect TLS](usecases/debugging.md) | Yes | Yes |

See [Choose a use case](usecases/index.md) for the full comparison, including listener and configuration details, or [the threat model](security/threat-model.md) to evaluate containment and trust before deploying.

## Install

Requires Go 1.26+ to build from source; prebuilt Debian/Ubuntu packages are published for `amd64`, `arm64`, and `armhf`.

=== "Build from source"

    ```sh
    make build
    ./bin/mitmania --help
    ```

=== "Debian or Ubuntu package"

    ```sh
    sudo apt install ./mitmania_1.2.3-1_amd64.deb
    sudoedit /etc/default/mitmania
    sudo systemctl enable --now mitmania
    ```

See [Install](start/install.md) for the full walkthrough and [First run](start/first-run.md) to bring up a single node.

## When not to use it

Do not use mitmania as the only containment boundary: a firewall must prevent clients from reaching the network directly. It is not a general-purpose reverse proxy, a packet firewall, or a shipped implementation of the design's future SSH, IMAP, HTTP/3, Redis, or PostgreSQL handlers.
