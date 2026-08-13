# mitmania

[![Coverage Status](https://coveralls.io/repos/github/mosquito/mitmania/badge.svg?branch=master)](https://coveralls.io/github/mosquito/mitmania?branch=master)

[GitHub](https://github.com/mosquito/mitmania) · [Documentation](https://docs.mitmania.com/) · [Releases](https://github.com/mosquito/mitmania/releases)

**A stateless data plane for egress: an intercepting HTTP/HTTPS forward proxy that scales horizontally with near-zero per-node state.**

mitmania controls outbound HTTP and HTTPS from containers, VMs, and sandboxes. It authenticates clients, constrains where they may connect, audits tunnels, and — optionally — terminates TLS to inspect, mutate, or redact traffic and to ask external brokers for decisions or credentials. Every node is interchangeable; all shared state lives in one pluggable `Storage` backend.

> mitmania is **not** a containment boundary on its own — a firewall must still prevent clients from reaching the network directly. It is also not a general-purpose reverse proxy or a packet firewall.

## Who it's for

- **Platform and infrastructure engineers** who need one forward proxy that every container, VM, or CI/agent sandbox in a fleet can share, with declarative per-client and fleet-wide rules instead of per-host configuration.
- **Security and SRE teams** who need an egress firewall / SSRF guard, an audited record of outbound tunnels, or a way to constrain what an untrusted or AI-agent workload can reach — without owning policy decisions themselves.
- **Anyone running a horizontally-scaled fleet** who wants nodes to be interchangeable: point a new node at the same `Storage` and `clusterKey` and it serves the same policy as every other node.

## The core property

Each node needs only three inputs: the shared `Storage` URL, the out-of-band `clusterKey`, and its listener addresses. Everything else — the signing CA, the leaf-certificate cache, and every client's rules — lives behind `Storage` (POSIX for one box, S3 for a real cluster).

- **Keys are derived, never shared.** Synthetic leaf private keys are derived with HKDF over `clusterKey` + the leaf's SAN set, so the same identity yields the same key on every node and no key material ever crosses the wire.
- **The CA is a byte-identical encrypted blob** copied to every node and decrypted with `clusterKey`.
- **Convergence without coordination.** Rules and the leaf cache propagate through `Storage`'s own change-versioning — no node-to-node RPC, no gossip, no lock, no leader, no generation counter. Eventually consistent by design.

Front a fleet with an L4 load balancer and add nodes at will; there is nothing to rebalance.

## Data plane, not policy owner

Which rule file governs a connection is a **pure function of network facts** — the client address, and nothing else. Client authentication is a gate that *attributes* a connection, never a mechanism that *selects* rules. That determinism is what makes mitmania a data plane: any node computes the same verdict from the same network facts, and any control plane can drive the fleet just by writing declarative state into `Storage` (or via the control socket). The proxy carries and enforces; deciding organizational intent is someone else's job.

The one deliberate escape hatch is **outcalls**: a rule can defer a per-request decision (`webhook`) or credential lookup (`header.fetch`) to an external broker — bounded (no retries, fail-closed by default, validated at load) precisely because it is the one place the pipeline stops being pure.

## What it does

- **Policy proxy without MITM.** Start with `mitm:false`: TLS stays end-to-end, no CA install required, and you still get client identity, connection-phase rules, an egress/SSRF guard, access logs, and metrics.
- **Interception on demand.** When a rule intercepts, mitmania *clones* the real certificate chain (subject, full SAN set, validity, key usage copied verbatim; SCT/OCSP/CRL stripped) and re-signs it under its own CA — validity is honored exactly, so expiry surfaces to the client as it really is.
- **Egress firewall / SSRF guard**, independent of host-based rules; a non-overridable guard denies traffic looping back to mitmania's own listeners.
- **Mutation**: block, rewrite, redact, and inject headers or credentials.
- **Bring your own CA** — typically a sub-CA under your org root, validated fully at load.
- **Observability**: OpenTelemetry metrics and traces, plus structured access logs, stealth by default (no `traceparent` injected upstream unless opted in).

## Use cases

| Goal | MITM? | CA install? |
| --- | --- | --- |
| Policy proxy (no interception) | No | No |
| Egress firewall / SSRF guard | No | No |
| Authenticated proxy | Optional | Only with MITM |
| AI agents: inject credentials without exposing them | Yes | Yes |
| Block, rewrite, redact | Usually | Yes for HTTPS |
| Contain an agent or sandbox | Optional | Only with MITM |
| Transparent interception (TPROXY/REDIRECT) | Optional | Only with MITM |
| Central policy via broker | Yes | Yes for HTTPS |

See [Choose a use case](https://docs.mitmania.com/usecases/) for the full comparison.

## Install

Requires Go 1.26+ to build from source; prebuilt Debian/Ubuntu packages are published for `amd64`, `arm64`, and `armhf`.

Build from source:

```sh
go build -o bin/mitmania ./cmd/mitmania

export CLUSTER_KEY="$(openssl rand -base64 32)"
install -d -m 700 ./state

./bin/mitmania \
  --storage "posix://$PWD/state" \
  --control "unix://$PWD/mitmania.sock" \
  --listen-http-proxy "tcp://127.0.0.1:3128" \
  --cluster-key "$CLUSTER_KEY"
```

Or install a released Debian/Ubuntu package:

```sh
sudo apt install ./mitmania_1.2.3-1_amd64.deb
sudoedit /etc/default/mitmania
sudo systemctl enable --now mitmania
```

On first start mitmania writes an encrypted `ca.p12` and a safe, deny-first default policy — with no HTTP allow rules yet, so traffic fails closed until you install an effective rule file. Continue with [Get started](https://docs.mitmania.com/start/install/) for the full walkthrough, including how to point a client and trust the CA for interception.

## Status

**v1**: HTTP/1.1 + HTTPS MITM (+ WebSocket) and HTTP/2, explicit and transparent (REDIRECT/TPROXY, Linux-only) proxy modes, cert cloning with deterministic keys, pluggable `Storage` (`posix://`/`s3://`), rule engine + egress policy, control socket, OpenTelemetry. SSH, IMAP, HTTP/3, and additional storage backends are design-space notes, not shipped.

## Documentation

Full docs — installation, CLI and rule-file reference, deployment topologies, CA management, monitoring, runbooks, and security — live at **[docs.mitmania.com](https://docs.mitmania.com/)** (source under [`docs/`](docs/)). Architecture rationale for contributors is in [`DESIGN.md`](DESIGN.md).

## License

[Hippocratic License](LICENSE). Copyright 2026 Dmitry Orlov.
