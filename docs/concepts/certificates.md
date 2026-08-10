# Interception and certificates

For an intercepted TLS connection, mitmania connects to the real origin first, observes its certificate chain and negotiated ALPN, then creates a leaf that preserves the origin's identity and error behavior while being signed by the cluster signing CA.

## Why mimic the origin chain?

A conventional MITM proxy often creates a fresh, currently valid certificate containing only the requested hostname and signs it directly with its local CA. That is enough to decrypt traffic, but it silently changes the result of certificate validation. Once the client trusts the proxy CA, an expired origin certificate, a hostname mismatch, a restricted EKU, or a broken intermediate constraint can appear healthy to the client.

That is a dangerous operational failure mode: the proxy becomes a certificate-error masking layer. An origin renewal can break, direct users can fail, and clients behind the proxy can remain green. SREs then see different behavior depending on the network path and may investigate the application, DNS, or load balancer before discovering that interception hid the real TLS regression.

mitmania instead reproduces the observed leaf and intermediate structure under its own signing CA. For each cloned element it preserves the Subject, the complete SAN extension including ordering and SAN types, `NotBefore`/`NotAfter`, key usage and extended key usage, and basic/path constraints. The client still owns the final validation decision against the mitmania CA it trusts.

| Origin condition | Hostname-only MITM leaf | mitmania clone |
| --- | --- | --- |
| expired or not-yet-valid leaf | may look newly valid | preserves the validity failure |
| requested name absent from SAN | may add the requested name and succeed | preserves the SAN mismatch |
| expired/restricted intermediate | often flattened away | preserves the intermediate and its constraints when the signing CA permits |
| origin renewal or chain rotation | may be invisible behind a generic leaf | produces a new content-addressed clone automatically |
| clients with different validation policy | proxy has already normalized the certificate | each client evaluates the preserved fields itself |

The operational win is **path consistency**: interception grants visibility and mutation, but does not intentionally “repair” the origin's certificate identity or lifetime. A certificate rollout that would fail directly should fail recognizably through mitmania for the properties it preserves. This makes synthetic monitoring meaningful, prevents false-green health checks, and shortens incident triage.

It also improves distributed behavior. The cache key includes the complete observed chain DER, so a renewal or intermediate change is a cache miss without waiting for a TTL. Nodes sharing Storage and `clusterKey` mint the same synthetic identity and deterministic leaf key, which prevents load-balanced clients from seeing node-dependent certificate churn.

!!! note "Fidelity, not byte-for-byte copying"
    The synthetic chain has new public keys, signatures, issuer links, and derived serials. Embedded SCTs and AIA/OCSP/CRL distribution metadata are deliberately not copied because they refer to the origin CA and would be invalid for the synthetic chain. A constrained BYO signing CA may require chain flattening. Certificate pinning still detects interception, and cloning cannot preserve every possible origin validation failure, such as a bad original signature or a missing issuer that is replaced by the mitmania trust path.

Leaf private keys are deterministic: each node derives the same key from `clusterKey` and the type-tagged SAN set. They are never persisted. The cached material is enough to reproduce the same leaf identity, while the encrypted `ca.p12` in Storage makes every node present the same signing CA.

The default behavior preserves the validation-relevant fields above so clients still reject applicable `badssl.com` cases, including expiry and hostname failures. A fallback leaf is used only when mitmania must finish a client TLS handshake to deliver its own error page and no upstream leaf is available.

!!! danger "Security"
    Installing the signing CA grants interception power over that trust store. Protect `clusterKey` out of band, scope which clients trust the CA, and treat BYO-CA use as an increase in blast radius.

See [CA operations](../ops/ca.md), [bring your own CA](../tutorials/byo-ca.md), and [secrets at rest](../security/secrets.md).
