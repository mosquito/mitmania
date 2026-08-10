# Debugging and inspecting TLS

**Who and why:** operators inspect decrypted HTTP behavior, ALPN negotiation, origin certificate failures, and per-request traces.

**MITM required?** Yes.

Trust the signing CA in a disposable client, enable trace export, and send controlled requests to `httpbingo.org`, `tls.peet.ws`, and relevant `badssl.com` endpoints. mitmania negotiates HTTP/1.1 or HTTP/2 independently on each leg while preserving the origin's certificate-error behavior by default.

This preservation is intentional, not cosmetic. A simple MITM proxy can replace a broken origin leaf with a fresh hostname certificate and make proxied health checks pass while direct clients fail. mitmania keeps the origin's SANs, validity, usage, and applicable intermediate constraints so the client still detects those rollout failures. See [why mitmania mimics the origin chain](../concepts/certificates.md#why-mimic-the-origin-chain) for the exact guarantees and limits.

Do not install a debugging CA broadly. See [Interception and certificates](../concepts/certificates.md) and [Telemetry and logging](../config/observability.md).
