# Authenticating forward proxy

**Who and why:** operators gate an explicit proxy with Basic, Bearer, or broker-delegated credentials and attach an authenticated principal to telemetry.

**MITM required?** No. `auth.http_proxy` runs before the connection-phase rule and can protect `mitm:false` tunnels.

Configure the auth mechanism on the effective rule file, store only Argon2id or SHA-256 hashes, and require credentials. A missing or invalid `Proxy-Authorization` receives `407`; a successful credential is stripped before forwarding.

Authentication is a gate, not rule selection: it never changes the effective rule file or its proxied client `uuid`. See [Client authentication](../config/auth.md).

