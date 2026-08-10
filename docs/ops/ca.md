# CA and certificate management

The first node atomically creates encrypted `ca.p12` when Storage has none. Later nodes decrypt the same object with the shared `clusterKey`. Distribute `/ca.pem` only to clients that need interception and verify its SHA-256 fingerprint out of band.

## Why this is more than ordinary MITM

mitmania does not mint one generic “valid now” leaf for every hostname. It clones the origin's served leaf and intermediate structure, including SANs, validity windows, EKUs, key usage, and CA constraints, then re-signs that structure into the client-trusted mitmania chain.

For SREs, this prevents interception from turning a broken certificate rollout into a false-green result. Expiry, hostname, and applicable intermediate-constraint failures remain visible to client validation; chain renewals automatically produce a new cache identity; and all nodes mint consistently from shared state. Direct and proxied synthetic checks therefore measure much closer to the same origin condition.

Monitor certificate failures rather than treating them as proxy noise. If direct traffic fails while proxied traffic succeeds, compare the failure with the documented [fidelity limits](../concepts/certificates.md#why-mimic-the-origin-chain), especially certificate pinning, omitted revocation metadata, missing issuers, and BYO-CA chain flattening.

For rotation, replace the signing CA through a controlled maintenance procedure, distribute trust before serving new leaves, and clear cached public leaf material with `DELETE /cache` so it is re-minted. Leaf private keys require no rotation job because they are never stored.

!!! danger "Security"
    Back up encrypted Storage and escrow `clusterKey` separately. A backup without the key does not reveal the signing key; losing either component prevents recovery.
