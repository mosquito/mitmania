# Secrets at rest

The signing CA does live in Storage—including S3—but only as `ca.p12`, strongly encrypted with `clusterKey`. A bucket or backup compromise alone does not expose the signing key; the attacker also needs `clusterKey`, which is delivered out of band and never written to Storage.

Leaf private keys are not stored. Nodes derive them for each call from `clusterKey` and the type-tagged SAN set, so there is no leaf-key cache to steal.

Rule-embedded broker tokens, injected authorization values, and proxy-auth hashes are stored with mode `0600` on POSIX and masked or omitted from `/stats` and logs. Embedded S3 credentials in `--storage` are rendered as `<REDACTED>` in startup logs.

!!! danger "Security"
    Protect `clusterKey` in a secret manager, restrict which workloads can read the service environment, and separate its backups from Storage backups. This is the one cluster-wide secret whose disclosure converts durable encrypted or derivable material into signing capability.

