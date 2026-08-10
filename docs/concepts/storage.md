# State and storage

`Storage` is the durability boundary used by the rule engine, certificate cache, and signing CA. v1 provides POSIX and S3 implementations with the same keyspace:

| Key | Content |
| --- | --- |
| `ca.p12` | signing CA, strongly encrypted under `clusterKey` |
| `certs/...` | cached public certificate/chain material; no leaf private keys |
| `rules/default` | complete source-address fallback table |
| `rules/ip/...` | per-source-address rule overrides |

Use POSIX for one node and S3 for a fleet. Telemetry spools are deliberately outside Storage and rotate independently on each node.

See [Storage backends](../ops/storage.md) and [Secrets at rest](../security/secrets.md).

