# First run: one node

This first run starts an explicit HTTP(S) forward proxy and a Unix-socket control API. It generates the signing CA and safe default egress policy in local POSIX storage.

```sh
export CLUSTER_KEY="$(openssl rand -base64 32)"
install -d -m 700 ./state

./bin/mitmania \
  --storage "posix://$PWD/state" \
  --control "unix://$PWD/mitmania.sock" \
  --listen-http-proxy "tcp://127.0.0.1:3128" \
  --cluster-key "$CLUSTER_KEY"
```

Keep that terminal open. On first start, mitmania writes an encrypted `ca.p12`, a complete `rules/default` table, and no leaf private keys.

!!! danger "Security"
    `CLUSTER_KEY` is the cluster's root secret. Keep it outside Storage and deliver it to every node through your secret manager. Losing it makes the persisted signing CA unusable; exposing it together with Storage exposes the signing CA.

The seeded default has no HTTP allow rules, so requests fail closed until you install an effective rule file. Continue to [point a client](point-client.md) for a non-MITM path, or [trust the CA](trust-ca.md) before interception.

