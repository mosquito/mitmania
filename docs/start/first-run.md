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

The seeded default has two catch-all buckets with **no HTTP allow rules**, so
every request fails closed with `511` until you install policy — but it does
ship a deny-first egress floor (loopback, private, link-local, and cloud
metadata denied) so it is never SSRF-open.

You can now make the node useful in one of two ways:

- **One client:** install a per-IP override, the quickest path to a working
  request — continue to [point a client](point-client.md), then
  [verify it works](verify.md).
- **The whole fleet:** customize the shared default table so every
  un-overridden client inherits your policy — see
  [The default rule table](../config/default-ruleset.md).

Install [the CA](trust-ca.md) only when a rule uses interception; a
`mitm:false` path needs no CA.

