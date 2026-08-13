# Transparent interception with REDIRECT or TPROXY

**Who and why:** operators need to govern containers, VMs, appliances, or agents that cannot be configured with an explicit HTTP proxy—or that must not be able to opt out by clearing proxy environment variables.

**MITM required?** No for connection and resolved-address policy; yes when HTTPS method, path, headers, bodies, injection, or broker decisions must be visible. A `mitm:false` rule remains an end-to-end TLS splice.

## Domain-based matching without a CONNECT authority

A transparent connection carries no CONNECT/absolute-form authority to read `host` from — only the destination IP:port the Acceptor recovered. To still match rules on domain, mitmania peeks the traffic itself before any rule runs: the TLS ClientHello's SNI, *before* connection-phase matching rather than after (the reverse of the explicit CONNECT path, which already knows its host and only peeks afterward to catch an SNI/authority mismatch).

A client that sends no SNI at all (permitted by TLS, though rare in practice), or whose traffic isn't a recognizable TLS ClientHello at all, has no domain to match on — the destination's literal IP is used as `host` instead. That decision is never guessed from content: whether a non-TLS connection even *might* be HTTP is not inspected before matching, since doing so would make the single most security-relevant decision in the pipeline (`mitm` true or false) depend on an unreliable heuristic, and some real traffic is deliberately built to defeat exactly that kind of classification (see below).

## Non-TLS transparent traffic (opaque TCP passthrough)

A transparent listener sees whatever an operator's REDIRECT/TPROXY capture rule sends it — not just HTTP(S). Some clients speak protocols that are not TLS and not HTTP, and some (Telegram's MTProto "obfuscated" transport is the canonical example) are deliberately built to look like neither, specifically to defeat protocol classification by anything sitting on the path. Such a client also typically never closes its connection to "help" a guessing game along — it sends its initial bytes and then waits for a response, so waiting for the connection to close before deciding "this isn't HTTP" would mean it's never spliced at all (see `--http-timeout-client-read` below).

For any connection that isn't a recognized TLS ClientHello, mitmania matches on the literal destination IP with `Proto: "tcp"` — a sentinel an operator must name explicitly, so this never fires for ordinary traffic by accident:

```json
{"http": [
  {"match": {"host": "91.108.4.0/22", "proto": "tcp"}, "mitm": false}
]}
```

What a matched rule can do depends on `mitm`:

- **`mitm:false`** — splice the connection raw, byte-for-byte, exactly as accepted. This is the only thing a plain "allow this destination" rule can mean for unidentified traffic — mitmania cannot decrypt or parse content it never identified.
- **`mitm:true`** (or `mitm` omitted, which defaults to it) — the operator has explicitly asked for interception at this destination, so it's no longer a guess to go try parsing the connection as HTTP (the only protocol mitmania knows how to intercept): if it parses, the request's own `Host` header takes over for message-phase policy, exactly like an explicit absolute-form request. If it genuinely isn't HTTP either, the connection fails closed rather than silently falling back to a splice the operator didn't ask for.

Plain, unencrypted HTTP transparent traffic goes through this same opaque path — it isn't TLS either — so reaching its `Host`-header-based message-phase policy needs an IP-scoped `proto:"tcp"` rule granting `mitm:true` for that destination, same as any other non-TLS traffic.

## Choose a transport

| Mode | Prefer it when | Destination recovery | Extra routing |
| --- | --- | --- | --- |
| REDIRECT | traffic crosses a Linux gateway and simple NAT steering is enough | `SO_ORIGINAL_DST` | no policy-routing table |
| TPROXY | the listener must retain transparent socket semantics without destination NAT | transparent local address | packet mark + `ip rule` + local route |

=== "REDIRECT"

    ```sh
    sudo nft add table ip mitmania
    sudo nft 'add chain ip mitmania prerouting { type nat hook prerouting priority dstnat; policy accept; }'
    sudo nft add rule ip mitmania prerouting \
      iifname "docker0" tcp dport 443 redirect to :3130

    mitmania \
      --listen-http-redirect 'tcp://*:3130' \
      --storage '<storage>' \
      --cluster-key "$CLUSTER_KEY"
    ```

=== "TPROXY"

    ```sh
    sudo nft add table ip mitmania
    sudo nft 'add chain ip mitmania prerouting { type filter hook prerouting priority mangle; policy accept; }'
    sudo nft add rule ip mitmania prerouting \
      iifname "docker0" tcp dport 443 \
      tproxy to :3129 meta mark set 0x1

    sudo ip rule add fwmark 0x1 lookup 100
    sudo ip route add local 0.0.0.0/0 dev lo table 100

    mitmania \
      --listen-http-tproxy 'tcp://*:3129' \
      --storage '<storage>' \
      --cluster-key "$CLUSTER_KEY"
    ```

Scope the nftables rule to the workload ingress interface, source subnet, or cgroup. Do not capture mitmania's own upstream traffic and create a forwarding loop. IPv6 needs an equivalent `ip6` nftables table plus `ip -6 rule` and `ip -6 route add local ::/0 ...` policy routing for TPROXY.

**What you get:** policy coverage without client proxy configuration, original source identity at the transparent listener, and the same effective rule file, egress policy, logging, and optional interception pipeline.

**Limits:** transparent clients have no `Proxy-Authorization` exchange, and `auth.http_proxy.required:true` therefore fails closed. The deployment must still block direct alternate egress paths and exclude the proxy's own traffic from capture.

Next: review the full [nftables tutorial](../tutorials/transparent-nft.md) and the required [deployment invariants](../security/invariants.md).
