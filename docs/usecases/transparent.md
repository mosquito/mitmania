# Transparent interception with REDIRECT or TPROXY

**Who and why:** operators need to govern containers, VMs, appliances, or agents that cannot be configured with an explicit HTTP proxy—or that must not be able to opt out by clearing proxy environment variables.

**MITM required?** No for connection and resolved-address policy; yes when HTTPS method, path, headers, bodies, injection, or broker decisions must be visible. A `mitm:false` rule remains an end-to-end TLS splice.

## Domain-based matching without a CONNECT authority

A transparent connection carries no CONNECT/absolute-form authority to read `host` from — only the destination IP:port the Acceptor recovered. To still match rules on domain, mitmania peeks the traffic itself before any rule runs: the TLS ClientHello's SNI for HTTPS, or the request's `Host` header for plaintext HTTP, in both cases *before* connection-phase matching rather than after (the reverse of the explicit CONNECT path, which already knows its host and only peeks afterward to catch an SNI/authority mismatch).

A client that sends no SNI at all (permitted by TLS, though rare in practice) has no domain to match on — the destination's literal IP is used as `host` instead, the same fallback `mitm:false`'s literal-IP dial path already uses elsewhere.

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
