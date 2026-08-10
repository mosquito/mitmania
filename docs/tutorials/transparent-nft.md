# Transparent interception with nftables

!!! warning "Design-space, not shipped"
    The current binary exposes `--listen-http-redirect` and `--listen-http-tproxy` for compatibility with the v1 design, but startup reports these transports as not implemented. Do not deploy the nftables rules below yet.

Choose REDIRECT for simple destination-NAT steering, or TPROXY when the listener must retain transparent socket semantics. Both examples scope capture to traffic arriving from `docker0`, which keeps locally originated mitmania upstream connections out of the rule.

=== "REDIRECT"

    REDIRECT preserves the source address and lets mitmania recover the pre-NAT destination with `SO_ORIGINAL_DST`.

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

    TPROXY marks the packet and uses policy routing to deliver it locally without destination NAT.

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

    Confirm the routing state with:

    ```sh
    ip rule show
    ip route show table 100
    sudo nft list table ip mitmania
    ```

For IPv6 TPROXY, mirror the nftables rule in an `ip6` table and add `ip -6 rule add fwmark 0x1 lookup 100` plus `ip -6 route add local ::/0 dev lo table 100`.

!!! danger "Security"
    Scope capture to the workload boundary and block direct egress there. A broad host-wide rule can recapture the proxy's own upstream connections, create loops, or intercept management traffic.

Once the listener ships, this tutorial will cover loop prevention, CA installation in the intercepted container, an effective MITM rule, and a decrypted access-log check. Until then, use the [explicit proxy setup](../start/point-client.md).
