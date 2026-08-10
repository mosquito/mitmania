# Hardening checklist

- [ ] Block direct workload egress at the firewall.
- [ ] Keep the control API on a mode-restricted Unix socket.
- [ ] Keep the seeded deny-first egress ranges or tighten them.
- [ ] End `egress[]` deliberately; fall-through denies.
- [ ] Put narrow connection and message rules before broad ones.
- [ ] Treat `mitm:false` as full encrypted tunnel authority.
- [ ] Require proxy auth where network source identity is insufficient.
- [ ] Restrict `--trusted-proxies` and sanitize forwarded identity headers.
- [ ] Scope broker sockets, destinations, fields, concurrency, and cache policy.
- [ ] Leave `failOpen` false unless availability explicitly outweighs containment.
- [ ] Never permit brokers to inject framing, hop-by-hop, or proxy-auth headers.
- [ ] Keep `clusterKey` separate from Storage and backups.
- [ ] Alert on forwarding denials, auth failures, broker failures, and rule compile errors.

