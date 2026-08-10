# Agent and sandbox containment

**Who and why:** security engineers constrain an untrusted workload's outbound network capability and make each allowed route explainable.

**MITM required?** Optional. Use splices for authority-level access; intercept only when method, path, header, body, or broker policy is necessary.

Combine a firewall that blocks direct egress, a narrowly ordered `http[]`, deny-first `egress[]`, the non-overridable self-listener guard, client authentication where identity crosses NAT, and tightly scoped outcalls.

An allowed `host:port` means the workload may exchange arbitrary encrypted bytes through a `mitm:false` tunnel. It does not constrain URLs or credentials. Begin with the [Threat model](../security/threat-model.md).

For workloads that can clear or ignore proxy environment variables, combine the external egress firewall with the intended [transparent REDIRECT or TPROXY topology](transparent.md). Transparent steering changes how traffic reaches mitmania; it does not replace the firewall invariant.
