# Threat model: containment

The attacker controls a proxied workload and can choose destinations, DNS names, ports, TLS payloads, request concurrency, and any credentials already present inside that workload. An **escape** is useful outbound communication outside the authority granted by the effective rule file and external network boundary.

mitmania constrains traffic that reaches it. It prevents authority and resolved-address mismatches, DNS rebinding, self-listener forwarding, unauthenticated explicit-proxy use, and outcall amplification within configured limits. MITM enables finer message claims; a splice deliberately does not.

It cannot stop direct egress, alternate protocols, another network interface, or a compromised host from routing around it. Those are [deployment invariants](invariants.md), not proxy features.

