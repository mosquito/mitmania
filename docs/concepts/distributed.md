# Distributed operation

Nodes do not coordinate with one another. They share a Storage backend and `clusterKey`; changes propagate when a node observes a changed Storage version on a later connection. There are no locks, generations, or gossip.

Shared state includes the encrypted signing CA, cached leaf certificate data, `rules/default`, and per-IP rule overrides. Listener sockets, telemetry exporters, and file-spool rotation stay per-node. Consequently, nodes are replaceable and an L4 load balancer can add or remove them without CA reprovisioning.

This is eventual consistency, not atomic fleet-wide activation. Plan revocation and rolling upgrades around the consistency contract described in [Upgrades and consistency](../ops/upgrades.md).

