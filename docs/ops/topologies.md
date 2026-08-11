# Deployment topologies

| Topology | Use it for | State |
| --- | --- | --- |
| One explicit node | evaluation, small trusted network | POSIX |
| N explicit nodes behind L4 LB | production fleet | S3 + shared `clusterKey` |
| Sidecar or host proxy | workload-local egress control | POSIX or shared S3 |
| Transparent REDIRECT/TPROXY | clients that cannot set a proxy | POSIX or shared S3; Linux-only, needs kernel-side nftables/policy routing (see [transparent interception](../usecases/transparent.md)) |

Prefer source-preserving balancing. Every node is otherwise interchangeable: state is shared, leaf keys are derived, and rule changes converge without node-to-node traffic.

