# Deployment invariants

The proxy's security claims require controls outside the process:

- a firewall blocks direct egress and permits only the intended proxy path;
- clients cannot reach the control API, Storage, or brokers directly;
- load balancers preserve source identity or overwrite forwarding headers and are the only trusted proxies;
- `clusterKey` is delivered out of band and never stored beside shared state;
- CA trust is installed only where interception is intended;
- DNS and routing cannot create an unobserved alternate path.

Test these invariants from inside the contained workload, not just from the proxy host.

