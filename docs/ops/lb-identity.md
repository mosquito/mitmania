# Load balancing and client identity

An L4 load balancer that SNATs traffic collapses many clients into one apparent source IP, and therefore one effective rule file. Avoid this with a source-preserving DSR/transparent design where possible.

For explicit listeners only, `--trusted-proxies` allows forwarding headers from named CIDRs to recover the original client address. Headers from every other peer are ignored. Proxy auth supplies an attributable principal but does not select rules.

!!! danger "Security"
    Trust only load-balancer addresses you operate, overwrite inbound forwarding headers at that boundary, and prevent clients from connecting through another path that can spoof a trusted peer.

