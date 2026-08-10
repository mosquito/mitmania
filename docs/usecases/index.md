# Choose a use case

| Goal | MITM? | Listeners | Key configuration | CA install? |
| --- | --- | --- | --- | --- |
| [Policy proxy](no-mitm.md) | No | explicit | `mitm:false`, `http[]` | No |
| [Egress firewall / SSRF guard](egress.md) | No | explicit | `egress[]`, deny first | No |
| [Authenticated proxy](auth-proxy.md) | Optional | explicit | `auth.http_proxy` | Only with MITM |
| [Inject credentials](injection.md) | Yes | explicit or transparent | `header.fetch` | Yes |
| [Block, rewrite, redact](mutation.md) | Usually | explicit or transparent | request/response actions | Yes for HTTPS |
| [Contain an agent](containment.md) | Optional | either | narrow `http[]` + `egress[]` | Only with MITM |
| [Intercept without client proxy settings](transparent.md) | Optional | REDIRECT or TPROXY | nftables + policy routing | Only with MITM |
| [Central broker policy](broker.md) | Yes | either | `webhook` | Yes for HTTPS |
| [Inspect TLS](debugging.md) | Yes | either | MITM + telemetry | Yes |

Start with the [Docker egress allowlist tutorial](../tutorials/egress-docker.md) if you want a result without distributing a CA.
