# FAQ and troubleshooting

## Why do I get 511?

No connection-phase rule matched the authority. Install a per-IP override for the source address shown in the access log, or update the complete `rules/default` table.

## Why do I get 403 before CONNECT succeeds?

The authority matched, but resolved-address egress policy denied at least one DNS answer, fell through without an allow, or hit mitmania's self-listener guard.

## Why does my per-client rule not apply behind a load balancer?

The load balancer probably SNATs clients. Preserve the source address or configure only its CIDR in `--trusted-proxies` and have it overwrite forwarding headers. Proxy auth alone does not select another rule file.

## Why does HTTPS fail with an unknown CA?

The selected rule is intercepting (`mitm` defaults to true). Either install and verify `/ca.pem`, or use a connection-only `mitm:false` rule when no L7 policy is required.

## Why does a private destination return 403 despite an allow rule?

Host rules and `egress[]` are independent and both must pass. The built-in default denies private, loopback, and link-local destinations. Add a narrow egress exception before the broader deny only when intended.

## Why did my rule PUT fail although the JSON is valid?

PUT also compiles patterns and actions, validates auth/egress, checks complete default-table coverage, and probes outcalls. The response body names the rejected condition. Use `?validate=false` only when a broker intentionally starts later.

## Why won't a transparent listener start?

REDIRECT and TPROXY are not implemented in the current binary. Use the explicit listener until a release marks those transports shipped.

