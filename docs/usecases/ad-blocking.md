# Block ads and trackers without MITM

Use `connection: {accept: false}` to reject a connection by hostname, before
any dial or TLS handshake — the client never receives a certificate, so it
never needs to trust mitmania's signing CA. This is the shape a hostname
blocklist wants: many entries, each meaning "refuse this host outright," not
"intercept it to inspect and then block."

## Why not `mitm:true` + block?

A request-phase `block` action also stops the request, but only after
mitmania terminates TLS to reach the message phase — the client sees
mitmania's leaf certificate and rejects it unless the signing CA is
installed. For a large blocklist, every blocked domain then shows a
certificate error on any client that hasn't installed the CA — often none of
them, on a transparently-intercepted network.

`connection: {accept: false}` skips interception entirely for a match: no
dial, no TLS termination, no certificate exchange. The connection is refused
at the same point a `no-match` would be, just for a reason you named
explicitly.

--8<-- "tested/rules/ad-blocking.json"

Apply it with `PUT /rules/{client-ip}` (or embed the same `http[]` shape in a
`rules/default` bucket for a fleet-wide blocklist — see
[The default rule table](../config/default-ruleset.md)). `ads.example` and
`tracker.example` (and its subdomains) are refused outright; everything else
falls through to the trailing `mitm:false` splice.

## Matching by hostname at scale

A real blocklist is many exact hostnames, not a hand-written glob. Group them
into one `re:` suffix pattern instead of one rule per host —
`internal/rules` recognizes this specific canonical shape and indexes it, so
matching stays fast even with hundreds of thousands of entries:

    {"match": {"host": "re:(?i)(?:^|\\.)(?:ads\\.example|tracker\\.example)$"},
     "connection": {"accept": false}}

## What still works

- top-down connection-phase matching on `host`, `port`, and `proto` — the
  same first-match ordering as every other rule, so a narrower
  `accept:true` exception ahead of a broad `accept:false` block still wins;
- transparent interception (REDIRECT/TPROXY): the match runs against the TLS
  ClientHello's SNI, so this works with zero client configuration and no CA
  install anywhere on the network — see
  [Intercept without client proxy settings](transparent.md) for the
  listener setup;
- explicit-proxy CONNECT and absolute-form requests, matched on the
  authority instead of SNI;
- one access-log record per refused connection (`outcome: "denied"`), plus
  metrics (`mitmania.requests.total{verdict="deny",mitm="false"}`).

## What you give up

`connection: {accept: false}` cannot see method, path, headers, or body — it
runs before any of that is visible, the same as `mitm:false`. It cannot
carry message-phase match fields, a `mitm` value, or request/response
actions; a rule that needs those (e.g. a custom block page instead of a
silent refusal) needs `mitm:true` and a request-phase `raise` action
instead, which does require the client to trust the signing CA.

!!! warning
    A large blocklist compiled from third-party sources is still policy you
    are choosing to enforce. Review sources before trusting them, and keep
    `egress[]` deny-first regardless — `connection: {accept: false}` governs
    which hosts get *matched*, not what an allowed connection is permitted
    to reach.

Next: [choose REDIRECT or TPROXY](transparent.md), or see
[the rule-file schema](../reference/rule-schema.md) for the full
`connection`/`mitm` field reference.
