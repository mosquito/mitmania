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

## Generate a real blocklist automatically

Hand-authoring one rule per hostname doesn't scale to a real blocklist.
`tools/adblock_to_mitmania.py` converts uBlock/AdGuard/hosts-style filter
lists into exactly the shape above — one indexed `re:` suffix pattern per
generated rule, `connection:{accept:false}` by default — so this is the
ordinary way a real fleet's blocklist gets built, not a one-off script. It
needs only Python 3's standard library; no `pip install`. See
[the full CLI/preset reference](../config/default-ruleset.md#generate-an-advertising-and-tracker-policy)
for every flag.

### 1. Generate first, push later

Write the generated rules to a file and inspect them before anything goes
live. With no arguments the converter uses HaGeZi Multi Light (ads/trackers)
plus HaGeZi TIF Mini (malware/phishing/scam/C2), pulled straight from each
provider's maintained URL:

```sh
python3 tools/adblock_to_mitmania.py \
  --output generated-rules.json \
  --domains-output generated-domains.txt
```

`generated-domains.txt` is the flat, sorted, deduplicated hostname list —
the fastest way to spot-check what's actually being blocked before trusting
it. Progress lines report how many rules each provider contributed and the
final effective-domain/generated-rule counts.

### 2. Apply it fleet-wide

Once you're satisfied, regenerate straight against the live control socket
instead of a file. This fetches the current `rules/default`, prepends the
generated block rules to every bucket's `http[]` (keeping each bucket's
`uuid`, `auth`, `egress`, and any rules you've already written), and `PUT`s
the complete replacement in one step:

```sh
python3 tools/adblock_to_mitmania.py \
  --control "unix://$PWD/mitmania.sock"
```

The submitted table still goes through the same parser, compiler, coverage
check, and control API size limit as a hand-written `PUT` — a malformed
generation fails closed; it never applies partially.

### 3. Verify

```sh
curl -v https://<a-domain-from-generated-domains.txt>
```

Expect a clean `SSL_ERROR_SYSCALL`/connection reset — no certificate,
because `connection:{accept:false}` never attempts TLS. Confirm the access
log agrees:

```
"outcome":"denied","verdict":"deny","mitm":"false"
```

An unrelated site should be unaffected — the trailing `mitm:false` splice
still allows anything the generated rules didn't match.

### 4. Keep it fresh

Filter lists are maintained upstream and change; re-run the same command
periodically (a systemd timer or cron job) to pick up new entries.
Re-running is safe to repeat: the converter marks its own output with an
internal boundary, so a fresh run replaces the *previous* generation instead
of prepending onto it indefinitely — hand-written rules placed after that
boundary are never touched or duplicated.

!!! warning "No exception mechanism yet"
    Generated rules are always prepended ahead of your existing `http[]`
    rules, so first-match-wins picks a generated block before an exception
    written *after* it ever runs. To allow a hostname a preset would
    otherwise block, remove it from the source list you feed the converter
    (a local, edited copy of the filter file, or a narrower `--preset`
    selection) rather than relying on rule ordering.

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
