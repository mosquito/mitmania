# The default rule table

`rules/default` is one JSON object, keyed by IPv4 and IPv6 address/mask
entries, that supplies the effective rule file for every proxied client
**without** a per-IP override. It is stored under a single Storage key
(`rules/default`) and managed with `GET` and `PUT /rules/default`.

A per-IP override (`PUT /rules/{ip}`) always wins outright when it exists.
Only when a client has no override does the default table decide its rules —
by picking the single highest-ranked entry whose address/mask matches the
client's source address.

## Two ways to write a key

Each key is an address, a `/`, and then **either** a decimal prefix length
**or** a literal mask in the address family's own notation.

| Form | Example | Matches |
| --- | --- | --- |
| Decimal prefix length | `10.0.0.0/8` | an ordinary CIDR prefix |
| Literal mask (dotted-quad / colon-hex) | `10.0.0.0/255.0.255.0` | the bits the mask sets — need not be contiguous |

Address bits that fall outside the mask are cleared, not rejected, exactly as
a CIDR's host bits are — so `10.1.2.3/8` loads as `10.0.0.0/8` and a table
copied from a firewall or routing table loads as-is.

A **sparse mask** is the literal-mask form whose set bits are *not* a single
run from the most significant bit. It carves out fixed bits that aren't the
leading ones — for example two fixed bytes out of a `/64` handed to a network
segment, where the bits identifying the client sit inside the address rather
than at its front. Use it when the field you want to key on isn't a prefix.

### Keys normalize; last one wins

A contiguous literal mask is stored as its `/N` equivalent, so `10.0.0.0/8`
and `10.0.0.0/255.0.0.0` are the **same entry**, never two competing ones. If
both appear, the one later in the object replaces the earlier. `PUT` persists
this canonical form, so a subsequent `GET /rules/default` echoes what each
entry *became*, not what you typed.

## How an entry is chosen: ranking by mask value

There is one ordered list per address family. Entries are sorted by their
mask's value as a big-endian integer, **descending**, and the first entry that
matches wins. More set bits — whether contiguous or sparse — mean a larger
mask value and a higher rank.

This single rule subsumes longest-prefix-match (a prefix's mask is just a
contiguous run of ones) **but is not identical to it**. A sparse mask can
outrank a longer prefix if its mask value is larger:

| Entry | Mask value | Rank |
| --- | --- | --- |
| `10.0.0.0/255.255.255.0` | `0xFFFFFF00` | highest |
| `10.0.0.0/16` | `0xFFFF0000` | middle |
| `10.0.0.0/8` | `0xFF000000` | lowest |

For `10.0.0.5`, the sparse `255.255.255.0` entry wins even though `/16` and
`/8` also match, because its mask value is the largest. `10.0.1.5` — outside
the sparse entry's third octet — falls through to `/16`.

!!! warning
    Ranking is by mask **value**, not by "how specific it looks." A sparse
    mask and a plain CIDR compete in one order. Confirm the winner for a
    representative address before relying on an override.

## The coverage obligation

`PUT /rules/default` rejects a table unless the **plain-prefix** (contiguous)
entries alone cover the entire IPv4 space and the entire IPv6 space, with no
gaps. This is a save-time correctness check, so a valid table always has an
answer for every client.

Sparse-mask entries are **exempt** in both directions: they do not help close
a gap, and their presence does not excuse one. A sparse mask is an override
layered on top of the topology, not a partition of it — carving a service
field out of a block doesn't change what the block itself must cover.

A gap is reported with the specific range that is missing:

```
invalid default ruleset: rules/default: v4 coverage gap: 128.0.0.0-255.255.255.255 not covered
```

Omitting a family entirely is a gap too: a table with only `0.0.0.0/0` is
rejected for missing v6 coverage.

!!! danger "Fail-closed depends on coverage"
    A missing or invalid `rules/default` blob leaves un-overridden clients with
    no bucket, so every one of their connections fails closed with `511`. The
    startup seed and this coverage check exist to keep that from happening
    silently.

## Relationship to per-IP overrides and to egress

- A per-IP override (`rules/ip/*`) replaces the whole effective rule file for
  its client. The default table is not consulted for that client's `http[]`.
- An override that omits the `egress` key **inherits the egress list of the
  default bucket that covers it** — resolved through the same mask ranking.
  Supplying `"egress": []` instead denies every destination. See
  [Rule files](rules.md) for that nil-vs-empty distinction.
- With a valid table saved, the bucket lookup always succeeds. A `511` then
  means the matched bucket's `http[]` had no connection-phase rule for the
  request — not that no bucket matched.

## The bootstrap seed

On first start a fresh cluster seeds `rules/default` with two catch-all
buckets:

- `0.0.0.0/0` and `::/0`, each with an **empty `http[]`** — no rule ever
  matches, so every connection still falls through to `511`, the same
  fail-closed behavior an unconfigured deployment has;
- but a **deny-first egress default** on each — loopback, RFC1918/ULA private
  ranges, and link-local (including the `169.254.169.254` cloud-metadata
  address) denied, everything else allowed.

The seed is a safe floor, not a working policy: it blocks SSRF-style egress
out of the box while still requiring you to add `http[]` rules before any
request succeeds.

## Worked example

A complete table with the two seed catch-alls, one plain-prefix bucket, and
one sparse override:

--8<-- "tested/rules/default-ruleset.json"

Line by line:

- `0.0.0.0/0`, `::/0` — the two plain-prefix catch-alls that satisfy the
  coverage obligation. Empty `http[]` (so any address they alone cover still
  `511`s) with the deny-first egress floor.
- `10.0.0.0/8` (`uuid: corp-net`) — a plain-prefix override for the corporate
  range. Mask value `0xFF000000`.
- `10.0.0.0/255.0.255.0` (`uuid: probe-fabric`) — a **sparse** override
  matching every `10.*.0.*` address (octets 1 and 3 fixed, 2 and 4
  don't-care). Mask value `0xFF00FF00`, larger than `/8`'s `0xFF000000`, so it
  outranks `corp-net` for the addresses it matches. It is exempt from
  coverage; `10.0.0.0/8` and the catch-alls carry that obligation.

Resolution for a client with no per-IP override:

| Client | Winning entry | Why |
| --- | --- | --- |
| `10.5.0.9` | `probe-fabric` | matches the sparse mask; largest mask value |
| `10.5.7.9` | `corp-net` | third octet `7` fails the sparse mask; falls to `/8` |
| `8.8.8.8` | `0.0.0.0/0` | only the catch-all matches |

Save it through the control API (a Unix socket by default):

```sh
curl --fail-with-body --unix-socket "$PWD/mitmania.sock" \
  -X PUT -H 'Content-Type: application/json' \
  --data-binary @docs/tested/rules/default-ruleset.json \
  http://localhost/rules/default
```

`PUT` validates strict JSON, compiles every bucket's matches/actions/egress/
auth, enforces the coverage obligation, and probes outcalls unless
`?validate=false` is present. It stores the canonical form; read it back with
`GET /rules/default`. Changes take effect on the next connection — there is no
reload signal.

See the [rule-file schema](../reference/rule-schema.md) for the shape of a
single bucket and [Egress policy](egress.md) for the egress list.
