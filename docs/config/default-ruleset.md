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

## Generate an advertising and tracker policy

`tools/adblock_to_mitmania.py` converts hostname-wide entries from maintained
filter sources into ordered mitmania rules. These publisher presets are
available:

| Preset | Publisher source | Default |
| --- | --- | --- |
| `hagezi-light` | `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/light.txt` | Yes |
| `hagezi-tif-mini` | `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt` | Yes |
| `adblock` (EasyList) | `https://easylist-downloads.adblockplus.org/easylist.txt` | No |
| `easyprivacy` | `https://easylist.to/easylist/easyprivacy.txt` | No |
| `adguard` | `https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt` | No |
| `ublock` | `https://ublockorigin.github.io/uAssets/filters/filters.txt` | No |
| `ublock-privacy` | `https://ublockorigin.github.io/uAssets/filters/privacy.txt` | No |
| `peterlowe` | `https://pgl.yoyo.org/adservers/serverlist.php?hostformat=plain&mimetype=plaintext&showintro=0` | No |
| `ghostery` | `https://github.com/ghostery/trackerdb/archive/refs/heads/main.tar.gz` | No |

The no-argument policy combines HaGeZi Multi Light for relaxed ad and tracker
blocking with HaGeZi TIF Mini for malware, phishing, scam, and command-and-
control protection. The broader browser and privacy lists remain explicit
opt-ins because a whole-host connection decision cannot preserve their page,
request-type, or application context. Test any broader selection against the
proxied clients in scope.

Update the current `rules/default` through the local control socket:

```sh
python3 tools/adblock_to_mitmania.py \
  --control "unix://$PWD/mitmania.sock"
```

The converter fetches the current table, prepends the generated filter rules
to every bucket, preserves its `uuid`, auth, egress, and existing `http[]`
values, then submits the complete replacement. The update still passes the
production parser, compiler, coverage check, and control API size limit.

Use one or more named presets to select providers explicitly:

```sh
python3 tools/adblock_to_mitmania.py \
  --preset all \
  --control "unix://$PWD/mitmania.sock"
```

`--preset all` selects the strict union of every provider. Sources may overlap;
the converter deduplicates effective domains before generating rules.
`--preset ghostery` selects Ghostery alone. Available provider presets are `adblock`,
`easyprivacy`, `adguard`, `ublock`, `ublock-privacy`, `peterlowe`,
`hagezi-light`, `hagezi-tif-mini`, and `ghostery`. Every preset constructs its
provider from that class's maintained `default_url`. Custom sources are typed
as `provider=location`, which prevents an archive from being interpreted by
the wrong parser:

```sh
python3 tools/adblock_to_mitmania.py \
  ublock=https://filters.example/ads.txt \
  adguard=/etc/mitmania/local-adguard.txt \
  ghostery=/var/cache/mitmania/trackerdb.tar.gz \
  --output generated-rules.json
```

The location is an HTTP(S) URL, a local file, or `-` for standard input.
Explicit sources without `--preset` replace the defaults. Before downloading
a provider, `--control` first verifies that it can read the current table.
Progress logs report mined rule counts per provider and the final
effective-domain and generated-rule counts. Run
`python3 tools/adblock_to_mitmania.py --help` for output shapes, size bounds,
Ghostery category selection, and dry-file generation options.

!!! warning "Blocking rejects the connection"
    The default `--action block` emits a connection-phase `accept:false` rule.
    It rejects a selected hostname before TLS termination and does not require
    the proxied client to trust the signing CA. Use `--action raise` only when
    the proxied client trusts the signing CA and an HTTP status and body are
    preferable to a closed connection.
    Review the source licenses before redistributing generated data; Ghostery
    TrackerDB is CC-BY-NC-SA-4.0 and defaults to the advertising,
    pornvertising, and site-analytics categories.

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
