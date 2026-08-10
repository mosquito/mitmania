# Matching and actions

## Matching fields

| Field | Phase | Value |
| --- | --- | --- |
| `host` | connection | canonical destination hostname |
| `port` | connection | destination port |
| `proto` | connection | `http` or `https` transport label |
| `path` | message | request path |
| `method` | message | HTTP method |
| `header` | message | object of header-name to value pattern |
| `status` | response schema | reserved; not evaluated by the current two-pass engine |

An omitted field matches anything. A plain value uses path-style glob syntax; `re:` introduces a regular expression. Anchor security-sensitive regular expressions explicitly.

## Actions

| Action | Request | Response | Effect |
| --- | :---: | :---: | --- |
| `header.add` | ✓ | ✓ | append header values |
| `header.set` | ✓ | ✓ | replace; JSON `null` deletes |
| `raise` | ✓ | — | return a synthetic status/page |
| `block` | ✓ | — | close/reset |
| `webhook` | ✓ | — | broker authorization decision |
| `header.fetch` | ✓ | — | fetch headers from a broker |
| `body.replace` | — | ✓ | replace within the body window |
| `status.set` | — | ✓ | replace response status |

Request and response arrays run in order, but only for one first-matching rule. See [Outcalls](outcalls.md) for broker action parameters.

