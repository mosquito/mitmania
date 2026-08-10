# Egress policy

`egress[]` is an ordered, first-match list evaluated against every resolved destination address before dialing.

--8<-- "tested/rules/egress-private-exception.json"

| Field | Required | Meaning |
| --- | --- | --- |
| `cidr` | yes | destination prefix |
| `port` | no | number, inclusive range, `*`, or omitted |
| `proto` | no | selected L7 handler (`http` in v1) |
| `action` | yes | `allow` or `deny` |

Fall-through denies. DNS is resolved once, all answers are checked, and an answer set containing any denied address is refused. A hard guard denies mitmania's own listeners regardless of this list.
