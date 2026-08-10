# Request pipeline

Each connection passes through two independent policy questions: does a connection-phase rule authorize this authority, and does egress policy authorize every resolved address? Only intercepted traffic proceeds to message-phase rules.

```mermaid
flowchart TD
    A[Accept session] --> I[Resolve proxied client identity]
    I --> AU{Proxy auth required?}
    AU -->|invalid| X407[407]
    AU -->|valid / absent| C[Connection-phase first match]
    C -->|no match| X511[511]
    C --> E[Resolve once and check every address]
    E -->|denied| X403[403]
    E --> M{mitm?}
    M -->|false| S[Raw splice]
    M -->|true| T[Probe origin, clone leaf, terminate TLS]
    T --> Q[Message-phase first match]
    Q --> P[Run one request pipeline]
    P --> O[Forward and stream response]
    O --> RP[Run response actions]
```

The same ordered `http[]` list is scanned twice. The connection pass sees only `host`, `port`, and `proto` and decides whether to intercept. After interception, the message pass can also see `path`, `method`, and headers and runs exactly one rule's action pipeline.

Rules are first-match, not cumulative. A broad rule placed first can make every narrower rule dead. Egress is a separate first-match list over pinned destination IPs; both lists must allow the connection.

See [Matching and actions](../config/actions.md) for field semantics and [Error pages](../config/errors.md) for rejection delivery.

