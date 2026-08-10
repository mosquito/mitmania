# Glossary

**broker** — external service called by an outcall for authorization, headers, or proxy credential validation.

**clone** — synthetic certificate identity based on the observed origin chain and signed by mitmania's signing CA.

**connection phase** — first rule pass using only authority-level `host`, `port`, and `proto`.

**effective rule file** — per-IP override, or the highest-ranked `rules/default` bucket when no override exists.

**generation-less consistency** — eventual convergence through Storage versions without a cluster transaction or monotonic policy generation.

**leaf** — end-entity TLS certificate presented to a client for one cloned or fallback identity.

**message phase** — post-interception rule pass that can inspect HTTP path, method, and headers.

**outcall** — bounded request from an action or auth gate to a broker.

**principal** — authenticated Basic/Bearer name or broker assertion, recorded for attribution but not used to select rules.

**proxied client `uuid`** — stable logical identity from the effective rule file, sent to brokers and used to partition their cache.

**signing CA** — cluster-wide certificate authority stored as encrypted `ca.p12` and trusted by intercepted clients.

**splice** — `mitm:false` raw tunnel in which TLS remains end-to-end between client and origin.

**Storage** — POSIX or S3 durability abstraction for cluster-shared CA, certificate, and rule state.

