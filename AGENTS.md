# Working on mitmania

mitmania is a distributed, fail-closed policy and interception proxy. Treat every change as part of a security boundary: preserve the distinction between what a client asked for, what DNS resolved, what the proxy authorized, and what was ultimately dialed.

## North star

- Make the safe behavior the default.
- Keep nodes stateless and interchangeable beyond listeners and telemetry.
- Keep memory bounded and bodies streaming.
- Prefer explicit, testable policy over implicit fallback behavior.
- Document shipped behavior, not planned behavior.

## Start here

| Area | Source |
| --- | --- |
| Product design and invariants | `README.md` |
| Process wiring and startup | `cmd/mitmania/main.go` |
| CLI and environment variables | `internal/config/` |
| Request pipeline | `internal/session/`, `internal/proxy/` |
| Rules, auth, and egress | `internal/rules/` |
| Certificates and deterministic keys | `internal/cert/` |
| Shared state | `internal/storage/` |
| Control API | `internal/control/` |
| Metrics and traces | `internal/telemetry/` |
| User documentation | `docs/`, `mkdocs.yml` |
| Release automation | `.github/workflows/release.yml`, `Dockerfile` |

Read the relevant design section and neighboring tests before changing an implementation. Tests often encode security behavior more precisely than a short comment can.

## Request pipeline

Keep this ordering intact unless the design and tests are deliberately changed together:

1. Accept the session and establish the transport-derived client identity.
2. Select the effective rule file from the source address.
3. Apply explicit-proxy authentication without changing rule selection.
4. Run the connection-phase first match on `host`, `port`, and `proto`.
5. Resolve once, evaluate every returned address against egress policy, and pin the approved destination.
6. Either splice with `mitm:false` or terminate TLS and run message-phase policy.
7. Stream the response, apply bounded mutations, and record telemetry.

## Security invariants

Do not weaken these accidentally:

- `clusterKey` is delivered out of band, never written to Storage, and never logged.
- The signing CA may live in shared Storage only while strongly encrypted under `clusterKey`.
- Leaf private keys are derived, never persisted.
- Rule secrets and storage credentials remain masked in logs, stats, and errors.
- A rule authorizes the requested authority; egress policy separately authorizes resolved addresses. Both must pass.
- DNS is resolved once per connection and the approved address is pinned to prevent rebinding.
- The proxy's own data, control, Storage, and broker endpoints cannot be reached through the proxied data path.
- Rules and egress entries are ordered, first-match lists. Do not introduce accidental cascading.
- No connection rule match fails closed with `511`; egress refusal fails with `403 ERR_FORWARDING_DENIED`; an explicit `connection: {"accept": false}` rule fails closed with `403 ERR_RULE_DENIED`, before any dial or TLS termination — distinct from a `mitm:true` rule's later request-phase block.
- Proxy authentication is a gate and attribution source, not a rule-file selector.
- `mitm:false` is a raw encrypted splice. It cannot make claims about method, path, headers, or body.
- Header and body limits remain bounded; large bodies continue to stream.
- Outcalls remain time-bounded, concurrency-bounded, scoped by proxied client `uuid`, and fail closed unless explicitly configured otherwise.

Security-sensitive behavior needs a negative test: prove not only that the intended request succeeds, but that the adjacent escape attempt fails before an upstream connection is opened.

## Development workflow

1. Inspect `git status` and preserve unrelated work.
2. Reproduce or specify the behavior with a focused test.
3. Make the smallest coherent change across implementation, tests, and docs.
4. Run `gofmt` on changed Go files.
5. Run focused tests first, followed by the broad checks appropriate to the change.
6. Review logs and error responses for accidental secret disclosure.
7. Run `git diff --check` before handing off.

Useful commands:

```sh
make build VERSION=dev
make release VERSION=v1.2.3
make deb TARGET=linux-amd64 VERSION=v1.2.3
go test ./...
go vet ./...
make docs-test
```

Some tests open loopback TCP or Unix sockets. Run them in an environment that permits local listeners; do not delete or weaken those tests merely to accommodate a restricted sandbox.

## Go conventions

- Target the Go version declared in `go.mod`.
- Keep `CGO_ENABLED=0` compatibility and cross-compilation intact.
- Pass `context.Context` through network, Storage, and broker operations.
- Wrap errors with the operation and boundary that failed; preserve causes for `errors.Is`/`errors.As`.
- Keep interfaces at architectural seams rather than introducing abstractions for their own sake.
- Prefer compiled policy and immutable request-time data over reparsing on hot paths.
- Keep protocol-specific behavior in its handler; the dispatcher and Storage layers stay protocol-agnostic.
- Use the existing telemetry helpers so disabled telemetry remains a cheap no-op.
- Avoid attacker-controlled metric labels such as host, URL, client IP, principal, or `uuid`.

## Testing

- Keep tests beside the package they exercise.
- Prefer table-driven coverage for parsers, matchers, and validation matrices.
- Exercise both IPv4 and IPv6 where identity, CIDRs, listeners, or address formatting are involved.
- Test first-match ordering, omission versus explicit empty values, and strict unknown-field rejection.
- Certificate tests should verify chain order, identity fields, deterministic behavior, and persistence boundaries.
- Cross-platform changes must continue to build through the release matrix.
- Documentation rule snippets belong in `docs/tested/rules/` and must compile through the production rule engine.

## Documentation

The documentation is task-first and operator-first. A reader must be able to run a useful non-MITM policy proxy before installing a CA.

- Use the established terms: **proxied client `uuid`**, **effective rule file**, **connection phase**, **message phase**, **splice**, **leaf**, and **signing CA**.
- Say `mitm:false`, never “bypass.”
- Put reusable rule/config JSON in `docs/tested/` and include it with `pymdownx.snippets`.
- Clearly label design-space or unshipped behavior; never present it as runnable.
- Keep internal links valid and build with `mkdocs build --strict`.
- The canonical documentation URL is `https://docs.mitmania.com/`.

## Releases and containers

Publishing a GitHub Release starts `.github/workflows/release.yml`. The release tag is injected into `main.version`; binary archives, Debian packages, and checksums are uploaded to the existing release; and a multi-architecture Alpine image is pushed to `ghcr.io/<owner>/<repository>`.

The container job packages the Linux binaries produced by the release matrix. It must not compile the Go program a second time inside Docker; the release archive and container for a target must contain the same binary.

The Debian jobs likewise package the existing Linux release artifacts with `debx`; they do not compile the binary again. Keep `/etc/default/mitmania` in the package's `conffiles` metadata, keep it mode `0600`, and preserve the systemd service's `DynamicUser` state/runtime directory ownership model.

The runtime image:

- installs `ca-certificates`;
- places the binary at `/usr/bin/mitmania`;
- uses `CMD`, not `ENTRYPOINT`;
- runs as an unprivileged numeric user;
- keeps state under `/var/lib/mitmania` and runtime sockets under `/run/mitmania`.

Do not change release tags, artifact names, supported targets, image paths, or runtime ownership without updating the workflow, Dockerfile, and user documentation together.

## Definition of done

A change is complete when behavior, tests, observability, security implications, and user-facing documentation agree—and when a fresh node can still join a fleet using only shared Storage, the same `clusterKey`, and its local listener configuration.
