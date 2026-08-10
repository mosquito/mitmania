# Inject an API token through a broker

This advanced tutorial's contract is: a Unix-socket broker returns an `Authorization` header, a narrow `header.fetch` rule requests it, the origin receives it, and the proxied client never does. Rotating the effective rule file's `uuid` invalidates that client's cache namespace.

Before following it in production, understand the broker [wire format](../reference/wire-format.md), load-time probe, header denylist, timeout behavior, and `failOpen` trade-off in [Outcalls](../config/outcalls.md).

!!! note
    A maintained, tested broker fixture is still needed before this page can honestly provide the copy-runnable walkthrough required by the documentation standard. The shipped action and wire contract are documented; an untested toy broker is intentionally not presented as production guidance.

