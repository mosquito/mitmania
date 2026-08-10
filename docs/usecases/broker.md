# Central policy via a broker

**Who and why:** platform teams keep fast-changing authorization logic in a local or HTTP broker while mitmania enforces the answer in the data path.

**MITM required?** A `webhook` decides on message fields, so encrypted HTTPS must be intercepted.

The broker receives an allowlisted request envelope with sensitive headers masked. A 2xx response allows; any other status denies. `failOpen` is explicit, outcall concurrency and timeouts are bounded, and cache entries are namespaced by the proxied client `uuid`.

See [Outcalls](../config/outcalls.md) and the [wire format](../reference/wire-format.md).

