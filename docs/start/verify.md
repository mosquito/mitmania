# Verify it works

Install a temporary non-MITM rule for the client address shown in the access log. The control API is a Unix socket, so use curl's `--unix-socket` option:

```sh
CLIENT_IP=127.0.0.1
curl --fail-with-body --unix-socket "$PWD/mitmania.sock" \
  -X PUT -H 'Content-Type: application/json' \
  --data-binary @docs/tested/rules/get-started.json \
  "http://localhost/rules/$CLIENT_IP"
```

--8<-- "tested/rules/get-started.json"

Now TLS remains end-to-end:

```sh
curl --proxy http://127.0.0.1:3128 https://httpbingo.org/get
curl --proxy http://127.0.0.1:3128 https://example.com/
```

The first command succeeds. The second receives `511 Network Authentication Required`: the per-IP override you just installed has no connection-phase rule for `example.com`, so it falls closed. No CA is involved. (A client *without* an override would instead resolve the [default table](../config/default-ruleset.md), whose seeded buckets `511` for the same reason.)

To verify interception later, remove `mitm:false`, trust the CA, and compare the leaf seen through mitmania with the origin at `tls.peet.ws`. `badssl.com` cases exercise certificate-chain fidelity.

