# Egress allowlist for Docker, without MITM

This tutorial lets a container reach two HTTPS origins and rejects any other authority. TLS stays end-to-end, so the container does not trust a mitmania CA.

## 1. Start mitmania

```sh
export CLUSTER_KEY="$(openssl rand -base64 32)"
install -d -m 700 ./state
./bin/mitmania \
  --storage "posix://$PWD/state" \
  --control "unix://$PWD/mitmania.sock" \
  --listen-http-proxy tcp://0.0.0.0:3128 \
  --cluster-key "$CLUSTER_KEY"
```

## 2. Discover the client address

In another terminal, make one intentionally denied request:

```sh
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -e HTTPS_PROXY=http://host.docker.internal:3128 \
  curlimages/curl:latest -sS https://httpbingo.org/get
```

Read the `client` address from mitmania's `no-match` access record. Set it below; on common Linux bridge setups it is the container address, while Docker Desktop commonly presents a host-side address.

## 3. Install the rule

```sh
CLIENT_IP=<client-address-from-log>
curl --fail-with-body --unix-socket "$PWD/mitmania.sock" \
  -X PUT -H 'Content-Type: application/json' \
  --data-binary @docs/tested/rules/docker-egress.json \
  "http://localhost/rules/$CLIENT_IP"
```

--8<-- "tested/rules/docker-egress.json"

The file omits `egress`, so it inherits the safe cluster default: loopback, private, link-local, and cloud-metadata destinations are denied; public destinations are allowed.

## 4. Prove the boundary

```sh
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -e HTTPS_PROXY=http://host.docker.internal:3128 \
  curlimages/curl:latest -sS https://httpbingo.org/get

docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -e HTTPS_PROXY=http://host.docker.internal:3128 \
  curlimages/curl:latest -i https://www.iana.org/
```

The allowed request returns origin JSON. The unlisted authority returns `511` without an upstream connection. A connection that matches `http[]` but resolves to a destination denied by `egress[]` returns `403 ERR_FORWARDING_DENIED`.

!!! note
    Host authorization and resolved-address authorization are independent; both must pass. The first produces `511` on no match, while the second produces `403` on deny or fall-through.

