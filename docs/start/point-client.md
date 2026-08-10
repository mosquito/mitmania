# Point a client at mitmania

An explicit client sends ordinary HTTP requests and HTTPS `CONNECT` tunnels to the proxy.

=== "Shell environment"

    ```sh
    export HTTP_PROXY=http://127.0.0.1:3128
    export HTTPS_PROXY=http://127.0.0.1:3128
    export NO_PROXY=localhost,127.0.0.1
    ```

=== "One curl command"

    ```sh
    curl --proxy http://127.0.0.1:3128 https://httpbingo.org/get
    ```

=== "Docker"

    ```sh
    docker run --rm \
      --add-host=host.docker.internal:host-gateway \
      -e HTTPS_PROXY=http://host.docker.internal:3128 \
      curlimages/curl:latest https://httpbingo.org/get
    ```

The node chooses an effective rule file from the socket peer's source address. Container networking may make that address the bridge gateway rather than the container address; confirm the access log before installing a per-IP override.

Next: [verify the policy and TLS behavior](verify.md).

