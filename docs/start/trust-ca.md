# Trust the signing CA

Skip this page when every applicable rule uses `mitm:false`. Intercepted clients must trust the signing CA.

Fetch it through the explicit listener:

```sh
curl --proxy http://127.0.0.1:3128 http://mitmania/ca.pem -o mitmania-ca.pem
openssl x509 -in mitmania-ca.pem -noout -subject -fingerprint -sha256
```

=== "Debian / Ubuntu"

    ```sh
    sudo install -m 0644 mitmania-ca.pem /usr/local/share/ca-certificates/mitmania.crt
    sudo update-ca-certificates
    ```

=== "Alpine"

    ```sh
    sudo apk add --no-cache ca-certificates
    sudo install -m 0644 mitmania-ca.pem /usr/local/share/ca-certificates/mitmania.crt
    sudo update-ca-certificates
    ```

=== "curl only"

    ```sh
    curl --cacert mitmania-ca.pem --proxy http://127.0.0.1:3128 https://httpbingo.org/get
    ```

=== "Android"

    Install `mitmania-ca.pem` as a user CA in the device security settings. Apps that opt out of user-added CAs need an app-specific network security configuration.

!!! danger "Security"
    Trusting this CA authorizes the holder of the signing key to impersonate TLS origins for that client. Verify the SHA-256 fingerprint over a separate trusted channel before fleet-wide installation.

Next: [point a client](point-client.md).

