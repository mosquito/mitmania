# Run a cluster on S3

Two nodes form a fleet by using the same S3 storage URL and the same out-of-band `clusterKey`. Each node keeps its own listener and control socket configuration.

=== "Node A"

    ```sh
    mitmania --storage '<s3-url>' --cluster-key "$CLUSTER_KEY" \
      --control unix:///run/mitmania-a.sock \
      --listen-http-proxy tcp://0.0.0.0:3128
    ```

=== "Node B"

    ```sh
    mitmania --storage '<s3-url>' --cluster-key "$CLUSTER_KEY" \
      --control unix:///run/mitmania-b.sock \
      --listen-http-proxy tcp://0.0.0.0:3128
    ```

Use `s3://KEY:SECRET@host/?bucket=...&region=...` for `<s3-url>`. Put a complete `rules/default` or a per-IP override through node A's control API, open a new connection through node B, and confirm the new policy. Convergence is version-check based and eventual; it is not a fleet transaction.

!!! danger "Security"
    Keep `clusterKey` out of the S3 URL, bucket, and backups. Embedded S3 credentials are redacted from startup logs, but still require least privilege and normal secret delivery.

