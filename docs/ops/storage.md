# Storage backends

=== "POSIX"

    ```sh
    mitmania --storage posix:///var/lib/mitmania ...
    ```

    Use one private directory, owned by the service account. Rule and secret-bearing files are written with restrictive permissions.

=== "S3"

    ```sh
    mitmania --storage 's3://KEY:SECRET@s3.internal/?bucket=mitmania&region=eu-west-1' ...
    ```

    Use a dedicated bucket and credentials limited to the mitmania keyspace. Every node must use the same bucket and `clusterKey`.

The signing CA, certificate cache, and rule files belong to Storage. Telemetry JSONL spools do not; size/age rotation is local to each node.

