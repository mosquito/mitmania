# Install a release

## Debian or Ubuntu

Download the `.deb` matching the node's architecture from the GitHub Release,
then install it locally. For example:

```sh
sudo apt install ./mitmania_1.2.3-1_amd64.deb
sudoedit /etc/default/mitmania
sudo systemctl enable --now mitmania
systemctl status mitmania
```

Set `MITMANIA_CLUSTER_KEY` in `/etc/default/mitmania` before starting the
service. Generate a new cluster key with `openssl rand -base64 32`, or use the
same out-of-band key as the other nodes when joining an existing cluster.

`/etc/default/mitmania` is a package configuration file: upgrades preserve
local changes and `dpkg` reports upstream conflicts instead of silently
overwriting them. It is installed mode `0600` because the cluster key is a
secret.

The service runs as a transient systemd user. Persistent state is available at
`/var/lib/mitmania`, while the control socket lives under `/run/mitmania`.
systemd creates both with private ownership for the dynamic user. The package
does not start the service automatically because the cluster key must be set
first.

Release packages are published for `amd64`, `arm64`, `armhf`, `i386`,
`ppc64el`, `riscv64`, and `s390x`.

## Build the current source

You need Go 1.26 or later.

From a mitmania source checkout:

```sh
make build
./bin/mitmania --help
```

The build produces a static binary at `bin/mitmania`. Put that binary on the node that will accept client proxy traffic.

Next: [run a single node](first-run.md).
