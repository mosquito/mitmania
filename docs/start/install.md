# Install a release

## Container image

Images are published to `ghcr.io/mosquito/mitmania` for `linux/386`,
`linux/amd64`, `linux/arm/v7`, `linux/arm64`, `linux/ppc64le`,
`linux/riscv64`, and `linux/s390x`.

```sh
docker run -d \
  --name mitmania \
  -p 3128:3128 \
  -v mitmania-state:/var/lib/mitmania \
  -e MITMANIA_CLUSTER_KEY="$(openssl rand -base64 32)" \
  -e MITMANIA_LISTEN_HTTP_PROXY="tcp://*:3128" \
  ghcr.io/mosquito/mitmania:latest
```

The image runs `CMD`, not `ENTRYPOINT`, as an unprivileged numeric user, so
every flag is set through its `MITMANIA_*` environment variable instead of a
command-line argument. `--storage` defaults to `/var/lib/mitmania` (the
declared volume) and `--control` to a socket under `/run/mitmania`, so state
survives a container restart as long as the volume does. Persist the cluster
key you generate; losing it makes that volume's signing CA unusable.

## Download a binary archive

Prebuilt archives for every supported OS/architecture are attached to each
[GitHub Release](https://github.com/mosquito/mitmania/releases), alongside a
`SHA256SUMS` file. For example, on Linux amd64:

```sh
curl -LO https://github.com/mosquito/mitmania/releases/latest/download/mitmania-linux-amd64.tar.gz
curl -LO https://github.com/mosquito/mitmania/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf mitmania-linux-amd64.tar.gz
./mitmania --help
```

Replace `linux-amd64` with the target OS/architecture (`darwin-arm64`,
`windows-amd64`, ...); Windows archives are `.zip`.

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
