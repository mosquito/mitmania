# Install

## Build the current source

You need Go 1.26 or later.

From a mitmania source checkout:

```sh
make build
./bin/mitmania --help
```

The build produces a static binary at `bin/mitmania`. Put that binary on the node that will accept client proxy traffic.

!!! note
    Release-package and container-image installation instructions belong here once those artifacts ship. The source build above matches the current repository.

Next: [run a single node](first-run.md).
