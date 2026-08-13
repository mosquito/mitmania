# Arch Linux packaging

Two AUR packages, mirroring the `packaging/debian/` split between a
prebuilt-binary path and a build-from-source path:

- `mitmania-bin/` — downloads the release's `linux-amd64`/`linux-arm64`
  archive from GitHub Releases and installs the binary directly.
- `mitmania/` — builds from the tagged source tarball with `go build`.

Both install the same systemd unit and config file layout:
`/usr/bin/mitmania`, `/usr/lib/systemd/system/mitmania.service`, and
`/etc/mitmania.conf` (mode `0600`, since `MITMANIA_CLUSTER_KEY` lives there —
the Arch equivalent of the Debian package's `/etc/default/mitmania`
conffile). `mitmania.service` and `mitmania.conf` here are the shared
sources both PKGBUILDs pull in.

Verified against a real `archlinux:latest` container: `makepkg --printsrcinfo`
and a full `makepkg` build succeed for both packages as committed, producing
the expected file layout under `usr/`, `etc/`, and
`usr/share/licenses/<pkgname>/`. Both PKGBUILDs set `options=('!debug'
'!strip')` — the release binary is already stripped at Go build time
(`-ldflags "-w -s"`), and skipping makepkg's own tidy-strip step keeps the
packaged binary byte-identical to the one in the release archive.

## `mitmania-bin` as a release asset

Unlike `mitmania` (source-build, AUR-only), `mitmania-bin`'s `.pkg.tar.zst`
is also built directly in `.github/workflows/release.yml` (the
`arch-packages` job) and attached to each GitHub Release for both `x86_64`
and `aarch64`, alongside the `.deb` packages — installable directly via
`pacman -U` without going through AUR at all. That job reuses the Linux
binary the `binaries` job already built (never recompiles, matching this
project's rule that a release archive and its packaged forms must contain
the same binary) and packages it with a CI-only variant,
`mitmania-bin/PKGBUILD.release` — `PKGBUILD` itself always downloads over
the network from a tagged release, which would be circular against the
release currently being built.

Both architectures build from one image, `menci/archlinuxarm:base-devel`
(genuinely multi-arch: real Arch Linux on `amd64`, real Arch Linux ARM on
`arm64`, both with `base-devel` preinstalled), with `arm64` running under
QEMU emulation (`docker/setup-qemu-action`) on the `ubuntu-latest` runner.
Arch Linux ARM's image defaults `PKGEXT` to `.pkg.tar.xz` rather than
mainline Arch's `.pkg.tar.zst`; the job forces `.pkg.tar.zst` on both so the
two matrix jobs produce a predictable, matching extension. It also disables
pacman's Landlock-based download sandbox (`DisableSandbox`), which isn't
available under QEMU emulation.

## Publishing to AUR

This directory is not synced automatically — AUR publishing is a manual,
per-package git push to `ssh://aur@aur.archlinux.org/<pkgname>.git`, done
from an AUR account with an SSH key registered. To publish or update a
package:

```sh
git clone ssh://aur@aur.archlinux.org/mitmania-bin.git aur-mitmania-bin
cp packaging/arch/mitmania-bin/{PKGBUILD,.SRCINFO} aur-mitmania-bin/
cd aur-mitmania-bin
git add PKGBUILD .SRCINFO
git commit -m "..."
git push
```

Repeat for `mitmania` (source package). The two AUR repos hold only
`PKGBUILD` and `.SRCINFO` — `mitmania.service`/`mitmania.conf` are fetched by
each PKGBUILD's `source=()` array from this repo's raw GitHub URL at the
pinned tag, not committed into the AUR repo itself.

## Bumping a release

On every new mitmania release, for both `mitmania-bin/PKGBUILD` and
`mitmania/PKGBUILD`:

1. Update `pkgver` to the new release tag (without the `v` prefix) and reset
   `pkgrel=1`.
2. Update every `sha256sums*` entry that changed: the release archive
   hash(es) (from that release's `SHA256SUMS` asset), the source tarball
   hash (`mitmania` only), and the `mitmania.service`/`mitmania.conf` source
   hashes if those files changed. The `LICENSE` source URL and hash
   (`mitmania-bin` only) track the same tag, so update it too if the license
   text changed.
3. Regenerate `.SRCINFO`: `makepkg --printsrcinfo > .SRCINFO`.
4. Push to the corresponding AUR repo as above.

`mitmania-bin/PKGBUILD.release` needs no such bumping — the release workflow
substitutes `pkgver` and stages every source file locally on each run, so
there's nothing version-pinned to keep in sync by hand.
