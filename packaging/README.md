# Native packaging

Builders for OS-native ASH packages. Every artifact here is published as a **GitHub
Release asset only** — nothing in this directory submits to `microsoft/winget-pkgs`,
`community.chocolatey.org`, or Flathub, and nothing publishes a container image.

## The boundary these builders must not cross

ASH's own code may ship in a published artifact. Third-party code never may.

`.github/scripts/assert-artifact-contents.py` enforces that on the wheel and sdist, and
its `--self-test` plants a payload per detector so it cannot pass vacuously.

Native packages are downstream of that wheel and carry ASH's own wheel, so they sit on
the permitted side of the boundary. Each one bundles exactly one wheel and resolves
everything else from an index at install time.

## Why each package carries exactly one wheel

The "exactly one bundled wheel" rule is the guard that keeps these packages on the right
side of the boundary. It is cheap to check and hard to get wrong by accident: count the
files under `wheels/`, and if the answer is one, no third-party code shipped. A rule
phrased as "no third-party wheels" would need a judgment call per dependency and would
be enforced by whoever reviewed the build script that day.

Because dependencies come from an index, **these packages need a reachable Python index
at install time.** On an air-gapped host, stage a wheelhouse first — both
`packaging/deb/debian/README.Debian` and `packaging/rpm/README.rpm` give the exact
commands — or point the host at an internal index mirror.

A fully self-contained offline image is fine to build; it is simply built by whoever
operates the host rather than published from here. Bundle ASH's wheel with its
dependency wheels and `pip install --no-index` them, or bake the whole venv into a
container image. Nothing about that is impermissible. What the boundary rules out is
*us* publishing an artifact with someone else's code inside it, which is a question
about the publisher, not about what the bytes can do.

So the one change to avoid is quietly adding dependency wheels to the `.deb` or `.rpm`
built here. That would turn a one-file check anyone can run into a per-dependency
judgment nobody will re-run.

## Layout

| Directory | Format | Verified by |
|---|---|---|
| `deb/` | Debian, Ubuntu | build + install + real scan in `debian:bookworm` |
| `rpm/` | Amazon Linux, RHEL | build + install + real scan in `amazonlinux:2023` |
| `flatpak/` | any Linux with flatpak | build + install + real scan against `org.freedesktop.Sdk//24.08` |
| `homebrew/` | Homebrew tap, for `Formula/ash.rb` at the repository root | `brew install` + `brew test` + `brew audit --strict` on `macos-latest` |

The Flatpak needs a privileged container or a host that permits unprivileged user
namespaces, because `flatpak-builder` drives `bwrap`. That is why its CI job has no
`container:` key while the deb and rpm jobs do, and `packaging/flatpak/README.flatpak`
carries the measurement.

`homebrew/` is the odd one out and the rest of this file does not describe it. It builds
no package and bundles no wheel: it holds the generator that keeps the formula's
`resource` block in step with `pyproject.toml`, and Homebrew builds ASH from the git tag
on the user's machine. The one-wheel rule above therefore has nothing to count there --
what keeps the formula on the permitted side of the boundary is that a `resource` stanza
is a URL and a sha256, so no dependency source enters the tree. Read
`homebrew/README.md`.

## Install shape, common to the deb and the rpm

Both packages install the same way, so a bug in one is a bug in the other:

- `/usr/lib/ash/wheels/` — ASH's wheel, the only payload.
- `/usr/lib/ash/venv/` — created by the post-install step, never shipped inside the
  package. A venv built on the build host would carry absolute paths and the build
  host's interpreter ABI, so it cannot be relocated to the target.
- `/usr/bin/ash` — a wrapper execing the venv's entry point. A symlink into the venv
  would work for `ash` but breaks `sys.executable` discovery for the container runner,
  which shells out to itself.

Removal drops the venv, because `pip` created it after install and no package manager
tracks files a `postinst` wrote.

## Where the Flatpak differs, and why

Flatpak has no post-install hook: an installed app is a read-only OSTree checkout and no
code runs on the user's machine at install time. So the venv is built on **first run**,
by a launcher at `/app/bin/ash`, into
`~/.var/app/io.github.awslabs.automated_security_helper/data/`. The bundled wheel still
lives inside the app, at `/app/share/ash/wheels/`, and the count is still one.

The one-wheel rule needs a second check for this format that the `.deb` and `.rpm` do not
need. Those two can only gain third-party code by gaining a `.whl` file. A Flatpak build
step could instead `pip install` dependencies straight into `/app`, which leaves unpacked
modules and `.dist-info` directories and no wheel at all — so `packaging/flatpak/build.sh`
counts wheels *and* fails on any `.dist-info` or `.egg-info` under the built app.

Two things stop that happening by accident rather than by review: `build.sh` passes
`--disable-download`, and the manifest grants the build sandbox no network. The second was
measured by putting a `pip download requests` in the manifest's build-commands, which fails
with `Failed to resolve 'pypi.org' ([Errno -3] Temporary failure in name resolution)`.

The Flatpak also cannot put `ash` on the host's PATH — flatpak exports the application ID
— and it grants `--filesystem=host`, without which it would install and then be unable to
read the tree it was asked to scan. `packaging/flatpak/README.flatpak` documents both,
including what the permission gives up and what a user who wants tighter confinement can
do instead.
