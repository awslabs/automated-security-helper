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

So the one change to avoid is quietly adding dependency wheels to the `.deb`, `.rpm`,
or Chocolatey package built here. That would turn a one-file check anyone can run into
a per-dependency judgment nobody will re-run. Chocolatey is where that pressure is
highest, because vendoring binaries into `tools/` is the format's own convention;
`packaging/chocolatey/README.chocolatey` says so at the point where someone would be
tempted.

## Layout

| Directory | Format | Verified by |
|---|---|---|
| `deb/` | Debian, Ubuntu | build + install + real scan in `debian:bookworm` |
| `rpm/` | Amazon Linux, RHEL | build + install + real scan in `amazonlinux:2023` |
| `chocolatey/` | Windows, via Chocolatey | nuspec vs NuGet's XSD anywhere; build + install + real scan on `windows-latest` |
| `winget/` | Windows, via winget | manifest set vs Microsoft's published JSON Schemas. Installs the MSIX, so it is schema-valid but not submission-ready; `README.winget` says why |

## Install shape, common to both

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
