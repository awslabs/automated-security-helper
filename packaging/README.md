# Native packaging

Builders for OS-native ASH packages. Every artifact here is published as a **GitHub
Release asset only** — nothing in this directory submits to `microsoft/winget-pkgs`,
`community.chocolatey.org`, or Flathub, and nothing publishes a container image.

## The invariant these builders must not break

No GitHub-published artifact may contain third-party scanner source or assets.
`.github/scripts/assert-artifact-contents.py` enforces this on the wheel and sdist, and
its `--self-test` plants a payload per detector so it cannot pass vacuously.

Native packages are downstream of that wheel, so they inherit the guarantee **only for
as long as they bundle nothing else**. That is a real design constraint, not a
formality, and it is why these packages resolve dependencies at install time.

## Why these packages are not self-contained, and what that costs

The obvious design for an air-gapped host is to bundle ASH's wheel together with its
27 runtime dependency wheels and `pip install --no-index` them. **That is not
permissible here.** `detect-secrets>=1.5,<2` is a runtime dependency in
`pyproject.toml` *and* a denylisted scanner. The published wheel passes the contents
gate only because it *declares* its dependencies in metadata rather than vendoring
them; the moment a `.deb` carries a `detect_secrets` wheel, a GitHub-published artifact
contains third-party scanner source.

So each package bundles **ASH's own wheel and nothing else**, and its post-install step
resolves dependencies from whatever index the host is configured for.

The cost is explicit: **these packages need a reachable Python index at install time.**
That is a genuine gap against the air-gapped audience native packaging is partly for,
and there are only three ways to close it, none of which is a packaging change:

1. Move `detect-secrets` out of `[project] dependencies` and provision it like the other
   scanners. This is the only option that yields a bundled, offline, rule-compliant
   package, and it is a change to ASH's dependency surface rather than to packaging.
2. Ship a separate wheelhouse tarball as its own release asset, which users stage
   themselves. The scanner content then lives in an artifact the invariant forbids, so
   this only works if the wheelhouse is explicitly carved out of the rule — an
   operator decision, not one to assume.
3. Point the host at an internal index mirror. Works today, but it is site
   configuration rather than something the package can carry.

Do not "fix" the gap by bundling dependency wheels. That trades a documented
limitation for a silent violation of the one rule this directory exists to respect.

## Layout

| Directory | Format | Verified by |
|---|---|---|
| `deb/` | Debian, Ubuntu | build + install + real scan in `debian:bookworm` |
| `rpm/` | Amazon Linux, RHEL | build + install + real scan in `amazonlinux:2023` |

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
