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

## The package-contents gate

`.github/scripts/assert-artifact-contents.py` refuses an .msix or a .nupkg at exit 2
(it cannot judge them), so the packages built here have their own gate,
`packaging/assert-package-contents.py`. It runs on the real artifact, after the build:

| Format | Where it runs | What it checks beyond the wheel count |
|---|---|---|
| MSIX | `msix/verify-on-windows.ps1`, step 2b, on the signed package | every member is in the MSIX layout; the root `.exe` files are exactly the Application/@Executable names in the packaged `AppxManifest.xml` and exactly the wheel's console scripts, each a managed PE under 256 KiB; `AppxBlockMap.xml` matches every payload member's size and block hashes |
| Chocolatey | `chocolatey/verify-on-windows.ps1`, step 3b, on the packed .nupkg | every member is one `build.ps1` stages or `choco pack` adds; no binaries |
| Flatpak | `flatpak/build.sh`, check 4, on `build-dir/files` before export | every file is one the manifest installs; `bin/ash` is byte-identical to `ash-launcher.sh`; symlinks point only at it; the names in `bin/` are exactly the wheel's console scripts |

In all three the one ASH wheel is extracted and handed to the wheel gate, and every
other member goes through the wheel gate's payload rules (native binaries, vendored
scanners, nested archives, size). The layouts are closed: a new file in a package needs a
line in the gate in the same commit. `--self-test` plants payload in fixtures shaped like
the real packages and runs in the `build` job of `ash-package.yml` before anything is
built; `tests/unit/test_package_contents_gate.py` pins those fixtures to the member
lists of real builds.

## Release assets and provenance

A GitHub Release of ASH attaches these files, and nothing else.
`packaging/release-assets.py` holds the list, and every workflow reads it from there:

| Asset | File | Built and exercised by | Gate run on the attached bytes |
|---|---|---|---|
| wheel, sdist | `automated_security_helper-<v>-py3-none-any.whl`, `automated_security_helper-<v>.tar.gz` | `ash-package.yml` `build` | `assert-artifact-contents.py` |
| MCP bundle | `ash-<bundle version>.mcpb` | the committed archive, drift-checked | exactly one member, `manifest.json` |
| deb | `automated-security-helper_<v>_all.deb` | `ash-native-packages.yml`, Debian 12 assert leg | `assert-package-payload.py` |
| rpm | `automated-security-helper-<v>-1.noarch.rpm` | `ash-native-packages.yml`, Amazon Linux 2023 assert leg | `assert-package-payload.py` |
| MSIX | `automated-security-helper-<v>.msix` | `ash-package.yml` `msix` | `assert-package-contents.py` |
| Chocolatey | `ash.<v>.nupkg` | `ash-package.yml` `chocolatey` | `assert-package-contents.py` |
| Flatpak | `ash-<v>-x86_64.flatpak` | `ash-package.yml` `flatpak` | the bundle is imported into a scratch OSTree repository and checked out, then `assert-package-contents.py --flatpak-tree` |
| winget | `Amazon.AutomatedSecurityHelper.yaml`, `.installer.yaml`, `.locale.en-US.yaml` | rendered for the attached MSIX by `winget/set-release-metadata.py` | `winget/validate-manifests.py --released`, and InstallerSha256 and InstallerUrl must name the attached MSIX |
| VS Code | `ash-vscode-<v>.vsix` | `ash-release-assets.yml` `vsix` | `vsix-contents.ts`, then Python's zipfile over the same bytes |
| JetBrains | `ash-jetbrains-<plugin version>.zip` | `ash-release-assets.yml` `jetbrains` | `editors/jetbrains/assert-plugin-zip-contents.py` |

`homebrew/` attaches nothing: its channel is `Formula/ash.rb`, which names the release
tag. The container image is never published, here or anywhere else, and the asset check
refuses an image archive by name and by content.

`.github/workflows/ash-release-assets.yml` builds the whole set, stages it in one
directory, runs every gate above on it, and requires the directory to hold exactly the
listed files. Then it shows that check failing on a copy with the `.deb` removed and on a
copy with an ungated file added. On a push that is the release's dry run: it attests
nothing and publishes nothing. `ash-tag-on-merge.yml` calls the same workflow when a
`chore(release):` pull request merges, checks the downloaded bytes against the digests
the gates produced, attests every file with `actions/attest-build-provenance`, attaches
them with `gh release create`, and then compares the release's asset names with the
staged set.

To check a downloaded asset, with the GitHub CLI:

```bash
# Any asset, by its file name. The attestation names the workflow that built and
# attested it, so pin that too.
gh attestation verify automated-security-helper_4.0.0_all.deb \
  --repo awslabs/automated-security-helper \
  --signer-workflow awslabs/automated-security-helper/.github/workflows/ash-tag-on-merge.yml
```

The command is the same for every asset type: the `.whl`, `.tar.gz`, `.mcpb`, `.deb`,
`.rpm`, `.msix`, `.nupkg`, `.flatpak`, the three winget `.yaml` files, the `.vsix` and the
JetBrains `.zip`. Verify the file before installing it, because each installer runs code
from it. Two formats carry a second check of their own. Windows checks the MSIX's
Authenticode signature at install (`README.msix` covers the self-signed certificate), and
winget refuses an MSIX whose SHA-256 differs from the manifest's `InstallerSha256`, so
verifying the installer manifest also pins the MSIX it names.

## Layout

| Directory | Format | Verified by |
|---|---|---|
| `deb/` | Debian, Ubuntu | build + payload gate + install beside the distribution's `ash` shell + the three e2e scans (exit 2, 0 and 1, `tests/e2e`) + upgrade from N-1 + purge in `debian:bookworm` and `ubuntu:24.04` (`ash-native-packages.yml`) |
| `rpm/` | Amazon Linux, RHEL | build + payload gate + install beside a package owning `/usr/bin/ash` + the three e2e scans (exit 2, 0 and 1, `tests/e2e`) + upgrade from N-1 + erase in `amazonlinux:2023` and `ubi9` (`ash-native-packages.yml`) |
| `flatpak/` | any Linux with flatpak | build + install + real scan against `org.freedesktop.Sdk//24.08` |
| `msix/` | Windows 10, Windows 11 | build + sign + tampered-package refusal + install N-1 + upgrade to N + the three e2e scans (exit 2, 0, 1) + reinstall + uninstall on `windows-latest` |
| `chocolatey/` | Windows, via Chocolatey | nuspec vs NuGet's XSD anywhere; build + install + the three e2e scans (exit 2, 0, 1) + upgrade from N-1 + uninstall + a failing-install control on `windows-latest` |
| `winget/` | Windows, via winget | manifest set vs Microsoft's published JSON Schemas. Installs the MSIX, so it is schema-valid but not submission-ready; `README.winget` says why |
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

Both packages install the same way, so a bug in one is a bug in the other. Below,
`<pkgname>` is `ASH_PKG_NAME` and `<cli>` is `ASH_CLI_NAME`, both set in
`packaging/cli-name.sh`: `automated-security-helper` and `ashx` today. The READMEs the packages ship are
written with `@ASH_PKG@` and `@ASH_CLI@` and substituted at build time.

- `/usr/lib/<pkgname>/wheels/` — ASH's wheel, the only payload.
- `/usr/lib/<pkgname>/venv` — a symlink to `/usr/lib/<pkgname>/venv-<id>/`, which the
  post-install step creates; never shipped inside the package. A venv built on the
  build host would carry absolute paths and the build host's interpreter ABI, so it
  cannot be relocated to the target, and for the same reason an upgrade builds the
  new venv in its own directory and swaps the symlink by rename rather than moving a
  venv.
- `/usr/bin/<cli>` — a wrapper execing the venv's entry point. A symlink into the venv
  would work for the command itself but breaks `sys.executable` discovery for the container runner,
  which shells out to itself.

That wrapper is the only command either package puts on PATH. Neither installs
`/usr/bin/ash`, which is the Almquist shell's name (Debian ships it as the `ash`
package, and on a merged-`/usr` host `/bin/ash` and `/usr/bin/ash` are one file), and
neither declares a Provides, Conflicts, Replaces or Obsoletes naming `ash`. The venv
still holds the wheel's deprecated `ash` console script; nothing links it onto PATH.
Both `verify-in-container.sh` scripts assert the file list carries no `/usr/bin/ash`,
install a package owning `/usr/bin/ash` beside the package and require both to work,
and have a `negative-shell-path` mode that shows both checks failing on a build that
ships `/usr/bin/ash`.

Removal drops the venv, because `pip` created it after install and no package manager
tracks files a `postinst` wrote. An upgrade does not: the deb's `prerm` removes it only on
`remove`, the rpm's `%postun` only when `$1` is 0, and a failed rebuild never touches the
symlink, so the previous version keeps working.

Package versions are mapped from the wheel's PEP 440 version by `packaging/version-map.sh`
so dpkg and rpm sort them correctly (`3.8.0rc1` becomes `3.8.0~rc1`, below `3.8.0`).

Both packages compress their payload with gzip and add a license file, and
`packaging/assert-package-payload.py` pins each payload member by member, rejects any
member that is not a regular file or directory (a symlink or device node at a pinned
path, or a hard link) and any setuid, setgid, group-writable or world-writable
mode, applies the artifact-contents gate's own content
rules to every member, and hands the wheel it extracts from the built package back to
that gate. The shared install-and-scan logic,
including the negative controls that show each check failing, is
`packaging/verify-lib.sh`; the command name both packages install is set once, in
`packaging/cli-name.sh`.

## Where the Flatpak differs, and why

Flatpak has no post-install hook: an installed app is a read-only OSTree checkout and no
code runs on the user's machine at install time. So the venv is built on **first run**,
by a launcher at `/app/bin/ashx`, into
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

The Flatpak also cannot put `ashx` on the host's PATH — flatpak exports the application ID
— and it grants `--filesystem=host`, without which it would install and then be unable to
read the tree it was asked to scan. `packaging/flatpak/README.flatpak` documents both,
including what the permission gives up and what a user who wants tighter confinement can
do instead.
