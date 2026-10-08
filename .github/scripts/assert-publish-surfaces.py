#!/usr/bin/env python3
"""Fail when a workflow gains an artifact upload or a cache that is not allowlisted.

WHY THIS EXISTS

This repository is public, and on a public repository both the artifact store and
the Actions cache are readable by anyone holding a read token -- which is
everyone. `actions/upload-artifact` produces a download URL any GitHub user can
fetch, and an Actions cache entry can be restored by any workflow run, including
one from a fork's pull request. So every workflow step that uploads or caches
bytes THIS PROJECT BUILDS is publishing those bytes to the internet, whether or
not anyone meant to.

The set of such steps was audited once. Auditing it once is not worth much: the
next person to add a step is following an example from the internet, their step
looks exactly like the four already-accepted ones in review, and nothing in the
diff says "this is now downloadable by strangers". The invariant only holds if
something re-tests it, so this censuses the whole `.github/` tree on every pull
request rather than trusting the commit that established it.

What this does NOT do: judge. It has no opinion on whether a given upload is
safe. It only asserts that the set of publishing sites is the set somebody
decided on, and puts a human in the loop for anything else.

WHAT THE ALLOWLIST IS KEYED ON, AND WHY IT IS NOT JUST THE FILENAME

The obvious design -- "these files may upload" -- has a hole big enough to drive
the whole failure mode through. `ash-package.yml` is allowed to upload the wheel
and the sdist, so under a filename-keyed allowlist a pull request that adds a
SECOND upload to that same file (of the built container image, say) passes the
gate without a word. That is precisely the thing this is here to catch.

So the key is the site AND what the site publishes:

    (file, kind, action, publishes)

where `publishes` is built from the inputs that determine which bytes leave the
runner -- `name` and `path` for an upload, `path` and `key` for a cache, the
truthy cache inputs for an action with a built-in cache, plus the unset control
input for an action whose cache is on by default (setup-uv). Consequences:

  * A new upload inside an already-allowlisted file has a `publishes` nobody
    listed, so it is unexpected and fails.
  * Repointing an allowlisted upload at a different path or name fails twice
    over: the new key is unexpected, and the listed key is now orphaned.
  * A second upload with byte-identical inputs fails too, because entries carry
    an occurrence count and the census counts duplicates.

The check runs in BOTH directions. An allowlist entry that matches nothing is
itself a failure, for two reasons. An entry whose site was deleted should not
outlive it, same as the exemption staleness test in assert-actions-pinned.mjs.
And more importantly, it is this script's positive control against the worst
outcome available to a gate like this one -- a scanner that has quietly stopped
matching anything and reports a clean tree by finding nothing at all. If the
detector breaks, every entry orphans at once and the census goes red, rather than
green.

Step names are reported but deliberately not part of the key: renaming a step
does not change which bytes it publishes, and a gate that reddens on a reworded
label trains people to ignore it.

HOW TO ADD AN ENTRY

Do the decision first, then the entry. The entry is the record of the decision,
not a way around the gate. Ask whether the bytes are something this project
built -- a wheel, an sdist, a container image, a compiled binary, a bundle -- or
something already public that merely passed through a runner, like a third-party
package download or a vulnerability database. The first kind is a new
distribution channel for this project and needs to be a considered choice, with
whatever content gating that implies. The second kind distributes nothing this
project owns.

Then add a Surface to ALLOWLIST below with a `reason` that says which of those it
is and why it is acceptable. Copy the exact `kind`, `action` and `publishes`
strings out of the census this script prints; they have to match verbatim.

If the decision depends on WHEN the step runs -- "failure evidence only" -- set
`required_condition` on the entry too, so the step's `if:` is held to it. See the
first known limitation below for what that does and does not cover.

KNOWN LIMITATIONS

  * The key covers WHAT is published, not WHEN. Flipping `if: failure()` to
    unconditional widens an accepted upload from red runs to every run, and the
    key alone will not notice, because the bytes are the same bytes and were
    already accepted as publishable. An entry whose reason depends on the
    condition closes that by setting `required_condition`: the matched step's
    step-level `if:` must then have that exact term as a top-level `&&` conjunct.
    The parse is deliberately narrow -- any `||`, any parenthesised group other
    than an empty call such as `failure()`, or a nested `${{` fails the check --
    so a condition it cannot read is reported rather than trusted. Entries
    without `required_condition` are still keyed on WHAT only, and a job-level
    `if:` is not read.
  * Release assets are censused too, as kind `release-asset`: a `run:` line that
    calls `gh release create` or `gh release upload`, keyed on the positional
    arguments after the tag (the files it attaches), and the release-publishing
    actions (`softprops/action-gh-release`, `ncipollo/release-action`,
    `actions/upload-release-asset`), keyed on their file inputs. A release has a
    human on the button, but which files it attaches is decided in YAML, and a
    second attach site or a widened glob is the same mistake as a second upload.
    The set of files a glob matches is not this script's business:
    packaging/release-assets.py holds the staged directory to a fixed list before
    the one allowlisted site attaches it. A `gh` call built at run time (a
    variable holding "release", an alias, a script file) is invisible here, the
    same limit as the `run:` steps described below.
  * Expressions are compared as source text. Two spellings of the same artifact
    name are two different keys, which costs a false failure on a pure
    refactor -- the cheaper direction to be wrong in.
  * Two non-`uses:` shapes are read as well, both for ASH's own image layer
    cache: a step that exports ACTIONS_RUNTIME_TOKEN to later steps, and any
    `env:` setting ASH_GHA_BUILD_CACHE_EXPORT to something other than none.
    Otherwise only `uses:` steps are read. A third-party action can upload or cache from
    inside its own implementation, which is invisible here, and a `run:` step
    holding ACTIONS_RUNTIME_TOKEN can call the artifact API directly. Neither is
    reachable by a static census of this tree; what covers them is that adding a
    new action or a new token-holding step is itself a visible diff, and that
    every action is sha-pinned by assert-actions-pinned.mjs so the code behind a
    reviewed `uses:` cannot change underneath it.
  * Scope is `.github/`. That is the only place GitHub reads workflows and
    composite actions from, so it is the whole attack surface for this, but a
    check that publishes from outside Actions entirely is a different problem.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import shlex
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml

# Repository root, from this file's location: .github/scripts/<this>.
REPO_ROOT = Path(__file__).resolve().parents[2]
GITHUB_DIR = REPO_ROOT / ".github"

KIND_UPLOAD = "upload-artifact"
KIND_CACHE = "cache"
KIND_BUILTIN_CACHE = "builtin-cache"
# ASH's own container build writing image layers to the Actions cache (buildx
# type=gha, in automated_security_helper/interactions/run_ash_container.py). No
# `uses:` line does that, so two things are censused instead: a step that hands
# the cache credentials to later steps, which is what makes any layer export
# possible, and a step that sets ASH_GHA_BUILD_CACHE_EXPORT, which decides how
# much is exported.
KIND_CACHE_ACCESS_HANDOFF = "cache-access-handoff"
KIND_LAYER_CACHE = "layer-cache"
# Files attached to a GitHub Release. See KNOWN LIMITATIONS.
KIND_RELEASE_ASSET = "release-asset"
_GH_RELEASE = re.compile(r"(?:^|[\s;&|(])gh\s+release\s+(create|upload)\b(.*)$")
# gh release flags that take a value, so the value is not read as a file to attach.
_GH_RELEASE_VALUE_FLAGS = frozenset(
    {
        "--repo",
        "-R",
        "--target",
        "--title",
        "-t",
        "--notes",
        "-n",
        "--notes-file",
        "-F",
        "--discussion-category",
        "--notes-start-tag",
    }
)
# Actions that attach files to a release, and the inputs that name the files.
_RELEASE_ACTIONS: dict[str, tuple[str, ...]] = {
    "action-gh-release": ("files",),
    "release-action": ("artifacts",),
    "upload-release-asset": ("asset_path", "asset_name"),
}
_LAYER_CACHE_ENV = "ASH_GHA_BUILD_CACHE_EXPORT"
_LAYER_CACHE_ACTION = "ash build (buildx type=gha)"

# Injected by the line-tracking loader below; never a real workflow key.
LINE_KEY = "__line__"

# Input names that are cache controls on any action, not just the ones this repo
# happens to use today. Matched as a hyphen-delimited token so `enable-cache`,
# `cache-dependency-path`, `cache-to` and a bare `cache` all hit, without having
# to enumerate every setup-* action's spelling of it. `setup-uv`'s `enable-cache`
# and `setup-node`'s `cache:` are the two live cases; `docker/build-push-action`'s
# `cache-to: type=gha` would be a third, and is the one that would otherwise let
# a built container image into the public cache without a new `uses:` line for a
# reviewer to notice.
CACHE_INPUT_NEGATIVES = frozenset(
    {"no-cache", "nocache", "skip-cache", "disable-cache", "cache-disabled"}
)

# Values that mean "no cache" rather than a cache. `cache: ''` is how setup-node
# spells disabled, and it is a string, so a plain truthiness test on the YAML
# value is not enough on its own.
FALSEY_INPUT_VALUES = frozenset({"", "false", "no", "none", "off", "0"})

# Actions whose built-in cache is ON when the step says nothing about it, keyed by
# action, giving the input that controls it and how the census renders the unset
# case. Without this, a step with no `with:` block reads as "no cache inputs, so no
# cache", which is the opposite of what the runner does. setup-uv's `enable-cache`
# defaults to "auto", and auto caches on GitHub-hosted runners for every event
# except release, tag push, pull_request_target and workflow_run, so an ordinary
# push or pull request publishes a cache from a step whose YAML shows none.
DEFAULT_ON_CACHE_INPUTS: dict[str, tuple[str, str]] = {
    "astral-sh/setup-uv": ("enable-cache", "auto(default)"),
}


@dataclass(frozen=True)
class Surface:
    """One place bytes can leave a runner for a publicly readable store."""

    file: str
    kind: str
    action: str
    publishes: str

    def as_key(self) -> tuple[str, str, str, str]:
        return (self.file, self.kind, self.action, self.publishes)


@dataclass(frozen=True)
class Entry:
    """An allowlisted Surface, plus the decision that put it here."""

    file: str
    kind: str
    action: str
    publishes: str
    reason: str
    count: int = 1
    # When set, every censused step matching this entry must have this term as a
    # top-level `&&` conjunct of its `if:`. See KNOWN LIMITATIONS.
    required_condition: str = ""

    def as_key(self) -> tuple[str, str, str, str]:
        return (self.file, self.kind, self.action, self.publishes)


@dataclass(frozen=True)
class Found:
    """A Surface as measured, with enough context to write a useful message."""

    surface: Surface
    step: str
    line: int
    # The step's `if:` as source text, or "" when it has none.
    condition: str = ""


# ---------------------------------------------------------------------------
# THE ALLOWLIST
#
# Every entry is a decision someone took. See "HOW TO ADD AN ENTRY" above.
#
# The `publishes` strings are copied verbatim out of the census, expressions and
# all, which is why several of them are long. Do not tidy them.
# ---------------------------------------------------------------------------
_UPLOAD = "actions/upload-artifact"
_SETUP_UV = "astral-sh/setup-uv"
_SETUP_NODE = "actions/setup-node"

_UV_CACHE_REASON = (
    "uv's download cache. Holds third-party packages already published on PyPI, "
    "so it redistributes nothing this project builds -- anyone who can read the "
    "cache could already have fetched the same wheels from the index."
)
_UV_SPLIT_CACHE_REASON = (
    _UV_CACHE_REASON + " Restored with actions/cache/restore except on a tag push, "
    "and saved from a push to main only, in place of setup-uv's own cache, which "
    "restored on every event and saved from every ref. The workflows that use it "
    "run on tag pushes, and a tag run reads no cache entry."
)
_NPM_CACHE_REASON = (
    "npm's download cache, keyed on a committed lockfile. Holds third-party "
    "packages already published on the npm registry, so it redistributes nothing "
    "this project builds. Restored everywhere and saved from a push to main only, "
    "so a pull request never writes an entry another run reads."
)
_PIP_HTTP_CACHE_REASON = (
    "pip's HTTP download cache: responses fetched from PyPI, third-party packages "
    "already published there. Only the http directories are cached, never pip's "
    "wheels/ directory, which is where a locally built wheel -- ASH's own -- would "
    "land. Restored everywhere, saved from a push to main only."
)
_MCP_INSPECTOR_NPM_REASON = (
    "npm's download cache for the pinned @modelcontextprotocol/inspector install: "
    "third-party tarballs from the npm registry, keyed on the pinned version. "
    "Restored everywhere, saved from a push to main only."
)
_LAYER_CACHE_REASON = (
    "ASH's container image build layers, exported to the Actions cache by buildx "
    "type=gha. MAINTAINER DECISION (2026-10-06): the operator accepted that these "
    "layers are restorable by any workflow run in this repository, approved fork "
    "pull requests included, in exchange for warm image builds -- for build layers "
    "only. Exported only from pushes to main (mode=max); pull requests read and "
    "never write. Pushing the image to any registry, and uploading the image or a "
    "tarball of it as an artifact, remain forbidden."
)
_TOOL_ASSET_CACHE_REASON = (
    "Release assets of the scanner tools pinned by sha256 in "
    "automated_security_helper/utils/tool_downloads.py: public upstream releases, "
    "downloaded and verified by install_pinned_tool. MAINTAINER DECISION "
    "(2026-10-07): the operator approved caching these digest-pinned public "
    "binaries. Assets only -- never extracted binaries, install receipts, ASH's own "
    "wheel or its image. Re-verified against the pin on every use, and deleted and "
    "re-downloaded on a mismatch. Keyed on the pin table's hash; saved from a push "
    "to main only."
)
_OPENGREP_CACHE_REASON = (
    "The OpenGrep release binary, downloaded from the upstream GitHub release at the "
    "version pinned in utils/tool_downloads.py. A third-party binary that is already "
    "publicly downloadable, not one this project produced. Digest verified against "
    "that pin before it is cached and again after it is restored, before it reaches "
    "PATH; a restored copy that does not match is deleted and re-downloaded. Keyed on "
    "the ISO week, and saved from a push to the default branch only."
)
_BASE_IMAGE_CACHE_REASON = (
    "Third-party public image, byte-identical to docker.io at the pinned digest, "
    "hash-verified before use; saved on main only; approved by the maintainer. The "
    "Dockerfile's base image (ARG BASE_IMAGE at ARG BASE_IMAGE_DIGEST) as an OCI layout: "
    "prepull-base-image checks every blob against its sha256 and the index against the pin "
    "before any build reads it, and discards the entry on any mismatch."
)

_MKDOCS_PRIVACY_CACHE_REASON = (
    "Third-party assets the published docs site already links to (the "
    "mermaid bundle, twemoji images, a star-history badge), fetched from "
    "their public CDNs by mkdocs-material's privacy plugin. Nothing this "
    "project builds goes in it; the site that embeds them is itself public."
)

_GRYPE_DB_CACHE_REASON = (
    "grype's published vulnerability database, fetched from upstream and "
    "re-verified by grype on start. Third-party public data; this project builds "
    "none of it. Saved from the default branch only, and keyed on a time bucket "
    "derived from the bound grype enforces (automated_security_helper/utils/"
    "content_databases.py), so no restored copy is older than that bound."
)

_RELEASE_ASSET_ARTIFACT_REASON = (
    "BUILT BYTES, and a release asset (operator decision O3: the native packages and "
    "IDE artifacts may be public Release downloads; the container image never). "
    "This upload carries the file the job built, gated and, where the format allows, "
    "installed and exercised, to .github/workflows/ash-release-assets.yml, which "
    "gates it again on these bytes and stages it. Each package wraps the one ASH "
    "wheel the build job already publishes, held to that by its contents gate "
    "(packaging/assert-package-payload.py, packaging/assert-package-contents.py, "
    "vsix-contents.ts, editors/jetbrains/assert-plugin-zip-contents.py), so it "
    "widens the format and not the content. One file per artifact, N only, never "
    "an N-1 build; if-no-files-found: error and 14-day retention."
)

ALLOWLIST: tuple[Entry, ...] = (
    # -- GitHub Release attachments ----------------------------------------
    Entry(
        file=".github/workflows/ash-tag-on-merge.yml",
        kind=KIND_RELEASE_ASSET,
        action="gh release create",
        publishes="assets=${NOTES_ARGS[@]+${NOTES_ARGS[@]}}|release-assets/*",
        reason=(
            "THE RELEASE. The one place files are attached to a GitHub Release, in "
            "the job that runs only when a chore(release): pull request merges. "
            "release-assets/ is the directory the step before it held to "
            "packaging/release-assets.py (exactly the listed assets, digests equal to "
            "the ones computed after their gates) and attested. NOTES_ARGS expands to "
            "--notes and the changelog text, never a file."
        ),
    ),
    # -- Digest-pinned scanner release assets (maintainer decision) ----------
    Entry(
        file=".github/actions/tool-download-cache/action.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=${{ runner.temp }}/ash-tool-downloads key=ash-tool-asse"
            "ts-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('automated_security_helper/utils/tool_downloads.py') }}"
        ),
        reason=_TOOL_ASSET_CACHE_REASON,
    ),
    Entry(
        file=".github/actions/tool-download-cache/action.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=${{ runner.temp }}/ash-tool-downloads key=ash-tool-asse"
            "ts-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('automated_security_helper/utils/tool_downloads.py') }}"
        ),
        reason=_TOOL_ASSET_CACHE_REASON,
    ),
    # -- ASH image build layers in the Actions cache (maintainer decision) ------
    Entry(
        file=".github/actions/run-scan-test/action.yml",
        kind=KIND_CACHE_ACCESS_HANDOFF,
        action="actions/github-script",
        publishes=("exports ACTIONS_RUNTIME_TOKEN to later steps"),
        reason=_LAYER_CACHE_REASON
        + " The hand-off the docker container legs build with: step outputs that only"
        " the build steps map into their env.",
    ),
    Entry(
        file=".github/actions/run-scan-test/action.yml",
        kind=KIND_LAYER_CACHE,
        action="ash build (buildx type=gha)",
        publishes=(
            "ASH_GHA_BUILD_CACHE_EXPORT=${{ (github.event_name == 'push' && github.ref == 'refs/heads/main') && 'max' || 'none' }}"
        ),
        reason=_LAYER_CACHE_REASON + " max on a push to main, none otherwise.",
    ),
    Entry(
        file=".github/workflows/ash-unified-ci.yml",
        kind=KIND_CACHE_ACCESS_HANDOFF,
        action="actions/github-script",
        publishes=("exports ACTIONS_RUNTIME_TOKEN to later steps"),
        reason=_LAYER_CACHE_REASON
        + " The warm-image-layers job, which runs on pushes to main only.",
    ),
    Entry(
        file=".github/workflows/ash-unified-ci.yml",
        kind=KIND_LAYER_CACHE,
        action="ash build (buildx type=gha)",
        publishes=("ASH_GHA_BUILD_CACHE_EXPORT=max"),
        reason=_LAYER_CACHE_REASON
        + " The warm-image-layers job, which runs on pushes to main only.",
    ),
    # -- Third-party download caches added by the per-job cache pass ---------
    Entry(
        file=".github/actions/setup-ash/action.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=${{ steps.pip-cache-dir.outputs.dir }}/http-v2|"
            "${{ steps.pip-cache-dir.outputs.dir }}/http "
            "key=pip-http-${{ runner.os }}-${{ runner.arch }}-py${{ inputs.python-version }}-"
            "${{ hashFiles('pyproject.toml') }}"
        ),
        reason=_PIP_HTTP_CACHE_REASON,
    ),
    Entry(
        file=".github/actions/setup-ash/action.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=${{ steps.pip-cache-dir.outputs.dir }}/http-v2|"
            "${{ steps.pip-cache-dir.outputs.dir }}/http "
            "key=pip-http-${{ runner.os }}-${{ runner.arch }}-py${{ inputs.python-version }}-"
            "${{ hashFiles('pyproject.toml') }}"
        ),
        reason=_PIP_HTTP_CACHE_REASON,
    ),
    Entry(
        file=".github/actions/validate-mcp/action.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=${{ steps.inspector.outputs.npm-cache }} "
            "key=npm-mcp-inspector-${{ runner.os }}-${{ runner.arch }}-"
            "${{ steps.inspector.outputs.version }}"
        ),
        reason=_MCP_INSPECTOR_NPM_REASON,
    ),
    Entry(
        file=".github/actions/validate-mcp/action.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=${{ steps.inspector.outputs.npm-cache }} "
            "key=npm-mcp-inspector-${{ runner.os }}-${{ runner.arch }}-"
            "${{ steps.inspector.outputs.version }}"
        ),
        reason=_MCP_INSPECTOR_NPM_REASON,
    ),
    # -- Artifact uploads -----------------------------------------------------
    #
    # Three entries here publish something this project BUILT: the wheel and
    # sdist, the .msix, and the .vsix. Everything else is a report, a test
    # result, or scan output kept as evidence from a red run.
    Entry(
        file=".github/workflows/ash-package.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=ash-package-${{ github.sha }}-attempt-${{ github.run_attempt }} "
            "path=dist/*.whl|dist/*.tar.gz"
        ),
        reason=(
            "DELIBERATE, and the one distribution channel this project has. The "
            "packaging plan installs from a CI-built wheel because the project is "
            "not on PyPI and the name is taken there, so this upload is the "
            "install source rather than a debugging convenience. Its contents are "
            "gated separately by .github/scripts/assert-artifact-contents.py, "
            "which self-tests before the build and then checks the real artifact. "
            "Widening what this publishes is a packaging decision, not a CI one."
        ),
    ),
    Entry(
        file=".github/workflows/ash-package.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=ash-msix-${{ github.sha }}-attempt-${{ github.run_attempt }} "
            "path=build/msix/*.msix"
        ),
        reason=(
            "BUILT BYTES: the MSIX package the msix job builds, installs and scans "
            "with on windows-latest. Uploaded because packaging/winget/ declares this "
            "filename as its installer, and this is the only place the code that "
            "decides the filename produces it. The package wraps the same wheel the "
            "build job already publishes above plus the launcher compiled from "
            "packaging/msix/AshLauncher.cs, so it widens the format, not the "
            "content. Signed with the repository's MSIX_SIGNING_PFX secret when set "
            "and a throwaway self-signed certificate otherwise, which Windows will "
            "not trust. ash-release-assets.yml stages this file as the release's "
            ".msix and renders the winget manifests from it (operator decision O3). "
            "Exactly one .msix is uploaded, asserted by verify-on-windows.ps1, with "
            "if-no-files-found: error and 14-day retention."
        ),
    ),
    Entry(
        file=".github/workflows/ash-package.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=ash-nupkg-${{ github.sha }}-attempt-${{ github.run_attempt }} "
            "path=build/choco-out/*.nupkg"
        ),
        reason=_RELEASE_ASSET_ARTIFACT_REASON
        + " The Chocolatey .nupkg the chocolatey job installed, scanned with, "
        "upgraded to and uninstalled.",
    ),
    Entry(
        file=".github/workflows/ash-package.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=ash-flatpak-${{ github.sha }}-attempt-${{ github.run_attempt }} "
            "path=build/flatpak-out/*.flatpak"
        ),
        reason=_RELEASE_ASSET_ARTIFACT_REASON
        + " The N Flatpak bundle the flatpak job installed and updated to; the N-1 "
        "bundle sits under prev/, which the glob does not descend into.",
    ),
    Entry(
        file=".github/workflows/ash-native-packages.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=ash-${{ matrix.family }}-${{ github.sha }}-attempt-${{ github.run_attempt }} "
            "path=build/native-packages/*.${{ matrix.family }}"
        ),
        reason=_RELEASE_ASSET_ARTIFACT_REASON
        + " The .deb from the Debian 12 assert leg and the .rpm from the Amazon "
        "Linux 2023 assert leg (matrix.asset), each uploaded only after that leg "
        "installed, scanned with and purged it.",
        required_condition="matrix.asset",
    ),
    Entry(
        file=".github/workflows/ash-release-assets.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=ash-release-vsix-${{ github.sha }}-attempt-${{ github.run_attempt }} "
            "path=build/vsix/*.vsix"
        ),
        reason=_RELEASE_ASSET_ARTIFACT_REASON
        + " The .vsix, after the no-runtime-dependency check and vsix-contents.ts.",
    ),
    Entry(
        file=".github/workflows/ash-release-assets.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=ash-release-jetbrains-${{ github.sha }}-attempt-${{ github.run_attempt }} "
            "path=editors/jetbrains/build/distributions/*.zip"
        ),
        reason=_RELEASE_ASSET_ARTIFACT_REASON
        + " The JetBrains plugin zip, after assertDistributionContents and "
        "assert-plugin-zip-contents.py.",
    ),
    Entry(
        file=".github/workflows/ash-release-assets.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=ash-release-assets-${{ github.sha }}-attempt-${{ github.run_attempt }} "
            "path=release-assets/"
        ),
        reason=_RELEASE_ASSET_ARTIFACT_REASON
        + " The whole staged set, uploaded only after packaging/release-assets.py "
        "passed every gate on it: the files above plus the .mcpb and the winget "
        "manifests rendered for the staged .msix. ash-tag-on-merge.yml downloads "
        "it in the same run and attaches exactly these bytes.",
    ),
    Entry(
        file=".github/workflows/ash-vscode-extension.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes="name=ash-vscode-extension path=editors/vscode/ash-vscode.vsix",
        reason=(
            "BUILT BYTES: the VS Code extension archive packaged from editors/vscode. "
            "The step before it reads the archive with an independent zip reader and "
            "fails on any member under node_modules/ (no bundled third-party code) "
            "and on a missing extension/out/extension.js, so what is published is the "
            "extension's own compiled TypeScript and manifest. Not published to the "
            "Marketplace from here; 7-day retention, if-no-files-found: error."
        ),
    ),
    Entry(
        file=".github/workflows/ash-vscode-extension.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=vscode-visual-snapshots-${{ github.sha }}-attempt-${{ github.run_attempt }} "
            "path=${{ runner.temp }}/visual-snapshots/"
        ),
        reason=(
            "Failure evidence only (if: failure()): PNG screen captures of a VS Code "
            "window showing the extension's UI over the committed test fixture, and a "
            "diff image per mismatched scenario. The same pictures as the baselines "
            "committed under editors/vscode/test/visual/__snapshots__/, so nothing in "
            "them is not already in the repository. No built code. 7-day retention; "
            "if-no-files-found: warn because a failure before the first capture (the "
            "image build) leaves nothing to upload, and the job is already red."
        ),
    ),
    Entry(
        file=".github/workflows/ash-jetbrains-ci.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=jetbrains-reports-${{ github.sha }}-attempt-${{ github.run_attempt }} "
            "path=editors/jetbrains/build/reports/|editors/jetbrains/build/test-results/"
        ),
        reason=(
            "Failure evidence only (if: failure()): Gradle's test and coverage "
            "reports for the JetBrains plugin. Named report directories, not "
            "build/libs or build/distributions, so the plugin jar is not in it."
        ),
    ),
    Entry(
        file=".github/workflows/ash-jetbrains-ci.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=jetbrains-visual-${{ github.sha }}-attempt-${{ github.run_attempt }} "
            "path=editors/jetbrains/build/ui-snapshots/|editors/jetbrains/build/ui-logs/|"
            "editors/jetbrains/build/reports/tests/uiTest/"
        ),
        reason=(
            "Failure evidence only (if: failure()): the visual suite's rendered "
            "scenes and diff images, the IDE log and the test report, for a pixel "
            "difference a job log cannot show. Screenshots of a fixture project "
            "and named build directories, not build/libs or build/distributions."
        ),
    ),
    Entry(
        file=".github/actions/run-scan-test/action.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=ash_output-${{ inputs.os }}-${{ inputs.method }}-"
            "${{ inputs.config-file }}${{ inputs.oci-runner && "
            "format('-{0}', inputs.oci-runner) || '' }}"
            "${{ inputs.offline == 'true' && '-offline' || '' }} "
            "path=.ash/ash_output"
        ),
        reason=(
            "Scan reports -- SARIF, JSON, HTML -- from scanning this repository's "
            "own tree with the build under test. Findings about public code, not "
            "an executable."
        ),
    ),
    Entry(
        file=".github/workflows/run-ash-security-scan.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes="name=ash_output path=${{ inputs.output-dir }}",
        reason=(
            "Scan reports, in the reusable workflow consumers call. The bytes "
            "belong to the calling repository's scan and are published into the "
            "caller's run, not this one; on this repository the workflow only "
            "runs against this public tree."
        ),
    ),
    Entry(
        file=".github/actions/run-unit-tests/action.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=test-results-${{ inputs.os }}-"
            "${{ steps.runner-arch.outputs.label }}-"
            "py${{ inputs.python-version }} path=test-results/"
        ),
        reason=(
            "Test results and coverage data. No build output. The arch component "
            "of the name moved from an `arch` input to a label this action derives "
            "from RUNNER_ARCH, so the same bytes from the same path are published "
            "under the same names; only the source of the arch string changed."
        ),
    ),
    Entry(
        file=".github/workflows/ash-typescript-ci.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=ts-coverage-${{ matrix.package }} path=${{ matrix.dir }}/coverage/"
        ),
        reason=(
            "Coverage report for the TypeScript packages. Instrumented-line data "
            "over tracked source, not the compiled bundle. The path moved from "
            "deploy/${{ matrix.package }} to ${{ matrix.dir }} when editors/vscode "
            "joined the matrix beside deploy/cdk and deploy/cdk-constructs; the "
            "directory is still each package's own coverage/ output."
        ),
    ),
    Entry(
        file=".github/workflows/ash-unified-ci.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes="name=moto-server-suite-report path=test-results/moto-server-suite.junit.xml",
        reason="One JUnit XML report from the moto-server suite.",
    ),
    Entry(
        file=".github/workflows/ash-unified-ci.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes="name=integration-suite-report path=test-results/integration.junit.xml",
        reason="One JUnit XML report from the integration suite.",
    ),
    Entry(
        file=".github/workflows/ash-unified-ci.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes="name=sandbox-escape-report-${{ matrix.os }} path=test-results/sandbox.junit.xml",
        reason="Failure evidence only: one JUnit XML report from the sandbox escape suite.",
    ),
    Entry(
        file=".github/workflows/ash-unified-ci.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=sandbox-scanner-parity "
            "path=${{ runner.temp }}/sandbox-parity.json|${{ runner.temp }}/ash-sandbox-parity-*"
        ),
        reason=(
            "Failure evidence only: the parity report and the fixture's scan output "
            "with and without the sandbox. Fixture and reports, not build output."
        ),
    ),
    Entry(
        file=".github/workflows/ash-unified-ci.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=external-target-scan-evidence-${{ matrix.os }} "
            "path=${{ runner.temp }}/ash-external-target-*"
        ),
        reason=(
            "Failure evidence only: the fixture tree and scan output the gate "
            "keeps on disk when it goes red, so the failure messages point at "
            "bytes that still exist. Fixture and reports, not build output."
        ),
    ),
    Entry(
        file=".github/workflows/ash-unified-ci.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=multi-project-attribution-evidence-${{ matrix.os }} "
            "path=${{ runner.temp }}/ash-multi-project-*"
        ),
        reason="Failure evidence only; the sibling of external-target-scan-evidence.",
    ),
    Entry(
        file=".github/workflows/ash-iac-drift.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=cdk-synth-assembly "
            "path=deploy/cdk/cdk.out|${{ runner.temp }}/cdk-template-drift.diff"
        ),
        reason=(
            "Failure evidence only: the synthesized CloudFormation assembly and "
            "the diff against the committed templates, when they disagree. "
            "Templates rendered from tracked source. Note that a CDK assembly "
            "CAN carry staged asset bundles, so an app that starts bundling a "
            "Lambda from local source would widen this without changing the path "
            "-- which is a reason to re-read this entry if deploy/cdk grows asset "
            "staging, not a reason it is unacceptable today."
        ),
    ),
    Entry(
        file=".github/workflows/ash-iac-drift.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes=(
            "name=cdk-nag-reports "
            "path=deploy/cdk/cdk.out/*-NagReport.csv|"
            "deploy/cdk/cdk.out/*-NagReport.json|"
            "deploy/cdk/cdk.out/validation-report.json|"
            "deploy/cdk/cdk.out/manifest.json"
        ),
        reason=(
            "Failure evidence only, and narrowed to named report files inside the "
            "assembly rather than the whole of cdk.out."
        ),
    ),
    Entry(
        file=".github/workflows/ash-kubernetes-operator.yml",
        kind=KIND_UPLOAD,
        action=_UPLOAD,
        publishes="name=ash-operator-e2e-log path=${{ env.OPERATOR_DIR }}/e2e.log",
        reason=(
            "Failure evidence only (if: failure()), 7-day retention: the pytest -v "
            "log of the Kubernetes operator's kind end-to-end run. Test names, "
            "assertion output and the tail of kubectl and operator logs from a "
            "throwaway cluster, scanning committed fixtures whose only credential is "
            "AWS's documentation example key. One text file, not build output; the "
            "operator and ASH images stay on the runner."
        ),
        required_condition="failure()",
    ),
    # -- Standalone caches ----------------------------------------------------
    # The grype database: restored everywhere, saved only from a push to the default
    # branch, keyed on the time bucket content_databases.py derives from the bound grype
    # enforces. Four sites, one entry: the reusable scan workflow restores and (for a
    # caller's default-branch push) saves; ash-repo-scan.yml's main-only job is this
    # repository's writer, since the scan itself does not run on a push here.
    Entry(
        file=".github/workflows/run-ash-security-scan.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=~/.cache/grype/db "
            "key=grype-db-${{ runner.os }}-${{ steps.cachekeys.outputs.grype-db }}"
        ),
        reason=_GRYPE_DB_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/run-ash-security-scan.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=~/.cache/grype/db "
            "key=grype-db-${{ runner.os }}-${{ steps.cachekeys.outputs.grype-db }}"
        ),
        reason=_GRYPE_DB_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-repo-scan.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=~/.cache/grype/db "
            "key=grype-db-${{ runner.os }}-${{ steps.key.outputs.grype-db }}"
        ),
        reason=_GRYPE_DB_CACHE_REASON + " A lookup-only probe; it downloads nothing.",
    ),
    Entry(
        file=".github/workflows/ash-repo-scan.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=~/.cache/grype/db "
            "key=grype-db-${{ runner.os }}-${{ steps.key.outputs.grype-db }}"
        ),
        reason=_GRYPE_DB_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/run-ash-security-scan.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=~/.opengrep/cli/latest "
            "key=opengrep-${{ runner.os }}-${{ steps.cachekeys.outputs.week }}"
        ),
        reason=_OPENGREP_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/run-ash-security-scan.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=~/.opengrep/cli/latest "
            "key=opengrep-${{ runner.os }}-${{ steps.cachekeys.outputs.week }}"
        ),
        reason=_OPENGREP_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-repo-scan.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=~/.opengrep/cli/latest "
            "key=opengrep-${{ runner.os }}-${{ steps.key.outputs.week }}"
        ),
        reason=_OPENGREP_CACHE_REASON + " A lookup-only probe; it downloads nothing.",
    ),
    Entry(
        file=".github/workflows/ash-repo-scan.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=~/.opengrep/cli/latest "
            "key=opengrep-${{ runner.os }}-${{ steps.key.outputs.week }}"
        ),
        reason=_OPENGREP_CACHE_REASON,
    ),
    # mkdocs-material's privacy plugin cache: the external assets the docs site
    # references, downloaded so --strict does not fail on a transient fetch. Both jobs
    # of the workflow restore it, hence count=2; only deploy-docs saves it, gated to a
    # push to main.
    Entry(
        file=".github/workflows/ash-repo-docs.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=.cache/plugin/privacy "
            "key=mkdocs-privacy-${{ hashFiles('uv.lock', 'mkdocs.yml') }}"
        ),
        count=2,
        reason=_MKDOCS_PRIVACY_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-repo-docs.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=.cache/plugin/privacy "
            "key=mkdocs-privacy-${{ hashFiles('uv.lock', 'mkdocs.yml') }}"
        ),
        reason=_MKDOCS_PRIVACY_CACHE_REASON,
    ),
    # The build base image, as a verified OCI layout. The only cache the maintainer has
    # approved for image bytes, and deliberately not ASH's own image or layers. Restore runs
    # on every run; save is gated to a push to refs/heads/main in the action itself, so a
    # pull request can read the entry and can never write one.
    Entry(
        file=".github/actions/prepull-base-image/action.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=${{ runner.temp }}/ash-base-image-oci "
            "key=${{ steps.key.outputs.key }}"
        ),
        reason=_BASE_IMAGE_CACHE_REASON,
    ),
    Entry(
        file=".github/actions/prepull-base-image/action.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=${{ runner.temp }}/ash-base-image-oci "
            "key=${{ steps.key.outputs.key }}"
        ),
        reason=_BASE_IMAGE_CACHE_REASON,
    ),
    # -- Built-in caches on setup-* actions -----------------------------------
    #
    # These are caches too, which is why they are censused: `enable-cache: true`
    # writes to the same publicly readable store as `actions/cache`, with no
    # `uses: actions/cache` line to notice in review.
    Entry(
        file=".github/actions/setup-ash/action.yml",
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_UV,
        publishes=(
            "enable-cache=true "
            "save-cache=${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
        ),
        reason=_UV_CACHE_REASON
        + " Saved from a push to main only; every other ref restores and writes nothing.",
    ),
    Entry(
        file=".github/workflows/ash-package.yml",
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_UV,
        publishes="enable-cache=true",
        count=3,
        reason=_UV_CACHE_REASON + " Three times: the build, msix and winget jobs.",
    ),
    Entry(
        file=".github/workflows/ash-actions-pinned.yml",
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_UV,
        publishes="enable-cache=true",
        reason=(
            _UV_CACHE_REASON + " Here it holds only PyYAML, for the "
            "`uv run --no-project --with pyyaml` workflow-structure check."
        ),
    ),
    Entry(
        file=".github/workflows/ash-vscode-extension.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=~/.npm "
            "key=npm-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('editors/vscode/package-lock.json') }}"
        ),
        reason=_NPM_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-vscode-extension.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=~/.npm "
            "key=npm-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('editors/vscode/package-lock.json') }}"
        ),
        reason=_NPM_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-unified-ci.yml",
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_UV,
        publishes="enable-cache=true save-cache=${{ github.event_name == 'push' }}",
        reason=_UV_CACHE_REASON
        + " Saved from a push only, which narrows who writes the entry: a pull"
        " request restores its base branch's copy and no longer saves its own.",
    ),
    Entry(
        file=".github/workflows/ash-upgrade-paths.yml",
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_UV,
        publishes="enable-cache=true",
        reason=_UV_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/run-ash-security-scan.yml",
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_UV,
        publishes="enable-cache=true save-cache=${{ github.event_name == 'push' }}",
        reason=_UV_CACHE_REASON
        + " Saved from a push only, which narrows who writes the entry: a pull"
        " request restores its base branch's copy and no longer saves its own.",
    ),
    Entry(
        file=".github/workflows/ash-iac-drift.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=~/.npm "
            "key=npm-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('deploy/cdk/package-lock.json') }}"
        ),
        count=2,
        reason=_NPM_CACHE_REASON + " Twice: the synth job and the cdk-nag job.",
    ),
    Entry(
        file=".github/workflows/ash-iac-drift.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=~/.npm "
            "key=npm-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('deploy/cdk-constructs/package-lock.json') }}"
        ),
        reason=_NPM_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-typescript-ci.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=~/.npm "
            "key=npm-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles(format('{0}/package-lock.json', matrix.dir)) }}"
        ),
        reason=(
            _NPM_CACHE_REASON + " Keyed on ${{ matrix.dir }} since editors/vscode "
            "joined deploy/cdk and deploy/cdk-constructs in the matrix."
        ),
    ),
    Entry(
        file=".github/workflows/ash-iac-drift.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=~/.npm "
            "key=npm-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('deploy/cdk/package-lock.json') }}"
        ),
        count=2,
        reason=_NPM_CACHE_REASON + " Twice: the synth job and the cdk-nag job.",
    ),
    Entry(
        file=".github/workflows/ash-iac-drift.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=~/.npm "
            "key=npm-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('deploy/cdk-constructs/package-lock.json') }}"
        ),
        reason=_NPM_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-typescript-ci.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=~/.npm "
            "key=npm-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles(format('{0}/package-lock.json', matrix.dir)) }}"
        ),
        reason=(
            _NPM_CACHE_REASON + " Keyed on ${{ matrix.dir }} since editors/vscode "
            "joined deploy/cdk and deploy/cdk-constructs in the matrix."
        ),
    ),
    Entry(
        file=".github/workflows/ash-agent-plugins-drift.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=~/.cache/uv "
            "key=uv-agent-plugins-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ash-agent-plugins/agentic-coding/transpiler/uv.lock') }}"
        ),
        reason=_UV_SPLIT_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-agent-plugins-drift.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=~/.cache/uv "
            "key=uv-agent-plugins-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ash-agent-plugins/agentic-coding/transpiler/uv.lock') }}"
        ),
        reason=_UV_SPLIT_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-cdk-extra-drift.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=~/.cache/uv "
            "key=uv-cdk-extra-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('uv.lock') }}"
        ),
        reason=_UV_SPLIT_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-cdk-extra-drift.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=~/.cache/uv "
            "key=uv-cdk-extra-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('uv.lock') }}"
        ),
        reason=_UV_SPLIT_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-repo-docs.yml",
        kind=KIND_CACHE,
        action="actions/cache/restore",
        publishes=(
            "path=~/.cache/uv "
            "key=uv-docs-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('uv.lock') }}"
        ),
        count=2,
        reason=_UV_SPLIT_CACHE_REASON
        + (
            " Twice: build-docs restores it, and deploy-docs only looks the key up"
            " (lookup-only: true, nothing downloaded) so its save can skip an entry"
            " main already wrote. deploy-docs publishes the site and restores nothing."
        ),
    ),
    Entry(
        file=".github/workflows/ash-repo-docs.yml",
        kind=KIND_CACHE,
        action="actions/cache/save",
        publishes=(
            "path=~/.cache/uv "
            "key=uv-docs-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('uv.lock') }}"
        ),
        reason=_UV_SPLIT_CACHE_REASON
        + " Saved by deploy-docs, the only job here that runs on main.",
    ),
)


class _LineLoader(yaml.SafeLoader):
    """SafeLoader that records the source line of every mapping it builds.

    The line numbers are only used to emit `::error file=,line=` annotations, so
    a failure lands on the offending step in the pull request diff instead of
    only in a log someone has to go and open.
    """


def _construct_mapping_with_line(loader: _LineLoader, node: yaml.MappingNode) -> dict:
    mapping = yaml.SafeLoader.construct_mapping(loader, node, deep=True)
    mapping[LINE_KEY] = node.start_mark.line + 1
    return mapping


_LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping_with_line,
)


def _normalize_action(uses: str) -> str:
    """Strip the ref from a `uses:` value.

    These workflows pin every action to a full commit sha with a `# vN` trailing
    comment, so matching on a version string would match nothing here. The
    comment is gone by the time PyYAML hands the value over; the sha is not, so
    drop everything from the first `@`.
    """
    return uses.split("@", 1)[0].strip()


def _is_falsey(value: object) -> bool:
    if value is None or value is False:
        return True
    if isinstance(value, str):
        return value.strip().lower() in FALSEY_INPUT_VALUES
    if isinstance(value, int) and not isinstance(value, bool):
        return value == 0
    return False


def _is_cache_input(name: str) -> bool:
    lowered = name.strip().lower()
    if lowered in CACHE_INPUT_NEGATIVES:
        return False
    return "cache" in lowered.split("-")


def _flatten(value: object) -> str:
    """Render an input value as one stable line.

    `path:` takes a multi-line list of globs, and an upload that gains or loses
    one of them is publishing something different, so every line has to survive
    into the key -- just not the incidental whitespace around them.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return "|".join(_flatten(item) for item in value)
    text = str(value)
    lines = [line.strip() for line in text.splitlines()]
    return "|".join(line for line in lines if line)


def _step_name(step: dict, action: str) -> str:
    name = step.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return f"(unnamed step, uses: {action})"


def _classify(step: dict) -> tuple[str, str] | None:
    """Return (kind, publishes) when this step publishes to a public store."""
    uses = step.get("uses")
    if not isinstance(uses, str) or not uses.strip():
        return None
    action = _normalize_action(uses)
    lowered = action.lower()
    segments = lowered.split("/")
    with_block = step.get("with")
    inputs = with_block if isinstance(with_block, dict) else {}

    # A release-publishing action. Keyed on the inputs that name the files.
    if segments[-1] in _RELEASE_ACTIONS:
        rendered = " ".join(
            f"{name}={_flatten(inputs.get(name)) or '(unset)'}"
            for name in _RELEASE_ACTIONS[segments[-1]]
        )
        return KIND_RELEASE_ASSET, rendered

    # An artifact upload, by any owner. Keyed on `name` and `path` because those
    # two decide what appears at the download URL.
    if segments[-1].startswith("upload-artifact"):
        name = _flatten(inputs.get("name")) or "(default: artifact)"
        path = _flatten(inputs.get("path")) or "(default: cwd)"
        return KIND_UPLOAD, f"name={name} path={path}"

    # A standalone cache. `actions/cache`, and its `/save` and `/restore`
    # subpaths, which are separate actions with the same effect on the store.
    if "cache" in segments:
        path = _flatten(inputs.get("path")) or "(unset)"
        key = _flatten(inputs.get("key")) or "(unset)"
        return KIND_CACHE, f"path={path} key={key}"

    # An action with a built-in cache. Skipped for local `uses:` values -- a
    # composite action or reusable workflow in this repository is itself scanned,
    # so its own cache steps are counted there, at the site that actually does
    # the caching. Counting the caller too would double-count it.
    if action.startswith(("./", ".\\")):
        return None
    cache_inputs = {
        str(key): value
        for key, value in inputs.items()
        if str(key) != LINE_KEY and _is_cache_input(str(key)) and not _is_falsey(value)
    }
    default_on = DEFAULT_ON_CACHE_INPUTS.get(lowered)
    if default_on is not None:
        control, unset_rendering = default_on
        # Input names are case-insensitive to the runner, so match them that way.
        if not any(str(key).strip().lower() == control for key in inputs):
            cache_inputs[control] = unset_rendering
    if cache_inputs:
        rendered = " ".join(
            f"{key}={_flatten(cache_inputs[key])}" for key in sorted(cache_inputs)
        )
        return KIND_BUILTIN_CACHE, rendered
    return None


def _walk_mappings(node: object):
    """Yield every mapping in the document, steps and jobs alike."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_mappings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_mappings(item)


def _layer_cache_sites(document: object):
    """(mapping, kind, action, publishes) for the two layer-cache site shapes.

    A step handing ACTIONS_RUNTIME_TOKEN to later steps is censused whatever it
    hands it over for: with that token in the environment, ASH's build exports
    layers at its default (min) without any ASH_GHA_BUILD_CACHE_EXPORT in sight.
    Both spellings count: GITHUB_ENV or core.exportVariable, which reach every later
    step, and GITHUB_OUTPUT or core.setOutput, which reach the steps that map the
    output into their `env:`. A step that only maps such an output is not a second
    site; the step that produced it is. And a
    mapping (step, job or workflow) whose `env` sets ASH_GHA_BUILD_CACHE_EXPORT to
    anything but none is censused with the value, expressions included.
    """
    for node in _walk_mappings(document):
        env = node.get("env")
        if isinstance(env, dict) and _LAYER_CACHE_ENV in env:
            value = _flatten(env[_LAYER_CACHE_ENV])
            if value.strip().lower() != "none":
                yield (
                    node,
                    KIND_LAYER_CACHE,
                    _LAYER_CACHE_ACTION,
                    f"{_LAYER_CACHE_ENV}={value}",
                )
        texts = [
            node.get("run"),
            (node.get("with") or {}).get("script")
            if isinstance(node.get("with"), dict)
            else None,
        ]
        for text in texts:
            if (
                isinstance(text, str)
                and "ACTIONS_RUNTIME_TOKEN" in text
                and any(
                    verb in text
                    for verb in (
                        "exportVariable",
                        "GITHUB_ENV",
                        "setOutput",
                        "GITHUB_OUTPUT",
                    )
                )
            ):
                # The revoke steps write an empty value back; those publish nothing.
                if re.search(r'echo "\$\{name\}=" >> "\$GITHUB_ENV"', text):
                    continue
                yield (
                    node,
                    KIND_CACHE_ACCESS_HANDOFF,
                    _normalize_action(str(node.get("uses", "run"))),
                    "exports ACTIONS_RUNTIME_TOKEN to later steps",
                )


def _gh_release_attachments(script: str) -> list[tuple[str, str]]:
    """(verb, publishes) for each `gh release create|upload` in a run: script.

    Continuation lines are joined first, so a command spread over several lines is
    one command. A line that is wholly a shell comment is skipped, so prose can
    name the command. The positional arguments after the tag are the files; a flag
    that takes a value has its value skipped, and anything dynamic (a variable, an
    array expansion) stays in the key verbatim, because it could add files.
    """
    joined = re.sub(r"\\\n", " ", script)
    sites: list[tuple[str, str]] = []
    for line in joined.splitlines():
        if line.strip().startswith("#"):
            continue
        match = _GH_RELEASE.search(line)
        if match is None:
            continue
        verb, rest = match.group(1), match.group(2)
        try:
            tokens = shlex.split(rest, comments=True)
        except ValueError:
            tokens = rest.split()
        positional: list[str] = []
        skip_next = False
        for token in tokens:
            if skip_next:
                skip_next = False
                continue
            if token in {";", "&&", "||", "|"}:
                break
            if token.startswith("-"):
                if "=" not in token and token in _GH_RELEASE_VALUE_FLAGS:
                    skip_next = True
                continue
            positional.append(token)
        files = positional[1:]
        sites.append((verb, f"assets={'|'.join(files) or '(none)'}"))
    return sites


def _release_sites(document: object):
    """(mapping, kind, action, publishes) for every gh release attach in run: text."""
    for node in _walk_mappings(document):
        text = node.get("run")
        if not isinstance(text, str) or "gh" not in text:
            continue
        for verb, publishes in _gh_release_attachments(text):
            yield node, KIND_RELEASE_ASSET, f"gh release {verb}", publishes


def _walk_steps(node: object):
    """Yield every mapping that carries a `uses:`, wherever it sits.

    Workflows put steps under `jobs.<id>.steps`, composite actions put them under
    `runs.steps`, and a reusable workflow call is a `uses:` on the job itself. A
    recursive walk covers all three without this script needing to know which
    shape of file it is reading, which also means a new shape does not silently
    stop being censused.
    """
    if isinstance(node, dict):
        if isinstance(node.get("uses"), str):
            yield node
        for value in node.values():
            yield from _walk_steps(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_steps(item)


def scan_text(rel_path: str, text: str) -> list[Found]:
    """Census one YAML document's publishing sites."""
    try:
        documents = list(yaml.load_all(text, Loader=_LineLoader))
    except yaml.YAMLError as exc:
        raise SystemExit(f"{rel_path}: could not be parsed as YAML: {exc}") from exc
    found: list[Found] = []
    for document in documents:
        for step in _walk_steps(document):
            classified = _classify(step)
            if classified is None:
                continue
            kind, publishes = classified
            action = _normalize_action(step["uses"])
            found.append(
                Found(
                    surface=Surface(
                        file=rel_path, kind=kind, action=action, publishes=publishes
                    ),
                    step=_step_name(step, action),
                    line=int(step.get(LINE_KEY, 1)),
                    condition=_flatten(step.get("if")),
                )
            )
        for node, kind, action, publishes in (
            *_layer_cache_sites(document),
            *_release_sites(document),
        ):
            name = node.get("name")
            found.append(
                Found(
                    surface=Surface(
                        file=rel_path, kind=kind, action=action, publishes=publishes
                    ),
                    step=name.strip()
                    if isinstance(name, str) and name.strip()
                    else "(unnamed)",
                    line=int(node.get(LINE_KEY, 1)),
                )
            )
    return found


def scan_tree(github_dir: Path) -> list[Found]:
    found: list[Found] = []
    paths = sorted(
        path
        for path in github_dir.rglob("*")
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    )
    for path in paths:
        rel = path.relative_to(REPO_ROOT).as_posix()
        found.extend(scan_text(rel, path.read_text(encoding="utf-8")))
    return found


def evaluate(
    found: list[Found], allowlist: tuple[Entry, ...]
) -> tuple[list[Found], list[tuple[Entry, int]]]:
    """Compare the census against the allowlist, in both directions.

    Returns the sites nobody listed, and the entries the census did not account
    for -- either because the site is gone, or because the detector stopped
    seeing it.
    """
    allowed = {entry.as_key(): entry for entry in allowlist}
    seen = Counter(item.surface.as_key() for item in found)

    unexpected: list[Found] = []
    budget = {key: entry.count for key, entry in allowed.items()}
    for item in found:
        key = item.surface.as_key()
        if budget.get(key, 0) > 0:
            budget[key] -= 1
        else:
            unexpected.append(item)

    # Only a SHORTFALL orphans an entry. A surplus occurrence is already reported
    # against the step that added it, which is where a reader can act on it;
    # reporting it a second time as a count mismatch on the entry would describe
    # one duplicated upload as two separate problems.
    unmatched: list[tuple[Entry, int]] = []
    for key, entry in allowed.items():
        actual = seen.get(key, 0)
        if actual < entry.count:
            unmatched.append((entry, actual))
    return unexpected, unmatched


def _top_level_conjuncts(condition: str) -> list[str] | None:
    """Split an `if:` into its top-level `&&` terms, or None if it cannot be read.

    Narrow on purpose. `||` anywhere, a parenthesised group, or an expression
    nested inside the outer `${{ }}` returns None, because splitting those on
    `&&` would misread them: `failure() && x || always()` is
    `(failure() && x) || always()`, which runs on green builds. An empty call such
    as `failure()` or `always()` is the only parenthesis allowed.
    """
    text = condition.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    if not text or "${{" in text or "}}" in text or "||" in text:
        return None
    if "(" in text.replace("()", "") or ")" in text.replace("()", ""):
        return None
    return [term.strip() for term in text.split("&&")]


def check_conditions(
    found: list[Found], allowlist: tuple[Entry, ...]
) -> list[tuple[Found, Entry]]:
    """Return the allowlisted sites whose `if:` does not hold the entry's condition."""
    required = {
        entry.as_key(): entry for entry in allowlist if entry.required_condition
    }
    violations: list[tuple[Found, Entry]] = []
    for item in found:
        entry = required.get(item.surface.as_key())
        if entry is None:
            continue
        terms = _top_level_conjuncts(item.condition)
        if terms is None or entry.required_condition not in terms:
            violations.append((item, entry))
    return violations


def _print_census(found: list[Found]) -> None:
    print(f"Publish-surface census over {GITHUB_DIR.relative_to(REPO_ROOT)}/:")
    print(f"  {len(found)} site(s) that can publish bytes to a public store\n")
    for item in sorted(
        found, key=lambda f: (f.surface.file, f.line, f.surface.publishes)
    ):
        surface = item.surface
        print(f"  {surface.file}:{item.line}")
        print(f"    step      {item.step}")
        print(f"    kind      {surface.kind} ({surface.action})")
        print(f"    publishes {surface.publishes}")
    print()


def _report_condition_failures(violations: list[tuple[Found, Entry]]) -> None:
    for item, entry in sorted(
        violations, key=lambda pair: (pair[0].surface.file, pair[0].line)
    ):
        surface = item.surface
        shown = item.condition or "(none, so it runs whenever the job gets this far)"
        print(
            f"::error file={surface.file},line={item.line}::Allowlisted publish surface runs outside its accepted condition: {surface.file} step '{item.step}' must have '{entry.required_condition}' as a top-level && term of its if:, found {shown}"
        )
        print(f"CONDITION NOT HELD  {surface.file}:{item.line}")
        print(f"  step       {item.step}")
        print(f"  publishes  {surface.publishes}")
        print(f"  required   {entry.required_condition} (as a top-level && term)")
        print(f"  found if:  {shown}")
        print(f"  reason on file  {entry.reason}")
        print(
            "  why this failed\n"
            "    This upload was accepted on the condition that it runs only when\n"
            "    that term is true, and its step-level if: no longer guarantees it,\n"
            "    or is written in a form this check cannot read (any ||, or a\n"
            "    parenthesised group). Either way it may now publish on runs the\n"
            "    decision did not cover.\n"
            "  what to do\n"
            "    Restore the condition. If widening it is intended, that is a new\n"
            "    decision: change required_condition and the reason in the same\n"
            "    commit.\n"
        )


def _report_failures(
    unexpected: list[Found], unmatched: list[tuple[Entry, int]]
) -> None:
    for item in sorted(unexpected, key=lambda f: (f.surface.file, f.line)):
        surface = item.surface
        headline = {
            KIND_UPLOAD: "uploads an artifact",
            KIND_CACHE: "writes an Actions cache",
            KIND_BUILTIN_CACHE: "enables an action's built-in cache",
            KIND_CACHE_ACCESS_HANDOFF: "hands the Actions cache token to later steps",
            KIND_LAYER_CACHE: "sets ASH's image layer-cache export",
            KIND_RELEASE_ASSET: "attaches files to a GitHub Release",
        }[surface.kind]
        print(
            f"::error file={surface.file},line={item.line}::New publicly-downloadable surface: {surface.file} step '{item.step}' {headline} ({surface.publishes}) and is not allowlisted"
        )
        print(f"NOT ALLOWLISTED  {surface.file}:{item.line}")
        print(f"  step       {item.step}")
        print(f"  action     {surface.action}")
        print(f"  publishes  {surface.publishes}")
        print(
            "  why this failed\n"
            "    This repository is public, so artifacts and Actions caches are\n"
            "    readable by anyone with a read token -- which is everyone. This step\n"
            "    therefore makes whatever it publishes downloadable by strangers, and\n"
            "    nobody has recorded a decision that it should be.\n"
            "  what to do\n"
            "    If these bytes are something this project builds -- a wheel, an sdist,\n"
            "    a container image, a compiled binary, a bundle -- then this is a new\n"
            "    distribution channel for the project and needs to be a deliberate\n"
            "    choice, not a side effect of adding a step. Decide that first.\n"
            "    If it is already-public third-party content passing through a runner,\n"
            "    say so. Either way the decision gets recorded as an entry in\n"
            "    ALLOWLIST in .github/scripts/assert-publish-surfaces.py, with a reason.\n"
            "    Copy the kind, action and publishes strings above verbatim.\n"
            "    Removing the step also clears this.\n"
        )
    for entry, actual in sorted(unmatched, key=lambda pair: pair[0].as_key()):
        print(
            f"::error file={entry.file}::Allowlisted publish surface not found: expected {entry.count} occurrence(s) of {entry.kind} publishing '{entry.publishes}' in {entry.file}, censused {actual}"
        )
        print(f"ALLOWLIST ENTRY UNMATCHED  {entry.file}")
        print(f"  kind       {entry.kind} ({entry.action})")
        print(f"  publishes  {entry.publishes}")
        print(f"  expected   {entry.count} occurrence(s), censused {actual}")
        print(f"  reason on file  {entry.reason}")
        print(
            "  why this failed\n"
            "    Either the step was changed or removed and its allowlist entry was\n"
            "    left behind, or -- the case this direction of the check exists for --\n"
            "    the detector has stopped recognising it, in which case a genuinely\n"
            "    new upload would no longer be caught either. Do not delete the entry\n"
            "    to make this green without first confirming which of the two it is.\n"
            "    If the step is gone on purpose, drop the entry in the same change.\n"
            "    If the step was repointed at a different name or path, update the\n"
            "    entry to the censused strings and say in the reason why the new\n"
            "    target is acceptable.\n"
        )


# ---------------------------------------------------------------------------
# Self-test: the positive control.
#
# A gate that cannot fail is worse than no gate, because it reads as evidence.
# These fixtures exercise the four ways a publishing surface can appear or move,
# and the run asserts each one comes back red and the matching tree comes back
# green. It runs before the real census in CI, so a detector that has degenerated
# into "always pass" is caught by this rather than by the next incident.
# ---------------------------------------------------------------------------

_SELF_TEST_ALLOWED_FILE = "fixture/allowed.yml"
_SELF_TEST_CLEAN_FILE = "fixture/clean.yml"
_SELF_TEST_RELEASE_FILE = "fixture/release.yml"

# The allowlisted release attach is spread over continuation lines and preceded by a
# comment that names the command, so the clean baseline already proves the joiner
# reads one command and the comment rule keeps prose out of the census.
_SELF_TEST_RELEASE_YAML = """
name: fixture release
on: [pull_request]
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - name: Publish
        run: |
          set -euo pipefail
          # gh release create v9 everything/* would be wrong here
          gh release create "$TAG" \\
            --repo "$GITHUB_REPOSITORY" \\
            --title "$TAG" \\
            --generate-notes \\
            dist/*.whl
"""

_SELF_TEST_ALLOWED_YAML = """
name: fixture
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: astral-sh/setup-uv@bec219d24cd3e171d82865faccec33120bb574f4 # v10.1.0
        with:
          enable-cache: true
      - name: Upload the wheel
        if: ${{ failure() && !env.ACT }}
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: dist
          path: dist/
"""

_SELF_TEST_CLEAN_YAML = """
name: fixture without any publishing step
on: [pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
        with:
          node-version: 22
          # Disabled, so not a cache. A plain truthiness test on the YAML value
          # would read this empty string as "caching is on" and the fixture would
          # stop being a clean control.
          cache: ''
      # Explicitly off, so not a cache. The control for the default-on cases below:
      # a detector that flagged every setup-uv would turn this file red.
      - uses: astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7 # v10.2.0
        with:
          enable-cache: false
      - run: echo no publishing here
"""

_SELF_TEST_ALLOWLIST: tuple[Entry, ...] = (
    Entry(
        file=_SELF_TEST_ALLOWED_FILE,
        kind=KIND_UPLOAD,
        action="actions/upload-artifact",
        publishes="name=dist path=dist/",
        reason="self-test fixture",
        required_condition="failure()",
    ),
    Entry(
        file=_SELF_TEST_ALLOWED_FILE,
        kind=KIND_BUILTIN_CACHE,
        action="astral-sh/setup-uv",
        publishes="enable-cache=true",
        reason="self-test fixture",
    ),
    Entry(
        file=_SELF_TEST_RELEASE_FILE,
        kind=KIND_RELEASE_ASSET,
        action="gh release create",
        publishes="assets=dist/*.whl",
        reason="self-test fixture",
    ),
)


def _self_test_case(name: str, files: dict[str, str]) -> tuple[str, int, int, int]:
    found: list[Found] = []
    for rel, text in files.items():
        found.extend(scan_text(rel, text))
    unexpected, unmatched = evaluate(found, _SELF_TEST_ALLOWLIST)
    ungated = check_conditions(found, _SELF_TEST_ALLOWLIST)
    return name, len(unexpected), len(unmatched), len(ungated)


def self_test() -> int:
    baseline = {
        _SELF_TEST_ALLOWED_FILE: _SELF_TEST_ALLOWED_YAML,
        _SELF_TEST_CLEAN_FILE: _SELF_TEST_CLEAN_YAML,
        _SELF_TEST_RELEASE_FILE: _SELF_TEST_RELEASE_YAML,
    }

    # (h) a second place that attaches files to a release, through gh.
    release_upload = dict(baseline)
    release_upload[_SELF_TEST_CLEAN_FILE] = (
        _SELF_TEST_CLEAN_YAML
        + """
      - name: Attach the image to the release too
        run: gh release upload "v${VERSION}" image.tar --clobber
"""
    )

    # (h1) the same through a release action instead of gh.
    release_action = dict(baseline)
    release_action[_SELF_TEST_CLEAN_FILE] = (
        _SELF_TEST_CLEAN_YAML
        + """
      - name: Release with an action
        uses: softprops/action-gh-release@0000000000000000000000000000000000000000 # v2
        with:
          files: dist/*
"""
    )

    # (h2) the allowlisted attach widened to more files.
    release_widened = dict(baseline)
    release_widened[_SELF_TEST_RELEASE_FILE] = _SELF_TEST_RELEASE_YAML.replace(
        "dist/*.whl", "dist/*.whl build/*"
    )

    # (a) a new upload in a file that has none today.
    new_file_upload = dict(baseline)
    new_file_upload[_SELF_TEST_CLEAN_FILE] = (
        _SELF_TEST_CLEAN_YAML
        + """
      - name: Upload the container image
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: image
          path: image.tar
"""
    )

    # (b) a SECOND upload in a file that already has an allowed one. The case a
    # filename-keyed allowlist waves through.
    second_upload = dict(baseline)
    second_upload[_SELF_TEST_ALLOWED_FILE] = (
        _SELF_TEST_ALLOWED_YAML
        + """
      - name: Upload the container image too
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: image
          path: image.tar
"""
    )

    # (b2) a second upload whose inputs are byte-identical to the allowed one, so
    # the key alone cannot separate them and only the occurrence count can.
    duplicate_upload = dict(baseline)
    duplicate_upload[_SELF_TEST_ALLOWED_FILE] = (
        _SELF_TEST_ALLOWED_YAML
        + """
      - name: Upload the wheel again
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: dist
          path: dist/
"""
    )

    # (c) a new actions/cache anywhere.
    new_cache = dict(baseline)
    new_cache[_SELF_TEST_CLEAN_FILE] = (
        _SELF_TEST_CLEAN_YAML
        + """
      - name: Cache the build tree
        uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
        with:
          path: build/
          key: build-${{ runner.os }}
"""
    )

    # (c1) the same through `actions/cache/save`, the split form the base-image cache uses.
    # A separate case because the subpath is a different `uses:` string, and a detector
    # that matched only the bare `actions/cache` would miss it.
    new_cache_save = dict(baseline)
    new_cache_save[_SELF_TEST_CLEAN_FILE] = (
        _SELF_TEST_CLEAN_YAML
        + """
      - name: Save the built image layers
        uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
        with:
          path: /tmp/ash-image-layers
          key: ash-image-${{ github.sha }}
"""
    )

    # (c2) the same thing through an action's built-in cache rather than a
    # `uses: actions/cache` line, which is what a buildx `cache-to: type=gha`
    # looks like -- a built container image into the public cache with no new
    # cache action for a reviewer to spot.
    builtin_cache = dict(baseline)
    builtin_cache[_SELF_TEST_CLEAN_FILE] = (
        _SELF_TEST_CLEAN_YAML
        + """
      - name: Build and push with a GHA layer cache
        uses: docker/build-push-action@0000000000000000000000000000000000000000 # v6
        with:
          cache-to: type=gha,mode=max
"""
    )

    # (c3) setup-uv with no `enable-cache` input at all. The input defaults to
    # "auto", which caches on GitHub-hosted runners for an ordinary push or pull
    # request, so leaving it out is a cache with nothing in `with:` to see.
    default_uv_cache = dict(baseline)
    default_uv_cache[_SELF_TEST_CLEAN_FILE] = (
        _SELF_TEST_CLEAN_YAML
        + """
      - name: Install uv with the default cache setting
        uses: astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7 # v10.2.0
"""
    )

    # (c4) the same default, spelled out.
    auto_uv_cache = dict(baseline)
    auto_uv_cache[_SELF_TEST_CLEAN_FILE] = (
        _SELF_TEST_CLEAN_YAML
        + """
      - name: Install uv with enable-cache auto
        uses: astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7 # v10.2.0
        with:
          enable-cache: auto
"""
    )

    # (c5) ASH's layer cache: an export mode set where none was decided, and the
    # credential hand-off that makes an export possible at all.
    layer_export = dict(baseline)
    layer_export[_SELF_TEST_CLEAN_FILE] = (
        _SELF_TEST_CLEAN_YAML
        + """
      - name: Build the image and export every layer
        env:
          ASH_GHA_BUILD_CACHE_EXPORT: max
        run: ashx build-image --no-run
"""
    )
    credentials_export = dict(baseline)
    credentials_export[_SELF_TEST_CLEAN_FILE] = (
        _SELF_TEST_CLEAN_YAML
        + """
      - name: Hand the cache token to the build
        uses: actions/github-script@ed597411d8f924073f98dfc5c65a23a2325f34cd # v8.0.0
        with:
          script: core.exportVariable('ACTIONS_RUNTIME_TOKEN', process.env.ACTIONS_RUNTIME_TOKEN)
"""
    )

    # (d) an allowed upload repointed at a different path.
    repointed = dict(baseline)
    repointed[_SELF_TEST_ALLOWED_FILE] = _SELF_TEST_ALLOWED_YAML.replace(
        "path: dist/", "path: build/container-image.tar"
    )

    # (e) an allowlisted site deleted, so its entry orphans. Same signal the
    # detector-has-broken case produces.
    deleted = dict(baseline)
    deleted[_SELF_TEST_ALLOWED_FILE] = _SELF_TEST_CLEAN_YAML

    # (f) a failure-only upload widened to every run. Same bytes, same key, so
    # only required_condition can see it.
    _failure_only = "        if: ${{ failure() && !env.ACT }}\n"
    widened_always = dict(baseline)
    widened_always[_SELF_TEST_ALLOWED_FILE] = _SELF_TEST_ALLOWED_YAML.replace(
        _failure_only, "        if: always()\n"
    )

    # (f1) the condition dropped altogether.
    widened_dropped = dict(baseline)
    widened_dropped[_SELF_TEST_ALLOWED_FILE] = _SELF_TEST_ALLOWED_YAML.replace(
        _failure_only, ""
    )

    # (f2) failure() still present and still joined by &&, but an || makes the
    # whole thing true on green runs. A substring match would pass this.
    widened_or = dict(baseline)
    widened_or[_SELF_TEST_ALLOWED_FILE] = _SELF_TEST_ALLOWED_YAML.replace(
        _failure_only, "        if: ${{ failure() && !env.ACT || always() }}\n"
    )

    # (f3) failure() negated.
    widened_negated = dict(baseline)
    widened_negated[_SELF_TEST_ALLOWED_FILE] = _SELF_TEST_ALLOWED_YAML.replace(
        _failure_only, "        if: ${{ !failure() }}\n"
    )

    # (f4) failure() inside a negated group. Every term split on && reads as
    # failure() unless parenthesised groups are refused, yet the whole is true on
    # every green run (env.ACT is unset in CI).
    widened_grouped = dict(baseline)
    widened_grouped[_SELF_TEST_ALLOWED_FILE] = _SELF_TEST_ALLOWED_YAML.replace(
        _failure_only, "        if: ${{ !(env.ACT && failure() && true) }}\n"
    )

    # (g) the bare form, without ${{ }}, is the same condition and must pass.
    bare_failure = dict(baseline)
    bare_failure[_SELF_TEST_ALLOWED_FILE] = _SELF_TEST_ALLOWED_YAML.replace(
        _failure_only, "        if: failure()\n"
    )

    expectations = [
        # name, files, expect unexpected, expect unmatched, expect ungated
        ("clean tree matches the allowlist", baseline, 0, 0, 0),
        ("(a) new upload in a file with none", new_file_upload, 1, 0, 0),
        ("(b) second upload in an allowed file", second_upload, 1, 0, 0),
        ("(b2) duplicate of an allowed upload", duplicate_upload, 1, 0, 1),
        ("(c) new actions/cache", new_cache, 1, 0, 0),
        ("(c1) new actions/cache/save", new_cache_save, 1, 0, 0),
        ("(c2) built-in cache via cache-to", builtin_cache, 1, 0, 0),
        ("(c3) setup-uv with enable-cache left out", default_uv_cache, 1, 0, 0),
        ("(c4) setup-uv with enable-cache auto", auto_uv_cache, 1, 0, 0),
        ("(c5) layer-cache export mode set", layer_export, 1, 0, 0),
        ("(c6) cache credentials handed to later steps", credentials_export, 1, 0, 0),
        ("(d) allowed upload repointed", repointed, 1, 1, 0),
        ("(e) allowlisted site deleted", deleted, 0, 2, 0),
        ("(f) failure-only upload widened to always()", widened_always, 0, 0, 1),
        ("(f1) failure-only upload's if: removed", widened_dropped, 0, 0, 1),
        ("(f2) failure() kept but || always() added", widened_or, 0, 0, 1),
        ("(f3) failure() negated", widened_negated, 0, 0, 1),
        ("(f4) failure() inside a negated group", widened_grouped, 0, 0, 1),
        ("(g) bare if: failure() still holds", bare_failure, 0, 0, 0),
        ("(h) a second gh release attach", release_upload, 1, 0, 0),
        ("(h1) a release action attaching files", release_action, 1, 0, 0),
        ("(h2) the allowed release attach widened", release_widened, 1, 1, 0),
    ]

    failures = 0
    print("Self-test: does this check still detect and still fail?\n")
    for name, files, want_unexpected, want_unmatched, want_ungated in expectations:
        _, got_unexpected, got_unmatched, got_ungated = _self_test_case(name, files)
        ok = (
            got_unexpected == want_unexpected
            and got_unmatched == want_unmatched
            and got_ungated == want_ungated
        )
        status = "ok  " if ok else "FAIL"
        print(
            f"  {status} {name}: "
            f"unexpected={got_unexpected} (want {want_unexpected}), "
            f"unmatched={got_unmatched} (want {want_unmatched}), "
            f"ungated={got_ungated} (want {want_ungated})"
        )
        if not ok:
            failures += 1

    # The counts above prove the detectors fire. These prove the verdict main()
    # returns honors each of them, so dropping one from the exit decision (an
    # unexpected site, an orphaned entry, or a condition not held) goes red here
    # rather than only in the next incident.
    # The orphan case keeps the cache site, so the census is not empty and only the
    # unmatched upload entry can fail it. `deleted` above empties the census, which
    # the no-sites guard would fail on its own. The empty census is run against an
    # empty allowlist for the same reason: with any entry, the orphan check fails it.
    upload_removed = dict(baseline)
    upload_removed[_SELF_TEST_ALLOWED_FILE] = _SELF_TEST_ALLOWED_YAML.split(
        "      - name: Upload the wheel"
    )[0]
    verdicts: list[tuple[str, dict[str, str], tuple[Entry, ...], int]] = [
        # name, files, allowlist, expected exit status of gate()
        ("verdict: clean tree passes", baseline, _SELF_TEST_ALLOWLIST, 0),
        ("verdict: no sites censused fails", {}, (), 1),
        ("verdict: unexpected site fails", new_file_upload, _SELF_TEST_ALLOWLIST, 1),
        ("verdict: orphaned entry fails", upload_removed, _SELF_TEST_ALLOWLIST, 1),
        ("verdict: condition not held fails", widened_always, _SELF_TEST_ALLOWLIST, 1),
        ("verdict: grouped condition fails", widened_grouped, _SELF_TEST_ALLOWLIST, 1),
    ]
    for name, files, allowlist, want_status in verdicts:
        found = [item for rel, text in files.items() for item in scan_text(rel, text)]
        with contextlib.redirect_stdout(io.StringIO()):
            got_status = gate(found, allowlist)
        ok = got_status == want_status
        status = "ok  " if ok else "FAIL"
        print(f"  {status} {name}: exit={got_status} (want {want_status})")
        if not ok:
            failures += 1
    print()
    if failures:
        print(
            f"::error::assert-publish-surfaces.py self-test failed {failures} case(s). "
            "The check cannot be trusted to catch a new publishing surface until this "
            "is fixed; do not skip it."
        )
        return 1
    print("Self-test passed: every case the check exists for still comes back red.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Assert that every artifact upload and cache under .github/ is "
            "allowlisted, so a pull request cannot add a publicly-downloadable "
            "surface by accident."
        )
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the detector against synthetic fixtures and exit",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    found = scan_tree(GITHUB_DIR)
    _print_census(found)
    return gate(found, ALLOWLIST)


def gate(found: list[Found], allowlist: tuple[Entry, ...]) -> int:
    """Return main()'s exit status for a census against an allowlist.

    Separate from main() so the self-test can run the real verdict over fixtures.
    """
    if not found:
        print(
            "::error::assert-publish-surfaces.py censused zero publishing sites. "
            "This repository has several, so the scan found nothing rather than "
            "there being nothing to find."
        )
        return 1

    unexpected, unmatched = evaluate(found, allowlist)
    ungated = check_conditions(found, allowlist)
    gated = sum(1 for entry in allowlist if entry.required_condition)
    if not unexpected and not unmatched and not ungated:
        print(
            f"OK: all {len(found)} publishing site(s) match the "
            f"{len(allowlist)} allowlist entr(ies); {gated} entr(ies) with a "
            f"required condition hold it."
        )
        return 0

    _report_failures(unexpected, unmatched)
    _report_condition_failures(ungated)
    print(
        f"FAILED: {len(unexpected)} unexpected publishing site(s), "
        f"{len(unmatched)} unmatched allowlist entr(ies), "
        f"{len(ungated)} site(s) outside their required condition."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
