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
truthy cache inputs for an action with a built-in cache. Consequences:

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

KNOWN LIMITATIONS

  * The key covers WHAT is published, not WHEN. Flipping `if: failure()` to
    unconditional widens an accepted upload from red runs to every run and this
    will not notice, because the bytes are the same bytes and were already
    accepted as publishable.
  * Release assets (`softprops/action-gh-release` and friends) are out of scope.
    A release is a deliberate, human-triggered publication with a human on the
    button, which is the opposite of the accidental case this guards.
  * Expressions are compared as source text. Two spellings of the same artifact
    name are two different keys, which costs a false failure on a pure
    refactor -- the cheaper direction to be wrong in.
  * Only `uses:` steps are read. A third-party action can upload or cache from
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

    def as_key(self) -> tuple[str, str, str, str]:
        return (self.file, self.kind, self.action, self.publishes)


@dataclass(frozen=True)
class Found:
    """A Surface as measured, with enough context to write a useful message."""

    surface: Surface
    step: str
    line: int


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
_NPM_CACHE_REASON = (
    "npm's download cache, keyed on a committed lockfile. Holds third-party "
    "packages already published on the npm registry, so it redistributes nothing "
    "this project builds."
)
_BASE_IMAGE_CACHE_REASON = (
    "Third-party public image, byte-identical to docker.io at the pinned digest, "
    "hash-verified before use; saved on main only; approved by the maintainer. The "
    "Dockerfile's base image (ARG BASE_IMAGE at ARG BASE_IMAGE_DIGEST) as an OCI layout: "
    "prepull-base-image checks every blob against its sha256 and the index against the pin "
    "before any build reads it, and discards the entry on any mismatch."
)

_GRYPE_DB_CACHE_REASON = (
    "grype's published vulnerability database, fetched from upstream and "
    "re-verified by grype on start. Third-party public data; this project builds "
    "none of it. Saved from the default branch only, and keyed on a time bucket "
    "derived from the bound grype enforces (automated_security_helper/utils/"
    "content_databases.py), so no restored copy is older than that bound."
)

ALLOWLIST: tuple[Entry, ...] = (
    # -- Artifact uploads -----------------------------------------------------
    #
    # The wheel and the sdist are the only entries here that publish something
    # this project BUILT. Everything else is a report, a test result, or scan
    # output kept as evidence from a red run.
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
            "name=ts-coverage-${{ matrix.package }} "
            "path=deploy/${{ matrix.package }}/coverage/"
        ),
        reason=(
            "Coverage report for the TypeScript packages. Instrumented-line data "
            "over tracked source, not the compiled bundle."
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
        action="actions/cache",
        publishes=(
            "path=~/.opengrep/cli/latest "
            "key=opengrep-${{ runner.os }}-${{ steps.cachekeys.outputs.week }}"
        ),
        reason=(
            "The OpenGrep release binary, downloaded from upstream with its digest "
            "verified before install. A third-party binary that is already "
            "publicly downloadable, not one this project produced."
        ),
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
        publishes="enable-cache=true",
        reason=_UV_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-agent-plugins-drift.yml",
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_UV,
        publishes="enable-cache=true",
        reason=_UV_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-cdk-extra-drift.yml",
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_UV,
        publishes="enable-cache=true",
        reason=_UV_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-create-release.yml",
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_UV,
        publishes="enable-cache=true",
        reason=_UV_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-package.yml",
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_UV,
        publishes="enable-cache=true",
        reason=_UV_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-repo-docs.yml",
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_UV,
        publishes="enable-cache=true",
        count=2,
        reason=_UV_CACHE_REASON + " Twice: this workflow has two jobs.",
    ),
    Entry(
        file=".github/workflows/ash-tag-on-merge.yml",
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_UV,
        publishes="enable-cache=true",
        reason=_UV_CACHE_REASON,
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
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_NODE,
        publishes="cache=npm cache-dependency-path=deploy/cdk/package-lock.json",
        count=2,
        reason=_NPM_CACHE_REASON + " Twice: the synth job and the cdk-nag job.",
    ),
    Entry(
        file=".github/workflows/ash-iac-drift.yml",
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_NODE,
        publishes="cache=npm cache-dependency-path=deploy/cdk-constructs/package-lock.json",
        reason=_NPM_CACHE_REASON,
    ),
    Entry(
        file=".github/workflows/ash-typescript-ci.yml",
        kind=KIND_BUILTIN_CACHE,
        action=_SETUP_NODE,
        publishes=(
            "cache=npm "
            "cache-dependency-path=deploy/${{ matrix.package }}/package-lock.json"
        ),
        reason=_NPM_CACHE_REASON,
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
    if cache_inputs:
        rendered = " ".join(
            f"{key}={_flatten(cache_inputs[key])}" for key in sorted(cache_inputs)
        )
        return KIND_BUILTIN_CACHE, rendered
    return None


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


def _report_failures(
    unexpected: list[Found], unmatched: list[tuple[Entry, int]]
) -> None:
    for item in sorted(unexpected, key=lambda f: (f.surface.file, f.line)):
        surface = item.surface
        headline = {
            KIND_UPLOAD: "uploads an artifact",
            KIND_CACHE: "writes an Actions cache",
            KIND_BUILTIN_CACHE: "enables an action's built-in cache",
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
      - run: echo no publishing here
"""

_SELF_TEST_ALLOWLIST: tuple[Entry, ...] = (
    Entry(
        file=_SELF_TEST_ALLOWED_FILE,
        kind=KIND_UPLOAD,
        action="actions/upload-artifact",
        publishes="name=dist path=dist/",
        reason="self-test fixture",
    ),
    Entry(
        file=_SELF_TEST_ALLOWED_FILE,
        kind=KIND_BUILTIN_CACHE,
        action="astral-sh/setup-uv",
        publishes="enable-cache=true",
        reason="self-test fixture",
    ),
)


def _self_test_case(name: str, files: dict[str, str]) -> tuple[str, int, int]:
    found: list[Found] = []
    for rel, text in files.items():
        found.extend(scan_text(rel, text))
    unexpected, unmatched = evaluate(found, _SELF_TEST_ALLOWLIST)
    return name, len(unexpected), len(unmatched)


def self_test() -> int:
    baseline = {
        _SELF_TEST_ALLOWED_FILE: _SELF_TEST_ALLOWED_YAML,
        _SELF_TEST_CLEAN_FILE: _SELF_TEST_CLEAN_YAML,
    }

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

    # (d) an allowed upload repointed at a different path.
    repointed = dict(baseline)
    repointed[_SELF_TEST_ALLOWED_FILE] = _SELF_TEST_ALLOWED_YAML.replace(
        "path: dist/", "path: build/container-image.tar"
    )

    # (e) an allowlisted site deleted, so its entry orphans. Same signal the
    # detector-has-broken case produces.
    deleted = dict(baseline)
    deleted[_SELF_TEST_ALLOWED_FILE] = _SELF_TEST_CLEAN_YAML

    expectations = [
        # name, files, expect unexpected, expect unmatched
        ("clean tree matches the allowlist", baseline, 0, 0),
        ("(a) new upload in a file with none", new_file_upload, 1, 0),
        ("(b) second upload in an allowed file", second_upload, 1, 0),
        ("(b2) duplicate of an allowed upload", duplicate_upload, 1, 0),
        ("(c) new actions/cache", new_cache, 1, 0),
        ("(c1) new actions/cache/save", new_cache_save, 1, 0),
        ("(c2) built-in cache via cache-to", builtin_cache, 1, 0),
        ("(d) allowed upload repointed", repointed, 1, 1),
        ("(e) allowlisted site deleted", deleted, 0, 2),
    ]

    failures = 0
    print("Self-test: does this check still detect and still fail?\n")
    for name, files, want_unexpected, want_unmatched in expectations:
        _, got_unexpected, got_unmatched = _self_test_case(name, files)
        ok = got_unexpected == want_unexpected and got_unmatched == want_unmatched
        status = "ok  " if ok else "FAIL"
        print(
            f"  {status} {name}: "
            f"unexpected={got_unexpected} (want {want_unexpected}), "
            f"unmatched={got_unmatched} (want {want_unmatched})"
        )
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

    if not found:
        print(
            "::error::assert-publish-surfaces.py censused zero publishing sites. "
            "This repository has several, so the scan found nothing rather than "
            "there being nothing to find."
        )
        return 1

    unexpected, unmatched = evaluate(found, ALLOWLIST)
    if not unexpected and not unmatched:
        print(
            f"OK: all {len(found)} publishing site(s) match the "
            f"{len(ALLOWLIST)} allowlist entr(ies)."
        )
        return 0

    _report_failures(unexpected, unmatched)
    print(
        f"FAILED: {len(unexpected)} unexpected publishing site(s), "
        f"{len(unmatched)} unmatched allowlist entr(ies)."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
