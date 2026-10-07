#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Report every tool ``tool_downloads.py`` pins whose upstream has a newer release.

Why this exists
---------------
``automated_security_helper/utils/tool_downloads.py`` pins each tool ASH provisions
itself to an exact version and SHA256: the release binaries in ``TOOL_VERSIONS``,
the Python scanners the container image installs with ``uv tool install`` (the
``THIRD_PARTY_LICENSES`` entries with a ``distribution``), the license files fetched
at each tool's release commit, and the cfn-nag gem. Nothing told anyone when one of
those fell behind. Dependabot reads lockfiles and manifests; a Python dict is
neither, so it never sees these pins, and the module's own guidance describes a bump
as a manual edit of both digest tables. A pin that nobody is reminded about stays
where it was set, including past the upstream release that fixes a vulnerability
the scanner exists to find.

This script reads the pins from the module itself and asks each upstream for its
latest release: the GitHub releases API for the release binaries and the license-only
entries, PyPI's JSON API for the uv-tool pins, and the RubyGems API for cfn-nag. It
prints pinned against latest, and for each pin that is behind, every place in the
module a bump has to change. ``.github/workflows/ash-pinned-tool-versions.yml`` runs
it weekly with ``--fail-on-outdated``.

There is no second list of tools here. The pins come from ``TOOL_VERSIONS``,
``THIRD_PARTY_LICENSES`` and ``CFN_NAG_GEM_VERSION``, so a tool pinned in any of them
is checked without editing this file. A pin kept in a new module-level name would not
be; ``tests/unit/test_pinned_tool_version_check.py`` fails on any module
global named like a version pin that ``PIN_SOURCES`` below does not name.

What was rejected
-----------------
1. Dependabot. It has no ecosystem for "a version string in a Python dict", and
   the docker ecosystem only reads ``FROM`` lines, not the ``ARG`` pins.
2. Opening an issue or a pull request. A bump is not a version edit: every
   archive and executable digest changes, and the license files and source commit
   have to be re-taken and checked by a person. A generated pull request would
   carry the version and none of the evidence. The weekly job fails and its summary
   says what to change; a person does the change.
3. Comparing version strings. ``"v0.69.10" < "v0.69.9"`` as strings, so a string
   comparison reports a newer trivy as older. Versions are parsed into numbers.

Known limitations
-----------------
* "Latest" is each upstream's own notion: GitHub's ``releases/latest`` (which
  skips drafts and pre-releases), PyPI's ``info.version`` and RubyGems'
  ``latest.json``. A project that marks a release "latest" out of version order
  is reported as it marks it.
* A pin newer than upstream's latest is reported as ``ahead`` and does not fail.
  That happens when a release is yanked or demoted after it was pinned, and it is a
  reason to look, not something this script can decide.
* A lookup that fails (network, rate limit, renamed project) is reported as
  ``error`` and exits 2 whatever the flags. A pin whose upstream could not be read
  has not been shown to be current, and reporting it as current would be the
  failure this script exists to prevent. Unauthenticated GitHub API calls are
  limited to 60 an hour per address; set ``GITHUB_TOKEN`` (or ``GH_TOKEN``) to
  lift that.
* Pre-release suffixes compare as text after the numeric part, so ``1.2.0rc10``
  sorts before ``1.2.0rc9``. The upstream APIs above return final releases, so
  the case does not arise in practice.

Usage::

    python scripts/check_pinned_tool_versions.py
    python scripts/check_pinned_tool_versions.py --fail-on-outdated --markdown

Exit codes: 0 when no pin is behind (or ``--fail-on-outdated`` is not given),
1 when a pin is behind and ``--fail-on-outdated`` is given, 2 when a lookup failed
or the pins could not be read.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "automated_security_helper"
PINS_FILE = "automated_security_helper/utils/tool_downloads.py"
INSTALLER = PACKAGE_ROOT / "assets" / "install-pinned-tool.py"
DOCKERFILE = REPO_ROOT / "Dockerfile"
GEMFILE = "automated_security_helper/assets/Gemfile"

# The module-level names of tool_downloads.py this script reads pins from. Any other
# global named like a version pin fails the unit tests, so a new kind of pin is added
# here on purpose rather than skipped by omission.
PIN_SOURCES = ("TOOL_VERSIONS", "THIRD_PARTY_LICENSES", "CFN_NAG_GEM_VERSION")

# The gem CFN_NAG_GEM_VERSION is the version of; see assets/Gemfile.
CFN_NAG_GEM = "cfn-nag"

GITHUB = "github-release"
PYPI = "pypi"
RUBYGEMS = "rubygems"

_GITHUB_PREFIX = "https://github.com/"
_TIMEOUT_SECONDS = 30

# The only hosts _get_json may contact: the GitHub releases API, PyPI's JSON API and
# RubyGems' API, the three upstreams the pins are compared against. Every URL is built
# from a fixed https prefix today; this check makes that a property of the function
# rather than of its callers, so a later caller cannot point it at a file:// path, a
# plain-http mirror or an arbitrary host.
_ALLOWED_HOSTS = frozenset({"api.github.com", "pypi.org", "rubygems.org"})

EXIT_OK = 0
EXIT_OUTDATED = 1
EXIT_ERROR = 2


class PinEnumerationError(Exception):
    """The pins module is in a state this script cannot read a pin from."""


@dataclass(frozen=True)
class Pin:
    """One pinned tool and where its upstream publishes releases.

    ``version`` is spelled exactly as the module spells it, leading ``v`` and all.
    ``project`` is ``owner/repo`` for a GitHub release, the distribution name for
    PyPI and the gem name for RubyGems. ``pinned_in`` names the module tables that
    carry this tool's version, which is what a bump has to edit.
    """

    tool: str
    version: str
    ecosystem: str
    project: str
    pinned_in: tuple[str, ...]


@dataclass(frozen=True)
class Result:
    pin: Pin
    latest: str | None
    status: str  # "current" | "outdated" | "ahead" | "error"
    detail: str = ""


# ---------------------------------------------------------------------------
# Loading the pins
# ---------------------------------------------------------------------------


def load_pins_module(package_root: Path = PACKAGE_ROOT) -> Any:
    """``tool_downloads`` loaded the way the container build loads it.

    Through ``install-pinned-tool``'s ``load_pins``, which imports the module by
    path without importing the package (whose ``__init__`` needs third-party
    imports), so this runs on a bare interpreter with nothing installed.
    """
    spec = importlib.util.spec_from_file_location("_ash_install_pinned_tool", INSTALLER)
    if spec is None or spec.loader is None:
        raise PinEnumerationError(f"cannot load {INSTALLER}")
    installer = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = installer
    spec.loader.exec_module(installer)
    return installer.load_pins(package_root)


def _github_project(url: str, where: str) -> str:
    """``owner/repo`` out of a github.com URL, or a refusal naming the field."""
    if not url.startswith(_GITHUB_PREFIX):
        raise PinEnumerationError(
            f"{where} is {url!r}, which is not a github.com URL; this script cannot "
            f"look up its latest release. Teach it the new host before pinning there."
        )
    parts = url[len(_GITHUB_PREFIX) :].split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise PinEnumerationError(f"{where} is {url!r}, which names no repository")
    return f"{parts[0]}/{parts[1]}"


def enumerate_pins(pins: Any) -> list[Pin]:
    """Every pin ``pins`` carries, one per tool, sorted by tool name.

    Raises:
        PinEnumerationError: when a pin cannot be attributed to an upstream, or
            when two tables disagree about one tool's version. Both are refused
            rather than skipped, because a skipped pin is a pin nobody is told about.
    """
    tool_versions: dict[str, str] = pins.TOOL_VERSIONS
    licenses: dict[str, Any] = pins.THIRD_PARTY_LICENSES
    release_urls: dict[str, str] = getattr(pins, "_RELEASE_BASE_URLS", {})

    result: list[Pin] = []
    for tool in sorted(set(tool_versions) | set(licenses)):
        entry = licenses.get(tool)
        pinned_in: list[str] = []

        if entry is not None and entry.distribution:
            if tool in tool_versions:
                raise PinEnumerationError(
                    f"{tool} is both a release-asset pin in TOOL_VERSIONS and a uv-tool "
                    f"pin (distribution {entry.distribution!r}); pick one."
                )
            result.append(
                Pin(
                    tool=tool,
                    version=entry.version,
                    ecosystem=PYPI,
                    project=entry.distribution,
                    pinned_in=("THIRD_PARTY_LICENSES (uv-tool pin)",),
                )
            )
            continue

        if tool in tool_versions:
            version = tool_versions[tool]
            pinned_in.append("TOOL_VERSIONS")
            if tool not in release_urls:
                raise PinEnumerationError(
                    f"TOOL_VERSIONS pins {tool} but _RELEASE_BASE_URLS has no entry for "
                    f"it, so its upstream is unknown."
                )
            project = _github_project(
                release_urls[tool], f"_RELEASE_BASE_URLS[{tool!r}]"
            )
            if entry is not None:
                pinned_in.append("THIRD_PARTY_LICENSES")
                if entry.version != version:
                    raise PinEnumerationError(
                        f"{tool} is {version} in TOOL_VERSIONS and {entry.version} in "
                        f"THIRD_PARTY_LICENSES; a version bump is half-applied."
                    )
        else:
            # A license-only entry: bundled, but not downloaded through this module.
            version = entry.version
            pinned_in.append("THIRD_PARTY_LICENSES")
            project = _github_project(
                entry.repository, f"THIRD_PARTY_LICENSES[{tool!r}].repository"
            )

        result.append(
            Pin(
                tool=tool,
                version=version,
                ecosystem=GITHUB,
                project=project,
                pinned_in=tuple(pinned_in),
            )
        )

    gem_version = getattr(pins, "CFN_NAG_GEM_VERSION", None)
    if gem_version is not None:
        result.append(
            Pin(
                tool=CFN_NAG_GEM,
                version=gem_version,
                ecosystem=RUBYGEMS,
                project=CFN_NAG_GEM,
                pinned_in=("CFN_NAG_GEM_VERSION",),
            )
        )

    return sorted(result, key=lambda p: p.tool)


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)(.*)$")


def parse_version(text: str) -> tuple[tuple[int, ...], tuple[int, str]]:
    """A sortable key for a release version, numeric part compared as numbers.

    ``v0.69.10`` sorts after ``v0.69.9``, ``1.2`` equals ``1.2.0``, and a final
    release sorts after any pre-release of the same numbers. Build metadata after
    ``+`` is ignored, as SemVer says it must be.

    Raises:
        ValueError: for a string with no leading numeric version.
    """
    match = _VERSION_RE.match(text.strip())
    if match is None:
        raise ValueError(f"not a version: {text!r}")
    release = tuple(int(part) for part in match.group(1).split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    suffix = match.group(2).split("+", 1)[0].lstrip("-.")
    return release, ((1, "") if not suffix else (0, suffix))


def compare(pinned: str, latest: str) -> str:
    """``current``, ``outdated`` (latest is newer) or ``ahead`` (pinned is newer)."""
    a, b = parse_version(pinned), parse_version(latest)
    if a == b:
        return "current"
    return "outdated" if a < b else "ahead"


# ---------------------------------------------------------------------------
# Upstream lookups
# ---------------------------------------------------------------------------


def _checked_url(url: str) -> str:
    """``url`` unchanged if it is https to one of ``_ALLOWED_HOSTS``; raises otherwise."""
    parts = urllib.parse.urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.hostname not in _ALLOWED_HOSTS
        or parts.username is not None
        or parts.password is not None
        or parts.port not in (None, 443)
    ):
        raise ValueError(
            f"refusing to fetch {url!r}: only https URLs on "
            f"{', '.join(sorted(_ALLOWED_HOSTS))} are looked up"
        )
    return url


def _get_json(url: str, headers: dict[str, str] | None = None) -> Any:
    request = urllib.request.Request(
        _checked_url(url), headers={"User-Agent": "ash-pin-check"}
    )
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # nosec B310 - _checked_url above allows only https to _ALLOWED_HOSTS
        return json.load(response)


def latest_github_release(project: str) -> str:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = _get_json(f"https://api.github.com/repos/{project}/releases/latest", headers)
    return str(data["tag_name"])


def latest_pypi_release(distribution: str) -> str:
    return str(
        _get_json(f"https://pypi.org/pypi/{distribution}/json")["info"]["version"]
    )


def latest_rubygems_release(gem: str) -> str:
    return str(
        _get_json(f"https://rubygems.org/api/v1/versions/{gem}/latest.json")["version"]
    )


Fetchers = dict[str, Callable[[str], str]]

DEFAULT_FETCHERS: Fetchers = {
    GITHUB: latest_github_release,
    PYPI: latest_pypi_release,
    RUBYGEMS: latest_rubygems_release,
}


def check(pins: Iterable[Pin], fetchers: Fetchers | None = None) -> list[Result]:
    """Look up each pin's latest release and classify it."""
    fetchers = fetchers or DEFAULT_FETCHERS
    results = []
    for pin in pins:
        try:
            latest = fetchers[pin.ecosystem](pin.project)
            status = compare(pin.version, latest)
        except Exception as exc:  # reported per pin, and it fails the run
            results.append(Result(pin, None, "error", f"{type(exc).__name__}: {exc}"))
            continue
        results.append(Result(pin, latest, status))
    return results


def exit_code(results: Iterable[Result], fail_on_outdated: bool) -> int:
    results = list(results)
    if any(r.status == "error" for r in results):
        return EXIT_ERROR
    if fail_on_outdated and any(r.status == "outdated" for r in results):
        return EXIT_OUTDATED
    return EXIT_OK


# ---------------------------------------------------------------------------
# What a bump has to change
# ---------------------------------------------------------------------------


def _dockerfile_args(tool: str, dockerfile: Path) -> list[str]:
    """``Dockerfile:<line>`` for each ``ARG <TOOL>_VERSION=`` line."""
    if not dockerfile.is_file():
        return []
    pattern = re.compile(rf"^\s*ARG\s+{re.escape(tool.upper())}_VERSION=")
    return [
        f"Dockerfile:{number}"
        for number, line in enumerate(
            dockerfile.read_text(encoding="utf-8").splitlines(), start=1
        )
        if pattern.match(line)
    ]


def _license_steps(pins: Any, tool: str, latest: str) -> list[str]:
    entry = pins.THIRD_PARTY_LICENSES.get(tool)
    if entry is None:
        return []
    project = _github_project(entry.repository, f"THIRD_PARTY_LICENSES[{tool!r}]")
    steps = [
        f'THIRD_PARTY_LICENSES["{tool}"].version -> {latest}',
        (
            f'_THIRD_PARTY_HASHES["{tool} commit"] -> the output of '
            f"`gh api repos/{project}/commits/{latest} --jq .sha`"
        ),
    ]
    for f in entry.files:
        if f.url:
            steps.append(
                f'_THIRD_PARTY_HASHES["{tool}/{f.name}"] -> sha256 of '
                f"https://raw.githubusercontent.com/{project}/<new commit>/{f.name}"
            )
        else:
            where = "wheel's dist-info" if entry.distribution else "release archive"
            steps.append(
                f"{f.name}: confirm the new {where} still carries it; if not, pin it "
                f"by URL and digest as the comment above THIRD_PARTY_LICENSES says"
            )
    return steps


def bump_steps(pins: Any, result: Result, dockerfile: Path = DOCKERFILE) -> list[str]:
    """Every edit a bump of ``result.pin`` to ``result.latest`` needs, in order."""
    pin, latest = result.pin, result.latest or "<latest>"
    tool = pin.tool
    steps: list[str] = []

    if pin.ecosystem == RUBYGEMS:
        return [
            f"CFN_NAG_GEM_VERSION -> {latest}",
            f'{GEMFILE}: gem "{CFN_NAG_GEM}", "{latest}"',
            (
                "automated_security_helper/assets/Gemfile.lock: regenerate with "
                f"`bundle lock --update {CFN_NAG_GEM}` in that directory"
            ),
        ]

    if "TOOL_VERSIONS" in pin.pinned_in:
        old_bare = pin.version.lstrip("v")
        filenames = list(pins._ASSET_TABLES.get(tool, {}).values())
        steps.append(f'TOOL_VERSIONS["{tool}"] -> {latest}')
        if filenames and all(old_bare in name for name in filenames):
            steps.append(
                f"asset filenames for {tool} ({len(filenames)}): replace {old_bare} "
                f"with {latest.lstrip('v')} and check each still exists upstream"
            )
        taken_at = getattr(pins, "_DIGESTS_TAKEN_AT", {})
        if tool in taken_at:
            steps.append(f'_DIGESTS_TAKEN_AT["{tool}"] -> {latest}')
        archive = [n for n in filenames if n in pins._DIGESTS]
        steps.append(
            f"_DIGESTS: {len(archive)} archive digest(s), "
            "from the release's checksums file or the asset's GitHub `digest` field"
        )
        executable = [n for n in filenames if n in pins._EXECUTABLE_DIGESTS]
        if executable:
            steps.append(
                f"_EXECUTABLE_DIGESTS: {len(executable)} executable digest(s), "
                "hashed from each verified archive's extracted member"
            )
        args = _dockerfile_args(tool, dockerfile)
        if args:
            steps.append(f"ARG {tool.upper()}_VERSION in {', '.join(args)}")

    steps += _license_steps(pins, tool, latest)
    steps.append(
        f"then `git grep -nF {pin.version.lstrip('v')}` for every other mention, and "
        "recompute the ferret-scan line ranges in .ash/.ash_community_plugins.yaml if "
        f"{PINS_FILE} lines moved"
    )
    return steps


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

_COLUMNS = ("tool", "pinned", "latest", "status", "upstream", "pinned in")


def _rows(results: list[Result]) -> list[tuple[str, ...]]:
    return [
        (
            r.pin.tool,
            r.pin.version,
            r.latest or "?",
            r.status,
            f"{r.pin.ecosystem}:{r.pin.project}",
            ", ".join(r.pin.pinned_in),
        )
        for r in results
    ]


def render_table(results: list[Result], markdown: bool = False) -> str:
    rows = _rows(results)
    if markdown:
        lines = [
            "| " + " | ".join(_COLUMNS) + " |",
            "|" + "|".join("---" for _ in _COLUMNS) + "|",
        ]
        lines += ["| " + " | ".join(row) + " |" for row in rows]
        return "\n".join(lines)
    widths = [
        max(len(c), *(len(row[i]) for row in rows)) for i, c in enumerate(_COLUMNS)
    ]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*_COLUMNS), fmt.format(*("-" * w for w in widths))]
    lines += [fmt.format(*row) for row in rows]
    return "\n".join(line.rstrip() for line in lines)


def _escape_markdown(text: str) -> str:
    """Escape ``_`` outside code spans, so ``_DIGESTS`` is not read as emphasis."""
    parts = text.split("`")
    return "`".join(
        part if i % 2 else part.replace("_", "\\_") for i, part in enumerate(parts)
    )


def render_report(pins: Any, results: list[Result], markdown: bool = False) -> str:
    out = []
    if markdown:
        out.append("## Pinned tool versions\n")
    out.append(render_table(results, markdown))

    outdated = [r for r in results if r.status == "outdated"]
    errors = [r for r in results if r.status == "error"]
    heading = "### " if markdown else ""
    bullet = "- " if markdown else "  - "

    for r in outdated:
        out.append(
            f"\n{heading}{r.pin.tool}: {r.pin.version} -> {r.latest}"
            + ("" if markdown else "\n" + "-" * 40)
        )
        out += [
            f"{bullet}{_escape_markdown(step) if markdown else step}"
            for step in bump_steps(pins, r)
        ]

    if outdated:
        out.append(
            f'\nSee "Bumping a version" in the {PINS_FILE} module docstring and '
            '"Adding a tool" in the comment above THIRD_PARTY_LICENSES for why each '
            "of these is pinned and how each value was taken."
        )
    for r in errors:
        out.append(f"\n{r.pin.tool}: lookup failed ({r.detail})")
    if not outdated and not errors:
        out.append("\nEvery pin is at its upstream's latest release.")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n", 1)[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--fail-on-outdated",
        action="store_true",
        help="exit 1 when any pin is behind its upstream's latest release",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="print a Markdown table, for $GITHUB_STEP_SUMMARY",
    )
    args = parser.parse_args(argv)

    try:
        pins = load_pins_module()
        pin_list = enumerate_pins(pins)
    except PinEnumerationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    results = check(pin_list)
    sys.stdout.write(render_report(pins, results, markdown=args.markdown))
    return exit_code(results, args.fail_on_outdated)


if __name__ == "__main__":
    sys.exit(main())
