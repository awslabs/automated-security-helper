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

There is no second list of versions here. The pins come from ``TOOL_VERSIONS``,
``THIRD_PARTY_LICENSES`` and ``CFN_NAG_GEM_VERSION``, so a tool pinned in any of them
is checked without editing this file. A pin kept in a new module-level name would not
be; ``tests/unit/test_pinned_tool_version_check.py`` fails on any module
global named like a version pin that ``PIN_SOURCES`` below does not name.

Tools that CI, the packaging harnesses and the editor test images pin outside that
module (kind, kubectl, cfn-guard, winget-cli, VS Code, the harness uv, actionlint,
shellcheck, the digest-pinned gradle, node, python and kind node images, and the
dated Debian and Ubuntu package snapshots) are listed in ``REPO_PINS``. That table
names where each pin is written and how to read it, not its value: the value is
read from the file every run, so it cannot drift from what CI uses. Each site must
match the number of times it says, and every site of one tool must agree, so a
moved line or a half-applied bump is refused rather than skipped. The same test file
runs a census of version and image pins under ``.github/workflows``,
``.github/actions``, ``packaging``, ``editors`` and ``deploy``, and fails on one that
neither ``REPO_PINS`` nor its short list of reasoned exemptions accounts for.

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
  skips drafts and pre-releases), PyPI's ``info.version``, RubyGems'
  ``latest.json`` and, for an image pinned as ``name:tag@sha256:...``, the digest
  Docker Hub reports for that tag today. A project that marks a release "latest"
  out of version order is reported as it marks it.
* An image digest is compared for equality only. A changed digest means the tag
  was rebuilt (usually a base-image security update), and is reported as
  ``outdated``; it says nothing about whether a newer tag exists.
* A dated package snapshot has no "latest". It is ``outdated`` once it is older
  than ``SNAPSHOT_MAX_AGE_DAYS``, because past that its packages miss the security
  updates published since.
* The uv the packaging harnesses install is held to the floor ``pyproject.toml``
  declares, deliberately, so the harness proves the oldest supported uv works. It is
  compared with that floor, not with uv's latest release.
* An image pinned by digest with no tag (``debian@sha256:...``) names no tag to
  look up, so it is not checked; the census exempts those by shape.
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
from datetime import datetime, timezone
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
DOCKER_HUB = "docker-hub-tag"
SNAPSHOT = "dated-snapshot"
PYPROJECT_FLOOR = "pyproject-floor"

# How old a dated package snapshot may get before it is reported as outdated.
SNAPSHOT_MAX_AGE_DAYS = 180
_SNAPSHOT_FORMAT = "%Y%m%dT%H%M%SZ"

_GITHUB_PREFIX = "https://github.com/"
_TIMEOUT_SECONDS = 30

# The only hosts _get_json may contact: the GitHub releases API, PyPI's JSON API,
# RubyGems' API and Docker Hub's tag API, the upstreams the pins are compared against. Every URL is built
# from a fixed https prefix today; this check makes that a property of the function
# rather than of its callers, so a later caller cannot point it at a file:// path, a
# plain-http mirror or an arbitrary host.
_ALLOWED_HOSTS = frozenset(
    {"api.github.com", "pypi.org", "rubygems.org", "hub.docker.com"}
)

EXIT_OK = 0
EXIT_OUTDATED = 1
EXIT_ERROR = 2


class PinEnumerationError(Exception):
    """The pins module is in a state this script cannot read a pin from."""


@dataclass(frozen=True)
class Pin:
    """One pinned tool and where its upstream publishes releases.

    ``version`` is spelled exactly as the module spells it, leading ``v`` and all
    (an image digest for a Docker Hub pin, a timestamp for a snapshot). ``project``
    is ``owner/repo`` for a GitHub release, the distribution name for PyPI and for
    a pyproject floor, the gem name for RubyGems, ``name:tag`` for an image and the
    archive for a snapshot. ``pinned_in`` names the module tables that
    carry this tool's version, which is what a bump has to edit.
    """

    tool: str
    version: str
    ecosystem: str
    project: str
    pinned_in: tuple[str, ...]
    # ``path:line`` of every place a REPO_PINS pin is written. Empty for module pins.
    sites: tuple[str, ...] = ()


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
# Pins outside tool_downloads.py
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PinSite:
    """One place a pin is written: a file, a regex whose group 1 is the value, and
    how many times it must match there."""

    path: str
    pattern: str
    count: int = 1


@dataclass(frozen=True)
class RepoPin:
    tool: str
    ecosystem: str
    # The upstream to compare with. Empty for a Docker Hub pin, whose ``name:tag``
    # is read from the pinned reference itself.
    project: str
    sites: tuple[PinSite, ...]


def _image_ref(name: str) -> str:
    """A regex for ``<name>:<tag>@sha256:<digest>``, the whole reference as group 1."""
    return rf"(?<![\w./-])({re.escape(name)}:[A-Za-z0-9._-]+@sha256:[0-9a-f]{{64}})"


_K8S_WORKFLOW = ".github/workflows/ash-kubernetes-operator.yml"
_VSCODE_VISUAL = "editors/vscode/test/visual/Dockerfile"
_JETBRAINS_UI = "editors/jetbrains/ui-test/Dockerfile"

REPO_PINS: tuple[RepoPin, ...] = (
    RepoPin(
        "kind",
        GITHUB,
        "kubernetes-sigs/kind",
        (PinSite(_K8S_WORKFLOW, r"^  KIND_VERSION: (v[0-9][0-9.]*)$"),),
    ),
    RepoPin(
        "kubectl",
        GITHUB,
        "kubernetes/kubernetes",
        (PinSite(_K8S_WORKFLOW, r"^  KUBECTL_VERSION: (v[0-9][0-9.]*)$"),),
    ),
    RepoPin(
        "cfn-guard",
        GITHUB,
        "aws-cloudformation/cloudformation-guard",
        (
            PinSite(
                ".github/workflows/ash-iac-drift.yml",
                r'^\s+CFN_GUARD_VERSION: "([0-9][0-9.]*)"$',
            ),
        ),
    ),
    RepoPin(
        "winget-cli",
        GITHUB,
        "microsoft/winget-cli",
        (
            PinSite(
                "packaging/winget/verify-on-windows.ps1",
                r"^\$WingetReleaseTag = '(v[0-9][0-9.]*)'$",
            ),
        ),
    ),
    RepoPin(
        "vscode",
        GITHUB,
        "microsoft/vscode",
        (
            PinSite(_VSCODE_VISUAL, r"^ARG VSCODE_VERSION=([0-9][0-9.]*)$"),
            PinSite(
                ".github/workflows/ash-vscode-extension.yml",
                r'^\s+ASH_IT_VSCODE_VERSION: "([0-9][0-9.]*)"$',
                count=2,
            ),
        ),
    ),
    RepoPin(
        "actionlint",
        GITHUB,
        "rhysd/actionlint",
        (
            PinSite(
                ".github/workflows/ash-unified-ci.yml",
                r'^\s+ACTIONLINT_VERSION: "([0-9][0-9.]*)"$',
            ),
        ),
    ),
    RepoPin(
        "shellcheck",
        GITHUB,
        "koalaman/shellcheck",
        (
            PinSite(
                ".github/workflows/ash-unified-ci.yml",
                r'^\s+SHELLCHECK_VERSION: "([0-9][0-9.]*)"$',
            ),
        ),
    ),
    RepoPin(
        "uv (packaging harnesses)",
        PYPROJECT_FLOOR,
        "uv",
        (
            PinSite("packaging/verify-lib.sh", r"^UV_VERSION=([0-9][0-9.]*)$"),
            PinSite(
                ".github/workflows/ash-native-packages.yml",
                r'^          version: "([0-9][0-9.]*)"$',
            ),
        ),
    ),
    RepoPin(
        "gradle image",
        DOCKER_HUB,
        "",
        (
            PinSite(
                ".github/workflows/ash-jetbrains-ci.yml", _image_ref("gradle"), count=3
            ),
            # The release build of the plugin zip uses the same image, so it moves with
            # the three above.
            PinSite(".github/workflows/ash-release-assets.yml", _image_ref("gradle")),
            PinSite(_JETBRAINS_UI, _image_ref("gradle")),
        ),
    ),
    RepoPin(
        "node image",
        DOCKER_HUB,
        "",
        (PinSite(_VSCODE_VISUAL, _image_ref("node")),),
    ),
    RepoPin(
        "python image",
        DOCKER_HUB,
        "",
        (
            # Two stages, the wheel build and the runtime, on the same digest.
            PinSite(
                "deploy/kubernetes-operator/Dockerfile", _image_ref("python"), count=2
            ),
            PinSite(
                "deploy/kubernetes-operator/tests/e2e/Dockerfile.ash",
                _image_ref("python"),
                count=2,
            ),
        ),
    ),
    RepoPin(
        "kind node image",
        DOCKER_HUB,
        "",
        (
            PinSite(
                "deploy/kubernetes-operator/tests/e2e/conftest.py",
                _image_ref("kindest/node"),
            ),
        ),
    ),
    RepoPin(
        "debian snapshot",
        SNAPSHOT,
        "snapshot.debian.org",
        (PinSite(_VSCODE_VISUAL, r"^ARG DEBIAN_SNAPSHOT=([0-9]{8}T[0-9]{6}Z)$"),),
    ),
    RepoPin(
        "ubuntu snapshot",
        SNAPSHOT,
        "snapshot.ubuntu.com",
        (PinSite(_JETBRAINS_UI, r"^ARG UBUNTU_SNAPSHOT=([0-9]{8}T[0-9]{6}Z)$"),),
    ),
)


def _read_site(repo_root: Path, tool: str, site: PinSite) -> list[tuple[str, str]]:
    """``(value, "path:line")`` for each match of ``site``, exactly ``site.count``."""
    path = repo_root / site.path
    if not path.is_file():
        raise PinEnumerationError(f"{tool}: {site.path} does not exist")
    pattern = re.compile(site.pattern, re.MULTILINE)
    text = path.read_text(encoding="utf-8")
    found = [
        (m.group(1), f"{site.path}:{text.count(chr(10), 0, m.start(1)) + 1}")
        for m in pattern.finditer(text)
    ]
    if len(found) != site.count:
        raise PinEnumerationError(
            f"{tool}: expected {site.count} pin(s) in {site.path} matching "
            f"{site.pattern!r}, found {len(found)}. The line moved or changed shape; "
            f"update REPO_PINS in {Path(__file__).name} with it."
        )
    return found


def enumerate_repo_pins(
    repo_root: Path = REPO_ROOT, table: Iterable[RepoPin] = REPO_PINS
) -> list[Pin]:
    """Every ``REPO_PINS`` pin, its value read from the files that carry it.

    Raises:
        PinEnumerationError: when a site matches other than its count, or when the
            sites of one tool disagree, which is a half-applied bump.
    """
    result = []
    for repo_pin in table:
        found = [
            hit
            for site in repo_pin.sites
            for hit in _read_site(repo_root, repo_pin.tool, site)
        ]
        values = sorted({value for value, _ in found})
        if len(values) != 1:
            raise PinEnumerationError(
                f"{repo_pin.tool} is pinned to {len(values)} different values "
                f"({', '.join(where + ' ' + v for v, where in found)}); a bump is "
                f"half-applied."
            )
        value = values[0]
        project, version = repo_pin.project, value
        if repo_pin.ecosystem == DOCKER_HUB:
            project, version = value.split("@", 1)
        result.append(
            Pin(
                tool=repo_pin.tool,
                version=version,
                ecosystem=repo_pin.ecosystem,
                project=project,
                pinned_in=tuple(dict.fromkeys(s.path for s in repo_pin.sites)),
                sites=tuple(where for _, where in found),
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


def snapshot_age_days(pinned: str, now: str) -> float:
    """Days from a ``YYYYMMDDTHHMMSSZ`` snapshot to ``now``, in the same format."""
    then = datetime.strptime(pinned, _SNAPSHOT_FORMAT).replace(tzinfo=timezone.utc)
    later = datetime.strptime(now, _SNAPSHOT_FORMAT).replace(tzinfo=timezone.utc)
    return (later - then).total_seconds() / 86400


def compare_pin(pin: Pin, latest: str) -> str:
    """``compare`` for version pins; equality for digests; age for snapshots."""
    if pin.ecosystem == DOCKER_HUB:
        return "current" if pin.version == latest else "outdated"
    if pin.ecosystem == SNAPSHOT:
        age = snapshot_age_days(pin.version, latest)
        if age < 0:
            return "ahead"
        return "outdated" if age > SNAPSHOT_MAX_AGE_DAYS else "current"
    return compare(pin.version, latest)


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


def latest_docker_hub_digest(reference: str) -> str:
    """The digest Docker Hub reports today for ``name:tag`` (``library/`` implied)."""
    name, tag = reference.rsplit(":", 1)
    namespace, _, repository = name.rpartition("/")
    namespace, repository, tag = (
        urllib.parse.quote(part, safe="")
        for part in (namespace or "library", repository, tag)
    )
    data = _get_json(
        f"https://hub.docker.com/v2/namespaces/{namespace}/repositories/"
        f"{repository}/tags/{tag}"
    )
    return str(data["digest"])


def snapshot_now(_archive: str) -> str:
    """The current time in snapshot format; a snapshot is compared with its age."""
    return datetime.now(timezone.utc).strftime(_SNAPSHOT_FORMAT)


def pyproject_floor(distribution: str, pyproject: Path | None = None) -> str:
    """The ``>=`` floor a quoted ``pyproject.toml`` requirement declares for ``distribution``.

    Read as text, not with tomllib, so the script still runs on the bare interpreters
    the rest of it supports. Only a requirement string that starts with the name, as
    a dependency list entry does, is read.
    """
    path = pyproject or REPO_ROOT / "pyproject.toml"
    pattern = re.compile(
        rf'^\s*"{re.escape(distribution)}\s*>=\s*([0-9][0-9.]*)[,"]',
        re.MULTILINE | re.IGNORECASE,
    )
    floors = sorted(set(pattern.findall(path.read_text(encoding="utf-8"))))
    if len(floors) != 1:
        raise LookupError(
            f"pyproject.toml declares {len(floors)} >= floors for {distribution} "
            f"({', '.join(floors) or 'none'}); expected exactly one"
        )
    return floors[0]


Fetchers = dict[str, Callable[[str], str]]

DEFAULT_FETCHERS: Fetchers = {
    GITHUB: latest_github_release,
    PYPI: latest_pypi_release,
    RUBYGEMS: latest_rubygems_release,
    DOCKER_HUB: latest_docker_hub_digest,
    SNAPSHOT: snapshot_now,
    PYPROJECT_FLOOR: pyproject_floor,
}


def check(pins: Iterable[Pin], fetchers: Fetchers | None = None) -> list[Result]:
    """Look up each pin's latest release and classify it."""
    fetchers = fetchers or DEFAULT_FETCHERS
    results = []
    for pin in pins:
        try:
            latest = fetchers[pin.ecosystem](pin.project)
            status = compare_pin(pin, latest)
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

    if pin.sites:
        new_value = latest
        if pin.ecosystem == SNAPSHOT:
            new_value = "a recent instant"
        steps += [f"{site}: {pin.version} -> {new_value}" for site in pin.sites]
        steps.append(
            "re-take every digest recorded beside those lines (release checksums, "
            "image digests) from the new value's own published files"
        )
        return steps

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
        pin_list = enumerate_pins(pins) + enumerate_repo_pins()
    except PinEnumerationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    results = check(pin_list)
    sys.stdout.write(render_report(pins, results, markdown=args.markdown))
    return exit_code(results, args.fail_on_outdated)


if __name__ == "__main__":
    sys.exit(main())
