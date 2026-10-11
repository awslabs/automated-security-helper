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

The Dockerfile's apt pins
-------------------------
Every ``apt-get install`` in the root ``Dockerfile`` names ``package=version``
(hadolint DL3008). Debian keeps one version of a package per suite, so a point
release or a security update can take a pinned version out of the archive, and the
next image build then fails with ``Version '...' for '...' was not found``. This
script reads those pins from the Dockerfile and looks each one up in the package
indexes apt reads in the image, for amd64 and arm64: the base image's Debian suite
with its ``-updates`` and ``-security`` suites (the codename comes from the
``BASE_IMAGE`` tag), and the NodeSource repository for the ``NODE_MAJOR`` the
Dockerfile configures. Each pin is reported as

* ``current``: the version apt would choose today;
* ``outdated``: still installable, but a newer version is published, typically a
  security update. Fails with ``--fail-on-outdated``, like a tool pin;
* ``unavailable``: no index carries it any more, so the image build is already
  broken. Always exits 1, and the report names the version to pin instead.

An ``apt-get install`` of a package with no ``=version`` is refused (exit 2) rather
than skipped, and so is one package pinned to two versions in different stages.

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
  lift that. A GitHub lookup that gets 403 with the token is retried once without
  it, and logs GitHub's error message to stderr; see ``_get_github_json``.
* Pre-release suffixes compare as text after the numeric part, so ``1.2.0rc10``
  sorts before ``1.2.0rc9``. The upstream APIs above return final releases, so
  the case does not arise in practice.
* An apt pin is checked against the indexes, not against a build: the report says
  what apt would find, so a dependency of a pinned package that no longer resolves
  is not caught here. Debian versions are ordered by dpkg's rules (epoch, then
  upstream version, then revision, with ``~`` sorting before everything).

Usage::

    python scripts/check_pinned_tool_versions.py
    python scripts/check_pinned_tool_versions.py --fail-on-outdated --markdown

Exit codes: 0 when no pin is behind (or ``--fail-on-outdated`` is not given),
1 when a pin is behind and ``--fail-on-outdated`` is given or when an apt pin is
unavailable, 2 when a lookup failed or the pins could not be read.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import lzma
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from http.client import HTTPMessage
from typing import IO, Any, Callable, Iterable

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

# The only hosts _get_bytes may contact: the GitHub releases API, PyPI's JSON API and
# RubyGems' API, the three upstreams the tool pins are compared against, and the Debian
# and NodeSource archives the Dockerfile's apt pins are looked up in. Every URL is built
# from a fixed https prefix today; this check makes that a property of the function
# rather than of its callers, so a later caller cannot point it at a file:// path, a
# plain-http mirror or an arbitrary host. A redirect cannot either: _CheckedRedirects
# applies the same check to every hop before it is followed.
_ALLOWED_HOSTS = frozenset(
    {
        "api.github.com",
        "pypi.org",
        "rubygems.org",
        # The archives the Dockerfile's apt pins are looked up in.
        "deb.debian.org",
        "deb.nodesource.com",
    }
)

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


def _origin(url: str) -> tuple[str, str | None, int]:
    parts = urllib.parse.urlsplit(url)
    return (
        parts.scheme,
        parts.hostname,
        parts.port or (443 if parts.scheme == "https" else 80),
    )


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    """Applies ``_checked_url`` to every redirect hop urllib would follow, before it does.

    urllib follows a 3xx to any http, https or ftp URL on its own, so without this
    the allowlist held for the first request only. A hop to one of those that fails
    the check raises ValueError. urllib refuses every other scheme (file:, data:)
    itself, with an HTTPError, before this runs, and a Location it cannot encode
    fails with UnicodeEncodeError. Each of these is a lookup error.

    The token goes with a hop only when the hop stays on the origin the token was
    sent to: the same scheme, host and port. GitHub's redirect for a renamed
    repository, to api.github.com/repositories/<id>/..., is one, and keeping the
    token there keeps its rate limit; dropping it made the anonymous limit answer
    403 on a hop the token was never sent to. Any other hop goes without it, as
    requests' ``should_strip_auth`` does.
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        try:
            _checked_url(newurl)
        except ValueError:
            fp.close()
            raise
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        token = req.unredirected_hdrs.get("Authorization")
        if new is not None and token and _origin(req.full_url) == _origin(newurl):
            new.add_unredirected_header("Authorization", token)
        return new


_OPENER = urllib.request.build_opener(_CheckedRedirects)


def _get_bytes(url: str, headers: dict[str, str] | None = None) -> bytes:
    request = urllib.request.Request(
        _checked_url(url), headers={"User-Agent": "ash-pin-check"}
    )
    for name, value in (headers or {}).items():
        if name.lower() == "authorization":
            # urllib copies a request's ordinary headers to the next hop of a
            # redirect and leaves the unredirected ones behind. _CheckedRedirects
            # puts the token back on a hop to the same origin, and only there.
            request.add_unredirected_header(name, value)
        else:
            request.add_header(name, value)
    with _OPENER.open(request, timeout=_TIMEOUT_SECONDS) as response:
        return response.read()


def _get_json(url: str, headers: dict[str, str] | None = None) -> Any:
    return json.loads(_get_bytes(url, headers))


# How much of GitHub's error message a refused request logs. Enough for any message
# GitHub sends; a bound so that an unexpected body cannot flood the job log.
_GITHUB_MESSAGE_LIMIT = 300


def _github_error_message(error: urllib.error.HTTPError, token: str) -> str:
    """The ``message`` of GitHub's JSON error body, quoted and safe to print.

    Quoted with ``repr``, so a newline in it cannot start a line of its own, which in
    a GitHub Actions log is where a workflow command would begin. The token is cut out
    before anything else, in case a body ever echoes it, and the result is truncated.
    """
    # Diagnostic only, so any failure to read the body is reported in its place
    # rather than raised: it must not decide whether the retry happens.
    try:
        body = json.loads(error.read(64 * 1024) or b"null")
    except Exception as exc:
        return f"(error body unreadable: {type(exc).__name__})"
    message = body.get("message") if isinstance(body, dict) else None
    if not isinstance(message, str):
        return "(error body has no message)"
    message = message.replace(token, "<token>")
    if len(message) > _GITHUB_MESSAGE_LIMIT:
        return repr(message[:_GITHUB_MESSAGE_LIMIT]) + " (truncated)"
    return repr(message)


def _get_github_json(path: str) -> Any:
    """``https://api.github.com/<path>``, with the token when one is set.

    Every endpoint this script reads is public: the token is sent only to lift the
    anonymous rate limit. So a 403 to the request that carries it is retried once
    without it, and the lookup fails only if that fails too. In the weekly job GitHub
    has repeatedly answered 403 to the token-carrying request for one repository
    while the same token worked for every other. Why is not established; the retry
    logs GitHub's own message so the next run shows it. Any other status, any network
    error, and a 403 with no token configured fail on the first try, as before.
    """
    url = f"https://api.github.com/{path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        return _get_json(url, headers)
    try:
        return _get_json(url, {**headers, "Authorization": f"Bearer {token}"})
    except urllib.error.HTTPError as exc:
        if exc.code != 403:
            raise
        message = _github_error_message(exc, token)
        answered = getattr(exc, "url", None) or url
    # Outside the except block, so a failed retry is reported as itself rather than
    # chained to the 403 before it. Never the headers: one of them is the token.
    if answered == url:
        what = f"GitHub answered 403 to the authenticated request for {path}"
    else:
        what = (
            f"GitHub answered 403 to {answered!r}, which the request for {path} "
            f"was redirected to"
        )
    print(
        f"warning: {what}; GitHub's message: {message}. "
        f"Retrying once without the token.",
        file=sys.stderr,
    )
    return _get_json(url, headers)


def latest_github_release(project: str) -> str:
    return str(_get_github_json(f"repos/{project}/releases/latest")["tag_name"])


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
# The Dockerfile's apt pins
# ---------------------------------------------------------------------------

APT_ARCHITECTURES = ("amd64", "arm64")

# Where each archive publishes the per-architecture index apt reads. {suite} and
# {arch} are filled in per lookup; {major} is the Dockerfile's NODE_MAJOR.
_DEBIAN_INDEX = (
    "https://deb.debian.org/debian/dists/{suite}/main/binary-{arch}/Packages.xz"
)
_DEBIAN_SECURITY_INDEX = "https://deb.debian.org/debian-security/dists/{suite}/main/binary-{arch}/Packages.xz"
_NODESOURCE_INDEX = "https://deb.nodesource.com/node_{major}.x/dists/nodistro/main/binary-{arch}/Packages"

_APT_INSTALL = re.compile(
    r"(?<![\w-])apt-get\s[^;&|]*?(?<![\w-])install(?![\w-])(?P<args>[^;&|]*)"
)
_APT_PIN = re.compile(
    r"^(?P<package>[a-z0-9][a-z0-9+.-]+)=(?P<version>[A-Za-z0-9.+~:-]+)$"
)


@dataclass(frozen=True)
class AptPin:
    package: str
    version: str
    lines: tuple[int, ...]  # Dockerfile line numbers that carry this pin


@dataclass(frozen=True)
class AptIndex:
    label: str  # e.g. "bookworm-security"
    url: str  # with {arch} still to fill in


@dataclass(frozen=True)
class AptResult:
    pin: AptPin
    arch: str
    candidate: str | None  # the version apt would choose, across every index
    status: str  # "current" | "outdated" | "unavailable" | "error"
    detail: str = ""


def _run_blocks(text: str) -> list[list[tuple[int, str]]]:
    """Each RUN instruction as its (line number, text) lines, comments dropped."""
    blocks: list[list[tuple[int, str]]] = []
    current: list[tuple[int, str]] | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if current is None:
            if not re.match(r"^RUN\s", line):
                continue
            current = []
            line = line[3:].strip()
        elif line.startswith("#"):
            continue
        continued = line.endswith("\\")
        current.append((number, line[:-1] if continued else line))
        if not continued:
            blocks.append(current)
            current = None
    return blocks


def enumerate_apt_pins(dockerfile: Path = DOCKERFILE) -> list[AptPin]:
    """Every ``package=version`` an ``apt-get install`` in ``dockerfile`` names.

    Raises:
        PinEnumerationError: for an installed package with no ``=version``, or one
            pinned to two different versions. Both are refused rather than skipped:
            the first is a pin this check cannot see, the second is two images.
    """
    versions: dict[str, str] = {}
    lines: dict[str, list[int]] = {}
    for block in _run_blocks(dockerfile.read_text(encoding="utf-8")):
        joined = " ".join(text for _, text in block)
        for match in _APT_INSTALL.finditer(joined):
            for word in match.group("args").split():
                if word.startswith("-"):
                    continue
                pin = _APT_PIN.match(word)
                if pin is None:
                    raise PinEnumerationError(
                        f"{dockerfile.name}:{block[0][0]} installs {word!r} with apt-get "
                        "and no version. Pin it as package=version; see the comment "
                        "above the first apt-get install for where versions come from."
                    )
                package, version = pin.group("package"), pin.group("version")
                if versions.setdefault(package, version) != version:
                    raise PinEnumerationError(
                        f"{package} is pinned to {versions[package]} and to {version} "
                        f"in {dockerfile.name}; every stage has to install the same one."
                    )
                lines.setdefault(package, []).extend(
                    number
                    for number, text in block
                    if word in re.split(r"[\s;&|]+", text)
                )
    return [
        AptPin(package, versions[package], tuple(sorted(set(lines[package]))))
        for package in sorted(versions)
    ]


def apt_indexes(dockerfile: Path = DOCKERFILE) -> list[AptIndex]:
    """The indexes apt reads in the image the Dockerfile builds.

    The Debian codename is the last ``-`` part of the ``BASE_IMAGE`` default's tag
    (``python:3.12-slim-bookworm``), and the NodeSource repository is the one
    ``NODE_MAJOR`` names, so a base-image or Node bump moves the lookup with it.
    """
    text = dockerfile.read_text(encoding="utf-8")
    base = re.search(r"^ARG BASE_IMAGE=\S+:(?P<tag>\S+)$", text, re.MULTILINE)
    codename = base.group("tag").rsplit("-", 1)[-1] if base else ""
    if not re.fullmatch(r"[a-z]+", codename):
        raise PinEnumerationError(
            f"cannot read a Debian codename from {dockerfile.name}'s ARG BASE_IMAGE; "
            "the apt pins cannot be looked up without knowing which suite apt reads."
        )
    indexes = [
        AptIndex(codename, _DEBIAN_INDEX.format(suite=codename, arch="{arch}")),
        AptIndex(
            f"{codename}-updates",
            _DEBIAN_INDEX.format(suite=f"{codename}-updates", arch="{arch}"),
        ),
        AptIndex(
            f"{codename}-security",
            _DEBIAN_SECURITY_INDEX.format(suite=f"{codename}-security", arch="{arch}"),
        ),
    ]
    node = re.search(r"\bNODE_MAJOR=(?P<major>\d+)\b", text)
    if node is not None:
        major = node.group("major")
        indexes.append(
            AptIndex(
                f"nodesource node_{major}.x",
                _NODESOURCE_INDEX.format(major=major, arch="{arch}"),
            )
        )
    return indexes


def parse_packages_index(text: str) -> dict[str, set[str]]:
    """Package name -> every version a Debian ``Packages`` index lists for it."""
    found: dict[str, set[str]] = {}
    for stanza in re.split(r"\n\s*\n", text):
        fields = dict(
            line.split(": ", 1)
            for line in stanza.splitlines()
            if ": " in line and not line.startswith((" ", "\t"))
        )
        if "Package" in fields and "Version" in fields:
            found.setdefault(fields["Package"], set()).add(fields["Version"].strip())
    return found


def _dpkg_order(char: str) -> int:
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _dpkg_compare_part(a: str, b: str) -> int:
    """dpkg's verrevcmp: alternating non-digit and digit runs."""
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (
            j < len(b) and not b[j].isdigit()
        ):
            ac = _dpkg_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _dpkg_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_debian_version(version: str) -> tuple[int, str, str]:
    epoch, _, rest = version.rpartition(":") if ":" in version else ("0", "", version)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch or 0), upstream, revision


def compare_debian_versions(a: str, b: str) -> int:
    """Negative, zero or positive as ``a`` sorts before, with or after ``b``."""
    ea, ua, ra = _split_debian_version(a)
    eb, ub, rb = _split_debian_version(b)
    if ea != eb:
        return ea - eb
    return _dpkg_compare_part(ua, ub) or _dpkg_compare_part(ra, rb)


def _newest(versions: Iterable[str]) -> str | None:
    newest = None
    for version in versions:
        if newest is None or compare_debian_versions(version, newest) > 0:
            newest = version
    return newest


def fetch_index(url: str) -> str:
    """One ``Packages`` index as text, decompressing ``.xz``."""
    data = _get_bytes(url)
    if url.endswith(".xz"):
        data = lzma.decompress(data)
    return data.decode("utf-8")


def check_apt(
    pins: Iterable[AptPin],
    indexes: Iterable[AptIndex],
    fetch: Callable[[str], str] = fetch_index,
    architectures: Iterable[str] = APT_ARCHITECTURES,
) -> list[AptResult]:
    """Each pin against every index, once per architecture."""
    pins, indexes = list(pins), list(indexes)
    results: list[AptResult] = []
    for arch in architectures:
        available: dict[str, set[str]] = {}
        failed: list[str] = []
        for index in indexes:
            url = index.url.format(arch=arch)
            try:
                listed = parse_packages_index(fetch(url))
            except Exception as exc:  # reported per pin, and it fails the run
                failed.append(f"{index.label} ({url}): {type(exc).__name__}: {exc}")
                continue
            for package, versions in listed.items():
                available.setdefault(package, set()).update(versions)
        for pin in pins:
            versions = available.get(pin.package, set())
            candidate = _newest(versions)
            if failed:
                results.append(
                    AptResult(pin, arch, candidate, "error", "; ".join(failed))
                )
            elif candidate is None:
                # Gone altogether, not merely moved on: apt cannot install it at any
                # version, so the build is as broken as for a retired version.
                results.append(
                    AptResult(
                        pin, arch, None, "unavailable", "no index lists the package"
                    )
                )
            elif pin.version not in versions:
                results.append(AptResult(pin, arch, candidate, "unavailable"))
            elif compare_debian_versions(candidate, pin.version) > 0:
                results.append(AptResult(pin, arch, candidate, "outdated"))
            else:
                results.append(AptResult(pin, arch, candidate, "current"))
    return results


def render_apt_report(results: list[AptResult], markdown: bool = False) -> str:
    columns = (
        "package",
        "pinned",
        "arch",
        "apt would choose",
        "status",
        "Dockerfile lines",
    )
    rows = [
        (
            r.pin.package,
            r.pin.version,
            r.arch,
            r.candidate or "?",
            r.status,
            ", ".join(str(n) for n in r.pin.lines),
        )
        for r in results
    ]
    out = ["## Dockerfile apt pins\n" if markdown else "\nDockerfile apt pins"]
    if markdown:
        out.append("| " + " | ".join(columns) + " |")
        out.append("|" + "|".join("---" for _ in columns) + "|")
        out += ["| " + " | ".join(row) + " |" for row in rows]
    else:
        widths = [
            max(len(c), *(len(row[i]) for row in rows)) for i, c in enumerate(columns)
        ]
        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
        out.append(fmt.format(*columns))
        out.append(fmt.format(*("-" * w for w in widths)))
        out += [fmt.format(*row).rstrip() for row in rows]

    bullet = "- " if markdown else "  - "
    seen: set[tuple[str, str]] = set()
    for r in results:
        if r.status not in ("unavailable", "outdated"):
            continue
        if (r.pin.package, r.candidate) in seen:
            continue
        seen.add((r.pin.package, r.candidate))
        lines = ", ".join(f"Dockerfile:{n}" for n in r.pin.lines)
        if r.candidate is None:
            edit = f"{r.pin.package}={r.pin.version}"
            why = "no index lists the package any more; the image build fails now"
        else:
            edit = f"{r.pin.package}={r.pin.version} -> {r.pin.package}={r.candidate}"
            why = (
                "no longer in any index, so the image build fails now"
                if r.status == "unavailable"
                else "a newer version is published"
            )
        out.append(
            f"{bullet}{'`' + edit + '`' if markdown else edit} in {lines}: {why}"
        )
    for r in results:
        if r.status == "error":
            out.append(
                f"{bullet}{r.pin.package} ({r.arch}): lookup failed ({r.detail})"
            )
    if all(r.status == "current" for r in results):
        out.append("\nEvery apt pin is the version apt would choose today.")
    return "\n".join(out) + "\n"


# What main() fetches apt indexes with. A module global so tests can replace it, as
# they replace DEFAULT_FETCHERS, and never reach the network.
APT_INDEX_FETCHER: Callable[[str], str] = fetch_index


def apt_exit_code(results: Iterable[AptResult], fail_on_outdated: bool) -> int:
    results = list(results)
    if any(r.status == "error" for r in results):
        return EXIT_ERROR
    if any(r.status == "unavailable" for r in results):
        return EXIT_OUTDATED
    if fail_on_outdated and any(r.status == "outdated" for r in results):
        return EXIT_OUTDATED
    return EXIT_OK


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
        apt_pins = enumerate_apt_pins()
        indexes = apt_indexes()
    except PinEnumerationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    results = check(pin_list)
    apt_results = check_apt(apt_pins, indexes, APT_INDEX_FETCHER)
    sys.stdout.write(render_report(pins, results, markdown=args.markdown))
    sys.stdout.write(render_apt_report(apt_results, markdown=args.markdown))
    # The worse of the two, where an error (2) outranks a failing pin (1).
    return max(
        exit_code(results, args.fail_on_outdated),
        apt_exit_code(apt_results, args.fail_on_outdated),
    )


if __name__ == "__main__":
    sys.exit(main())
