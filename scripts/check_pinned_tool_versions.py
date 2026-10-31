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
at each tool's release commit, the cfn-nag gem and the Bundler the image installs it
with. Nothing told anyone when one of
those fell behind. Dependabot reads lockfiles and manifests; a Python dict is
neither, so it never sees these pins, and the module's own guidance describes a bump
as a manual edit of both digest tables. A pin that nobody is reminded about stays
where it was set, including past the upstream release that fixes a vulnerability
the scanner exists to find.

This script reads the pins from the module itself and asks each upstream for its
latest release: the GitHub releases API for the release binaries and the rules
bundles, PyPI's JSON API for the uv-tool pins, and the RubyGems API for the gems. It
prints pinned against latest, and for each pin that is behind, every value a bump has
to change: the module's entries, the Dockerfile ARG, and each tracked file that
repeats one of the pin's digests. ``.github/workflows/ash-pinned-tool-versions.yml``
runs it weekly with ``--fail-on-outdated``.

There is no second list of tools here. The pins come from ``TOOL_VERSIONS``,
``THIRD_PARTY_LICENSES``, ``RULES_BUNDLES``, ``CFN_NAG_GEM_VERSION`` and
``BUNDLER_VERSION``, so a tool pinned in any of them is checked without editing this
file. A pin kept in a new module-level name would not be;
``tests/unit/test_pinned_tool_version_check.py`` fails on any module global named
like a version pin that ``PIN_SOURCES`` below does not name, and on any Dockerfile
``ARG <NAME>_VERSION`` that no pin owns.

Each pin is one of ``PIN_KINDS``, and each kind has its own bump steps. A license
entry that no download pin names is refused, because what a bump of it changes is
kept somewhere this script does not read. The same test file builds the steps for
every real pin and fails when one leaves out a value a bump changes, read
independently from the module's tables, the Dockerfile and the tracked files.

The Dockerfile's apt pins
-------------------------
Every ``apt-get install`` in the root ``Dockerfile`` names ``package=version``
(hadolint DL3008). Debian keeps one version of a package per suite, so a point
release or a security update can take a pinned version out of the archive, and the
next image build then fails with ``Version '...' for '...' was not found``. This
script reads those pins from the Dockerfile and looks each one up in the package
indexes apt reads in the image, for amd64 and arm64: the base image's Debian suite
with its ``-updates`` and ``-security`` suites (the codename comes from the
``BASE_IMAGE`` tag), and the NodeSource repository for the major the Dockerfile
configures, in ``NODE_MAJOR`` or in a ``node_<major>.x`` or ``setup_<major>.x`` URL.
Each pin is reported as

* ``current``: the version apt would choose today;
* ``outdated``: still installable, but a newer version is published, typically a
  security update. Fails with ``--fail-on-outdated``, like a tool pin;
* ``unavailable``: no index carries it any more, so the image build is already
  broken. Always exits 1, and the report names the version to pin instead.

An ``apt-get install`` of a package with no ``=version`` is refused (exit 2) rather
than skipped, and so is one package pinned to two versions in different stages. The
install is found in a ``RUN`` of any case, whether written in shell form, as an exec
form array or as a here-document, and whether spelled ``apt-get`` or ``apt``. The body
of a here-document that a copying command writes to a file (``cat > setup.sh <<'EOF'``)
is read too, because the file may be run later in the build: an unpinned package in it
is refused and a pinned one is looked up. Only a positional parameter in it (``"$@"``,
``$1``, ``${2}``), which is whatever the script's caller passes, is not a package; a
named variable (``$PKGS``) or a command substitution (``$(cat list)``) is refused as it
is in a plain ``RUN``, because the packages it names cannot be looked up, and so is a
pin whose version is an expansion (``jq=${JQ_VERSION}``), which is refused as a version
this check cannot read. A body is a file's content only when the command it is given to
is a copier (``cat``, ``tee``, ``install`` or ``cp`` of ``/dev/stdin``, ``dd``) and
every command it is piped on to is a copier that writes a file; a body given to any
other command, ``xargs apt-get install -y <<'EOF' > log`` among them, is that command's
input, so its words are read as part of the ``RUN``. Such a body is read as a file only
when its marker is quoted (``<<'EOF'``);
an unquoted marker has the build shell expand the body first, so it is read as the
``RUN`` text it becomes. Every file body is read as shell, whatever the file is. A body
that is not a script, a motd or a README that mentions ``apt-get install``, is skipped
by putting ``# apt-pin-check: skip`` on a line of its own directly above its ``RUN``
(blank lines and other comments between them are allowed). An option that takes its
value as a separate word (``-t suite``, ``-o Name=value``) and a redirection are not
packages. An install that xargs runs on words it reads from a here-document, a file
(``< list``, ``-a list``), a here-string or a pipe is refused, because those words are
not arguments of the install in the Dockerfile; packages written as arguments of the
install (``xargs apt-get install -y curl=1.2``) are read like any other. A Dockerfile
that configures NodeSource without a major this script can
read, or with two different majors, is refused too, because the nodejs pin would be
looked up in Debian's own nodejs or in the wrong NodeSource index.

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
  skips drafts and pre-releases) and PyPI's ``info.version``. A project that marks a
  release "latest" out of version order is reported as it marks it.
* A gem is compared with the newest final release for the ``ruby`` platform whose
  required Ruby version admits the Ruby the image installs, read from the
  Dockerfile's ``ruby=`` apt pin, so ``--fail-on-outdated`` fails only when the image
  could install a newer release. A newer release that needs a newer Ruby is named in
  the report and does not fail. The apt pin gives only major.minor, so the image's
  Ruby is compared as major.minor.0, and a release needing a later patch of the same
  minor is not counted. A Ruby pin or a required Ruby version this script cannot read
  is refused (exit 2), not guessed at. A release's required RubyGems version is compared
  with ``IMAGE_RUBYGEMS``, the RubyGems the Debian Ruby package bundles. The Dockerfile
  does not pin it, so the number is the upstream one for that Ruby and a test ties it to
  the Dockerfile's ``ruby=`` pin; Debian's own build was not read.
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
* A positional parameter in a script the Dockerfile writes to a file
  (``apt-get install -y "$@"``) is skipped: it is whatever the script's caller passes,
  and the caller's own install is checked where the caller is. A script whose caller is
  outside the Dockerfile, run with packages from a build argument or a mounted file,
  installs packages this check never reads.

Usage::

    python scripts/check_pinned_tool_versions.py
    python scripts/check_pinned_tool_versions.py --fail-on-outdated --markdown

Exit codes: 0 when no pin is behind (or ``--fail-on-outdated`` is not given),
1 when a pin is behind and ``--fail-on-outdated`` is given or when an apt pin is
unavailable, 2 when a lookup failed or the pins could not be read.
"""

from __future__ import annotations

import argparse
import ast
import base64
import importlib.util
import json
import lzma
import os
import re
import subprocess  # nosec B404 - git grep over this checkout, for bump steps only
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
PIN_SOURCES = (
    "TOOL_VERSIONS",
    "THIRD_PARTY_LICENSES",
    "RULES_BUNDLES",
    "CFN_NAG_GEM_VERSION",
    "BUNDLER_VERSION",
)

# The kinds of pin enumerate_pins reports. bump_steps has steps for each, and a pin of
# any other shape is refused when the pins are read, rather than given steps that
# leave out what a bump of it changes.
RELEASE_BINARY = "release-binary"  # TOOL_VERSIONS: one release asset per platform
UV_TOOL = "uv-tool"  # THIRD_PARTY_LICENSES with a distribution: a PyPI release
RULES_BUNDLE = "rules-bundle"  # RULES_BUNDLES: one release archive of rule files
GEM = "gem"  # GEM_PINS: a RubyGems release
# THIRD_PARTY_LICENSES with bundled_in: a library another pinned wheel carries, whose
# version is that wheel's. Listed and held, never looked up (see BUNDLED below).
BUNDLED_LIBRARY = "bundled-library"
PIN_KINDS = (RELEASE_BINARY, UV_TOOL, RULES_BUNDLE, GEM, BUNDLED_LIBRARY)

# The gem CFN_NAG_GEM_VERSION is the version of; see assets/Gemfile.
CFN_NAG_GEM = "cfn-nag"
# The Bundler the image installs cfn-nag's gems with; see the Dockerfile.
BUNDLER_GEM = "bundler"

# Each gem pin, by gem name, and the tool_downloads.py global holding its version.
GEM_PINS = {CFN_NAG_GEM: "CFN_NAG_GEM_VERSION", BUNDLER_GEM: "BUNDLER_VERSION"}

GITHUB = "github-release"
PYPI = "pypi"
RUBYGEMS = "rubygems"
# A library another pinned distribution bundles (a shared library auditwheel grafted
# into a wheel). Its version is whatever that wheel carries and cannot be bumped on its
# own, so it is listed but never looked up: comparing it with its project's latest
# release would report a bump nobody can make.
BUNDLED = "bundled"

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
    carry this tool's version, which is what a bump has to edit. ``kind`` is one of
    ``PIN_KINDS``, and decides which steps ``bump_steps`` gives.
    """

    tool: str
    version: str
    ecosystem: str
    project: str
    pinned_in: tuple[str, ...]
    kind: str


@dataclass(frozen=True)
class Result:
    """One pin against its upstream.

    ``latest`` is what the pin is compared with. For a gem, that is the newest
    release whose required Ruby version admits the Ruby the image installs, and
    ``note`` names the newest release when it needs a newer Ruby than that.
    """

    pin: Pin
    latest: str | None
    status: str  # "current" | "outdated" | "ahead" | "held" | "error"
    detail: str = ""
    note: str = ""


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


def _license_project(tool: str, entry: Any) -> str:
    """``owner/repo`` of a license entry's repository, or a refusal naming the entry.

    The bump steps name a ``gh api repos/<owner>/<repo>/commits/<tag>`` lookup for
    every pin that has a license entry, so a repository on another host has to be
    refused when the pins are read, not when the report is rendered the week the tool
    falls behind.
    """
    return _github_project(
        entry.repository, f"THIRD_PARTY_LICENSES[{tool!r}].repository"
    )


def enumerate_pins(pins: Any) -> list[Pin]:
    """Every pin ``pins`` carries, one per tool, sorted by tool name.

    Raises:
        PinEnumerationError: when a pin cannot be attributed to an upstream, when
            two tables disagree about one tool's version, or when a pin is of no
            kind in ``PIN_KINDS``. All are refused rather than skipped, because a
            skipped pin is a pin nobody is told about.
    """
    tool_versions: dict[str, str] = pins.TOOL_VERSIONS
    licenses: dict[str, Any] = pins.THIRD_PARTY_LICENSES
    bundles: dict[str, Any] = getattr(pins, "RULES_BUNDLES", {})
    release_urls: dict[str, str] = getattr(pins, "_RELEASE_BASE_URLS", {})
    # A gem's license entry is read with its gem pin, below, not as a download pin.
    gems = frozenset(GEM_PINS)

    result: list[Pin] = []
    for tool in sorted(set(tool_versions) | set(licenses) | set(bundles)):
        entry = licenses.get(tool)
        downloads = [
            name
            for name, table in (
                ("TOOL_VERSIONS", tool_versions),
                ("RULES_BUNDLES", bundles),
            )
            if tool in table
        ]
        pinned_in: list[str] = []

        if entry is not None and entry.distribution:
            if downloads:
                raise PinEnumerationError(
                    f"{tool} is both a download pin in {downloads[0]} and a uv-tool "
                    f"pin (distribution {entry.distribution!r}); pick one."
                )
            _license_project(tool, entry)
            result.append(
                Pin(
                    tool=tool,
                    version=entry.version,
                    ecosystem=PYPI,
                    project=entry.distribution,
                    pinned_in=("THIRD_PARTY_LICENSES (uv-tool pin)",),
                    kind=UV_TOOL,
                )
            )
            continue

        if len(downloads) > 1:
            raise PinEnumerationError(
                f"{tool} is pinned in both TOOL_VERSIONS and RULES_BUNDLES; pick one."
            )
        if tool in tool_versions:
            version = tool_versions[tool]
            kind = RELEASE_BINARY
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
        elif tool in bundles:
            version = bundles[tool].version
            kind = RULES_BUNDLE
            pinned_in.append("RULES_BUNDLES")
            project = _github_project(bundles[tool].url, f"RULES_BUNDLES[{tool!r}].url")
        elif getattr(entry, "bundled_in", None):
            result.append(
                Pin(
                    tool=tool,
                    version=entry.version,
                    ecosystem=BUNDLED,
                    project=entry.bundled_in,
                    pinned_in=("THIRD_PARTY_LICENSES (bundled)",),
                    kind=BUNDLED_LIBRARY,
                )
            )
            continue
        elif tool in gems:
            continue
        else:
            # Only a license entry names it, so the version a bump changes is kept
            # somewhere this script does not read, and its steps would leave it out.
            recorded = entry.version if entry is not None else None
            raise PinEnumerationError(
                f"THIRD_PARTY_LICENSES[{tool!r}] records {recorded}, but {tool} is "
                "not in TOOL_VERSIONS or RULES_BUNDLES and has no distribution, so this "
                "script cannot tell what a bump of it changes. Give it a kind in "
                "PIN_KINDS, with its own steps in bump_steps."
            )

        if entry is not None:
            pinned_in.append("THIRD_PARTY_LICENSES")
            if entry.version != version:
                raise PinEnumerationError(
                    f"{tool} is {version} in {pinned_in[0]} and {entry.version} in "
                    f"THIRD_PARTY_LICENSES; a version bump is half-applied."
                )
            _license_project(tool, entry)

        result.append(
            Pin(
                tool=tool,
                version=version,
                ecosystem=GITHUB,
                project=project,
                pinned_in=tuple(pinned_in),
                kind=kind,
            )
        )

    for gem, name in GEM_PINS.items():
        gem_version = getattr(pins, name, None)
        if not isinstance(gem_version, str) or not gem_version:
            raise PinEnumerationError(
                f"{PINS_FILE} has no version string named {name}, so the {gem} gem "
                "pin would go unchecked. Teach GEM_PINS the new name, or restore it."
            )
        gem_pinned_in = [name]
        gem_entry = licenses.get(gem)
        if gem_entry is not None:
            _license_project(gem, gem_entry)
            if gem_entry.version.removeprefix("v") != gem_version.removeprefix("v"):
                raise PinEnumerationError(
                    f"{gem} is {gem_version} in {name} and {gem_entry.version} in "
                    f"THIRD_PARTY_LICENSES; a version bump is half-applied."
                )
            gem_pinned_in.append("THIRD_PARTY_LICENSES")
        result.append(
            Pin(
                tool=gem,
                version=gem_version,
                ecosystem=RUBYGEMS,
                project=gem,
                pinned_in=tuple(gem_pinned_in),
                kind=GEM,
            )
        )

    return sorted(result, key=lambda p: p.tool)


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

# An optional "<project>-" prefix: libssh2 and OpenSSL tag their releases
# "libssh2-1.11.1" and "openssl-3.3.3", and their license entries record the tag.
# What follows the numbers is limited to the characters release versions are spelled
# with. A latest release is copied into the bump steps, which a person pastes into a
# shell and the job summary renders, so a tag that carries anything else (a quote, a
# ``$(...)``, a space, markup) is refused as not a version, not accepted as a suffix.
_VERSION_RE = re.compile(
    r"^(?:[A-Za-z][A-Za-z0-9]*-)?v?(\d+(?:\.\d+)*)([A-Za-z0-9._+-]*)$"
)


def parse_version(text: str) -> tuple[tuple[int, ...], tuple[int, str]]:
    """A sortable key for a release version, numeric part compared as numbers.

    ``v0.69.10`` sorts after ``v0.69.9``, ``1.2`` equals ``1.2.0``, and a final
    release sorts after any pre-release of the same numbers. A PEP 440
    post-release (``1.2.3.post1``, also spelled ``rev`` or ``r``) sorts after
    the final release it follows: read as a pre-release, a PyPI post-release
    was reported as ``ahead`` of the pin for the same numbers instead of
    ``outdated``. Build metadata after ``+`` is ignored, as SemVer says it must be.

    Raises:
        ValueError: for a string with no leading numeric version, or with a
            character after it that no release version is spelled with.
    """
    match = _VERSION_RE.match(text.strip())
    if match is None:
        raise ValueError(f"not a version: {text!r}")
    release = tuple(int(part) for part in match.group(1).split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    suffix = match.group(2).split("+", 1)[0].lstrip("-.")
    if not suffix:
        return release, (1, "")
    if _POST_RELEASE_RE.match(suffix):
        return release, (2, suffix)
    return release, (0, suffix)


# PEP 440's post-release spellings, after the separator is stripped.
_POST_RELEASE_RE = re.compile(r"^(?:post|rev|r)\d*$", re.IGNORECASE)


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


def rubygems_releases(gem: str) -> Any:
    """Every release of ``gem``, with its required Ruby version: one request.

    RubyGems' versions list, newest first, one entry per release and platform, each
    with ``number``, ``prerelease``, ``platform`` and ``ruby_version``.
    """
    return _get_json(f"https://rubygems.org/api/v1/versions/{gem}.json")


# One clause of a RubyGems requirement, as ``ruby_version`` writes it: ">= 3.1.0".
_REQUIREMENT_CLAUSE = re.compile(r"^\s*(~>|>=|<=|!=|=|>|<)?\s*(\d+(?:\.\d+)*)\s*$")


def _trimmed(numbers: Iterable[int]) -> tuple[int, ...]:
    """``numbers`` without trailing zeros, so 3.1 and 3.1.0 compare equal."""
    values = list(numbers)
    while len(values) > 1 and values[-1] == 0:
        values.pop()
    return tuple(values)


def ruby_admits(requirement: object, ruby: tuple[int, int]) -> bool:
    """Whether a gem release's required Ruby version admits Ruby ``major.minor``.

    ``requirement`` is the release's ``ruby_version`` from RubyGems: comma-separated
    clauses such as ``>= 3.1.0`` or ``~> 2.2``, or None or empty for no requirement.
    The image's Ruby is known only as major.minor (the Dockerfile's apt pin), so it is
    compared as major.minor.0: a release that needs 3.1.3 is not counted as
    installable on 3.1, even though the image's 3.1 patch release might be newer.

    Raises:
        ValueError: for a requirement this cannot read. A release whose Ruby cannot be
            judged is refused, not guessed at.
    """
    return _requirement_admits(requirement, ruby, "Ruby")


def rubygems_admits(
    requirement: object, rubygems: tuple[int, ...] | None = None
) -> bool:
    """Whether a release's required RubyGems version admits the image's RubyGems.

    ``requirement`` is the release's ``rubygems_version`` from RubyGems, in the grammar
    of ``ruby_admits``; None or empty means no requirement. ``rubygems`` defaults to
    ``IMAGE_RUBYGEMS``.

    Raises:
        ValueError: for a requirement this cannot read.
    """
    return _requirement_admits(
        requirement, IMAGE_RUBYGEMS if rubygems is None else rubygems, "RubyGems"
    )


def _requirement_admits(
    requirement: object, version: tuple[int, ...], what: str
) -> bool:
    """Whether a requirement in RubyGems' grammar admits ``version``; ``what`` names it."""
    if requirement is None or requirement == "":
        return True
    if not isinstance(requirement, str):
        raise ValueError(f"cannot read the required {what} version {requirement!r}")
    have = _trimmed(version)
    for clause in requirement.split(","):
        match = _REQUIREMENT_CLAUSE.match(clause)
        if match is None:
            raise ValueError(f"cannot read the required {what} version {requirement!r}")
        operator = match.group(1) or "="
        segments = [int(part) for part in match.group(2).split(".")]
        want = _trimmed(segments)
        if operator == "~>":
            # Pessimistic: at least this version, below the next release of its
            # second-to-last segment. ~> 2.2 is >= 2.2 and < 3; ~> 3.0.1 is < 3.1.
            upper = segments[:-1] if len(segments) > 1 else list(segments)
            upper[-1] += 1
            admitted = want <= have < _trimmed(upper)
        else:
            admitted = {
                "=": have == want,
                "!=": have != want,
                ">": have > want,
                "<": have < want,
                ">=": have >= want,
                "<=": have <= want,
            }[operator]
        if not admitted:
            return False
    return True


def _unmet_requirements(
    release: dict[str, Any], ruby: tuple[int, int], rubygems: tuple[int, ...] | None
) -> list[str]:
    """What a release needs that the image does not have, as note text; [] if nothing."""
    unmet = []
    if not ruby_admits(release.get("ruby_version"), ruby):
        unmet.append(
            f"Ruby {release.get('ruby_version')} and the image installs Ruby "
            f"{ruby[0]}.{ruby[1]}"
        )
    if not rubygems_admits(release.get("rubygems_version"), rubygems):
        have = ".".join(str(n) for n in (rubygems or IMAGE_RUBYGEMS))
        unmet.append(
            f"RubyGems {release.get('rubygems_version')} and the image installs "
            f"RubyGems {have}"
        )
    return unmet


def newest_installable(
    releases: Any,
    ruby: tuple[int, int],
    pinned: str,
    rubygems: tuple[int, ...] | None = None,
) -> tuple[str, str]:
    """(the release a gem pin is compared with, a note about a newer one or "").

    The newest final release for the ``ruby`` platform whose required Ruby version
    admits ``ruby`` and whose required RubyGems version admits ``rubygems`` (default
    ``IMAGE_RUBYGEMS``). Releases no newer than ``pinned`` are not judged: when none
    newer is installable, the pin is compared with itself. When the newest release
    needs a newer Ruby or RubyGems, the note says so and names it.

    Raises:
        ValueError: for an answer that is not a list of releases, a release with no
            version number, or a required Ruby or RubyGems version that cannot be read.
    """
    if not isinstance(releases, list):
        raise ValueError(f"RubyGems answered {type(releases).__name__}, not a list")
    finals = []
    for release in releases:
        if not isinstance(release, dict) or not isinstance(release.get("number"), str):
            raise ValueError(f"RubyGems listed a release with no number: {release!r}")
        if release.get("prerelease") or release.get("platform", "ruby") != "ruby":
            continue
        finals.append(release)
    if not finals:
        raise ValueError("RubyGems lists no final release for the ruby platform")
    finals.sort(key=lambda release: parse_version(release["number"]), reverse=True)
    newest, pin_key = finals[0], parse_version(pinned)
    if parse_version(newest["number"]) < pin_key:
        return newest["number"], ""
    target = pinned
    for release in finals:
        if parse_version(release["number"]) <= pin_key:
            break
        if not _unmet_requirements(release, ruby, rubygems):
            target = release["number"]
            break
    note = ""
    if parse_version(newest["number"]) > parse_version(target):
        needs = " and ".join(_unmet_requirements(newest, ruby, rubygems))
        note = (
            f"{newest['number']} is the newest release, but it needs {needs}; "
            f"{target} is the newest release the image can run"
        )
    return target, note


Fetchers = dict[str, Callable[[str], Any]]

DEFAULT_FETCHERS: Fetchers = {
    GITHUB: latest_github_release,
    PYPI: latest_pypi_release,
    RUBYGEMS: rubygems_releases,
}


def check(
    pins: Iterable[Pin],
    fetchers: Fetchers | None = None,
    ruby: tuple[int, int] | None = None,
) -> list[Result]:
    """Look up each pin's latest release and classify it.

    A gem is compared with the newest release the image's Ruby can run
    (``newest_installable``). ``ruby`` is that Ruby as (major, minor); when None it
    is read from the Dockerfile's apt pin the first time a gem needs it.
    """
    fetchers = fetchers or DEFAULT_FETCHERS
    results = []
    for pin in pins:
        note = ""
        if pin.ecosystem == BUNDLED:
            # The reason goes in ``note``, which the report prints for every result
            # that has one; ``detail`` is printed only for lookup failures.
            results.append(
                Result(pin, None, "held", note=f"version set by {pin.project}")
            )
            continue
        try:
            answer = fetchers[pin.ecosystem](pin.project)
            if pin.ecosystem == RUBYGEMS:
                if ruby is None:
                    ruby = image_ruby(enumerate_apt_pins())
                latest, note = newest_installable(answer, ruby, pin.version)
            else:
                latest = answer
            status = compare(pin.version, latest)
        except Exception as exc:  # reported per pin, and it fails the run
            results.append(Result(pin, None, "error", f"{type(exc).__name__}: {exc}"))
            continue
        results.append(Result(pin, latest, status, note=note))
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


def _arg_stem(tool: str) -> str:
    """The Dockerfile ARG name a tool's version is under, without ``_VERSION``.

    A hyphen cannot be used in a Dockerfile ARG name (``${CFN-GUARD_VERSION}`` parses
    as a default-value expansion), so cfn-guard's is ``CFN_GUARD_VERSION``.
    """
    return tool.upper().replace("-", "_")


def _dockerfile_args(tool: str, dockerfile: Path) -> list[str]:
    """``Dockerfile:<line>`` for each ``ARG <TOOL>_VERSION=`` line."""
    if not dockerfile.is_file():
        return []
    pattern = re.compile(rf"^\s*ARG\s+{re.escape(_arg_stem(tool))}_VERSION=")
    return [
        f"Dockerfile:{number}"
        for number, line in enumerate(
            dockerfile.read_text(encoding="utf-8").splitlines(), start=1
        )
        if pattern.match(line)
    ]


def _spelled_like(current: str, latest: str) -> str:
    """``latest`` in the spelling of ``current``: with the leading ``v`` it has.

    A uv-tool pin's latest comes from PyPI as the bare number, while its license
    entry records the release tag (``v1.180.0`` for semgrep, cfn-lint, zizmor), and
    the bump steps name that entry's new value and a ``gh api .../commits/<tag>``
    lookup. Spelled bare, the step named a version that is not the tag and a
    lookup that resolves no ref.
    """
    if current.startswith("v") and not latest.startswith("v"):
        return "v" + latest
    if not current.startswith("v") and latest.startswith("v"):
        return latest[1:]
    return latest


def _license_steps(pins: Any, tool: str, latest: str) -> list[str]:
    entry = pins.THIRD_PARTY_LICENSES.get(tool)
    if entry is None:
        return []
    project = _license_project(tool, entry)
    latest = _spelled_like(entry.version, latest)
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


def _global_name(pins: Any, value: Any) -> str | None:
    """The module-level name ``value`` is bound to in ``pins``, if any."""
    return next(
        (n for n, v in vars(pins).items() if v is value and not n.startswith("__")),
        None,
    )


def _major(bare_version: str) -> str | None:
    """The leading number of a version without its ``v``, or None if it has none."""
    match = re.match(r"\d+", bare_version)
    return match.group(0) if match else None


def _release_binary_steps(pins: Any, pin: Pin, latest: str) -> list[str]:
    tool = pin.tool
    old_bare = pin.version.lstrip("v")
    table = pins._ASSET_TABLES.get(tool, {})
    filenames = list(table.values())
    steps = [f'TOOL_VERSIONS["{tool}"] -> {latest}']
    table_name = _global_name(pins, table) or "asset filenames"
    new_bare = latest.lstrip("v")
    # Each name is judged on its own: one that carries no version (an unversioned
    # binary beside versioned archives) must not drop the step for the others.
    versioned = [name for name in filenames if old_bare in name]
    if versioned:
        which = "" if len(versioned) == len(filenames) else " that carry the version"
        steps.append(
            f"{table_name}: the {len(versioned)} asset file names of {tool}{which}, "
            f"{old_bare} -> {new_bare}; check each still exists upstream"
        )
    # A name that carries only the major version (cfn-guard's ``cfn-guard-v3-...``)
    # changes when the major does, and not on any other bump.
    old_major, new_major = _major(old_bare), _major(new_bare)
    if old_major is not None and new_major not in (None, old_major):
        major_only = [
            name
            for name in filenames
            if name not in versioned
            and re.search(rf"(?<![0-9A-Za-z])v{old_major}(?![0-9])", name)
        ]
        if major_only:
            steps.append(
                f"{table_name}: the {len(major_only)} asset file names of {tool} that "
                f"carry only the major version, v{old_major} -> v{new_major}; check "
                "each still exists upstream"
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
    return steps + _license_steps(pins, tool, latest)


def _uv_tool_steps(pins: Any, pin: Pin, latest: str) -> list[str]:
    return _license_steps(pins, pin.tool, latest)


def _bundle_version_name(pins: Any, tool: str) -> str | None:
    """The module-level name ``RULES_BUNDLES[tool]`` takes its ``version=`` from.

    Read from the module's source, because the value alone does not say which
    constant to edit. None when the entry spells the version out, or is not found.
    """
    source = Path(getattr(pins, "__file__", None) or PACKAGE_ROOT.parent / PINS_FILE)
    for node in ast.parse(source.read_text(encoding="utf-8")).body:
        targets: list[ast.expr]
        value: ast.expr | None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if not isinstance(value, ast.Dict) or not any(
            isinstance(t, ast.Name) and t.id == "RULES_BUNDLES" for t in targets
        ):
            continue
        for key, call in zip(value.keys, value.values):
            if not (isinstance(key, ast.Constant) and key.value == tool):
                continue
            if isinstance(call, ast.Call):
                for keyword in call.keywords:
                    if keyword.arg == "version" and isinstance(keyword.value, ast.Name):
                        return keyword.value.id
    return None


def _rules_bundle_steps(pins: Any, pin: Pin, latest: str) -> list[str]:
    """What a bump of a rules bundle changes: the RulesBundle docstring's procedure."""
    tool = pin.tool
    bundle = pins.RULES_BUNDLES[tool]
    old_bare, new_bare = pin.version.lstrip("v"), latest.lstrip("v")
    archive = bundle.url.rsplit("/", 1)[-1]
    if old_bare in bundle.url:
        new_url = bundle.url.replace(old_bare, new_bare)
        new_archive = new_url.rsplit("/", 1)[-1]
    else:
        new_url = new_archive = "<the new release's archive>"
    entry = f'RULES_BUNDLES["{tool}"]'
    constant = _bundle_version_name(pins, tool)
    steps = [
        (
            f"{constant} -> {latest}: {entry} takes its version from it, and its url "
            f"becomes {new_url}"
            if constant
            else f"{entry}.version -> {latest}, and its url -> {new_url}"
        ),
        (
            f'_DIGESTS["{archive}"] -> "{new_archive}": sha256sum of {new_url}, '
            "downloaded once"
        ),
    ]
    if archive in getattr(pins, "_BUNDLE_CONTENTS_DIGESTS", {}):
        steps.append(
            f'_BUNDLE_CONTENTS_DIGESTS["{archive}"] -> "{new_archive}": '
            "rules_bundles.contents_digest of the map rules_bundles.extract_bundle "
            "returns for that archive, once it matches its new _DIGESTS entry"
        )
    return steps + _license_steps(pins, tool, latest)


def _gem_steps(pins: Any, pin: Pin, latest: str) -> list[str]:
    steps = [
        (
            f"{GEM_PINS[pin.tool]} -> {latest}, once rubygems.org shows {latest}'s "
            "required Ruby version admits the Ruby the image installs (the "
            "Dockerfile's `ruby=` apt pin)"
        )
    ]
    if pin.tool == BUNDLER_GEM:
        # Bundler is not in the Gemfile; the lockfile records the Bundler that wrote
        # it, and the image installs that one (the Dockerfile ARG step follows).
        steps.append(f"{GEMFILE}.lock: its BUNDLED WITH line -> {latest}")
    else:
        steps += [
            f'{GEMFILE}: gem "{pin.tool}", "{latest}"',
            (
                f"{GEMFILE}.lock: regenerate with "
                f"`bundle lock --update {pin.tool}` in that directory"
            ),
        ]
    # A gem with a license entry has that entry's values to move as well.
    return steps + _license_steps(pins, pin.tool, latest)


def _bundled_library_steps(pins: Any, pin: Pin, latest: str) -> list[str]:
    """A bundled library has no bump of its own: its version is its wheel's.

    The checker never reports one as outdated (it is held), so these steps are
    reached only when a bump of the wheel changes what it bundles. They say which
    entry follows the wheel rather than naming an upstream release to fetch.
    """
    return [
        (
            f"{pin.tool} is bundled by {pin.project} and is not pinned on its own: after "
            f"a {pin.project} bump, read the version of {pin.tool} the new wheel carries "
            f'and set THIRD_PARTY_LICENSES["{pin.tool}"].version to it, with its commit '
            "and license-file digests taken from that release"
        )
    ]


# One function per kind in PIN_KINDS; a test keeps the two in step.
_KIND_STEPS: dict[str, Callable[[Any, Pin, str], list[str]]] = {
    RELEASE_BINARY: _release_binary_steps,
    UV_TOOL: _uv_tool_steps,
    RULES_BUNDLE: _rules_bundle_steps,
    GEM: _gem_steps,
    BUNDLED_LIBRARY: _bundled_library_steps,
}


def _pinned_digests(pins: Any, pin: Pin) -> list[str]:
    """Every digest and commit the module pins for ``pin``; a bump replaces each."""
    if pin.kind == RELEASE_BINARY:
        archives = list(pins._ASSET_TABLES.get(pin.tool, {}).values())
    elif pin.kind == RULES_BUNDLE:
        archives = [pins.RULES_BUNDLES[pin.tool].url.rsplit("/", 1)[-1]]
    else:
        archives = []
    values: list[str] = []
    for archive in archives:
        for table in ("_DIGESTS", "_EXECUTABLE_DIGESTS", "_BUNDLE_CONTENTS_DIGESTS"):
            value = getattr(pins, table, {}).get(archive)
            if value:
                values.append(value)
    entry = pins.THIRD_PARTY_LICENSES.get(pin.tool)
    if entry is not None:
        values.append(entry.commit)
        values += [f.sha256 for f in entry.files if f.sha256]
    return list(dict.fromkeys(v.lower() for v in values if v))


# One line of ``git grep -n -z``: the path, the line number and the matched text, the
# first two ended by a NUL and the third by the newline. A path may hold a newline, so
# the record is read as a whole rather than split into lines first.
_GREP_RECORD = re.compile(rb"([^\0]+)\0(\d+)\0[^\n]*(?:\n|$)")


def _copy_steps(pins: Any, pin: Pin, repo_root: Path) -> list[str]:
    """One step per tracked file outside the pins module that repeats a pinned digest.

    nix's package expressions (in SRI form), a CI install check and test fixtures
    carry copies of some digests, and a bump has to change those too. They are found
    with ``git grep`` over the tracked files, as hex and as the ``sha256-<base64>``
    string nix writes, so a copy added later is named without editing this script.
    """
    spellings: list[str] = []
    for digest in _pinned_digests(pins, pin):
        spellings.append(digest)
        if len(digest) == 64:
            sri = base64.b64encode(bytes.fromhex(digest)).decode("ascii")
            spellings.append(f"sha256-{sri}")
    if not spellings:
        return []
    # -z prints each path verbatim and ends the path and the line number with a NUL,
    # so a path that holds a colon, a non-ASCII character or a quote is read back as
    # it is. --no-color keeps a user's color.grep=always out of the paths. The output is
    # read as bytes: a matched line in an encoding this locale cannot decode must not
    # stop the report.
    argv = ["git", "-C", str(repo_root), "grep", "-n", "-z", "--no-color", "-I", "-F"]
    for spelling in spellings:
        argv += ["-e", spelling]
    argv += ["--", ".", f":(exclude){PINS_FILE}"]
    try:
        found = subprocess.run(  # nosec B603 B607 - git, fixed arguments, this checkout
            argv, capture_output=True, timeout=60, check=False
        )
        failure = (
            None
            if found.returncode in (0, 1)
            else found.stderr.decode("utf-8", "replace").strip()[:200]
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        failure = str(exc)
    if failure is not None:
        return [
            f"search every file outside {PINS_FILE} for these pinned values of "
            f"{pin.tool} and replace each copy (git grep failed: {failure}): "
            + ", ".join(spellings)
        ]
    lines: dict[str, list[str]] = {}
    for record in _GREP_RECORD.finditer(found.stdout):
        path = record.group(1).decode("utf-8", "replace")
        lines.setdefault(path, []).append(record.group(2).decode("ascii"))
    return [
        f"{path}:{','.join(numbers)}: a copy of a digest {pin.tool} pins; replace it "
        "with the new value"
        for path, numbers in sorted(lines.items())
    ]


def bump_steps(
    pins: Any,
    result: Result,
    dockerfile: Path = DOCKERFILE,
    repo_root: Path = REPO_ROOT,
) -> list[str]:
    """Every edit a bump of ``result.pin`` to ``result.latest`` needs, in order.

    The steps for the pin's kind, then for every kind: the Dockerfile ARG that
    carries the version, each tracked file that repeats one of its digests, and a
    search for anything else that spells the old version.

    Raises:
        ValueError: for a pin whose kind has no steps here. enumerate_pins never
            returns one; a Pin built by hand can.
    """
    pin, latest = result.pin, result.latest or "<latest>"
    kind_steps = _KIND_STEPS.get(pin.kind)
    if kind_steps is None:
        raise ValueError(
            f"{pin.tool} is a {pin.kind!r} pin, and bump_steps has steps for "
            f"{', '.join(PIN_KINDS)} only"
        )
    steps = kind_steps(pins, pin, latest)
    args = _dockerfile_args(pin.tool, dockerfile)
    if args:
        steps.append(f"ARG {_arg_stem(pin.tool)}_VERSION in {', '.join(args)}")
    steps += _copy_steps(pins, pin, repo_root)
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
    r"(?<![\w-])apt(?:-get)?\s[^;&|]*?(?<![\w-])install(?![\w-])(?P<args>[^;&|]*)"
)
_APT_PIN = re.compile(
    r"^(?P<package>[a-z0-9][a-z0-9+.-]+)=(?P<version>[A-Za-z0-9.+~:-]+)$"
)
# A pin whose version is an expansion, ``curl=${CURL_VERSION}``: a package and a version
# that is known only when the build runs, which no index can be asked about.
_APT_PIN_EXPANSION = re.compile(r"[a-z0-9][a-z0-9+.-]+=(?=\S*\$)\S+")
_XARGS = re.compile(r"(?<![\w-])xargs(?![\w-])")
# A file or a here-string given to a command as its input: ``< list``, ``<list``,
# ``<<< "curl git"``. Not a here-document (``<<EOF``), a descriptor copy (``<&3``) or
# ``< /dev/null``, which gives xargs no words.
_XARGS_STDIN_FILE = re.compile(
    r"(?<!<)<<<|(?<![<>])<(?![<&])(?!\s*/dev/null(?![\w/.-]))"
)
# xargs reading its words from a file: ``-a list``, ``-ra list``, ``--arg-file=list``.
_XARGS_ARG_FILE = re.compile(r"\s(?:-[0-9A-Za-z]*a|--arg-file(?![\w-]))")

# Tag parts of a base image that name a variant of the image, not a Debian suite.
_IMAGE_VARIANTS = frozenset({"slim", "alpine"})
# The NodeSource major the Dockerfile sets: NODE_MAJOR=22, NODE_MAJOR="22" or
# ENV NODE_MAJOR 22.
_NODE_MAJOR = re.compile(r"\bNODE_MAJOR(?:=|\s+)[\"']?(?P<major>\d+)\b")
# The same major written into the repository URL apt reads, which is where apt gets it,
# or into the URL of NodeSource's setup script (setup_22.x), which sets that repository up.
_NODESOURCE_URL_MAJOR = re.compile(
    r"deb\.nodesource\.com/(?:node|setup)_(?P<major>\d+)\.x(?![\w.])"
)
# Docker reads instruction names without regard to case.
_RUN_INSTRUCTION = re.compile(r"^RUN\s", re.IGNORECASE)
# A here-document marker on a RUN line: <<EOF, <<-EOF, <<"EOF", <<\EOF. Not a
# here-string (<<<), and not a name that goes on into a call. A quote around the name,
# or a backslash before it, stops the shell expanding the body (see _heredoc_markers).
_HEREDOC_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_HEREDOC_MARKER = re.compile(
    rf"(?<!<)<<-?\s*(?:([\"'])(?P<name>{_HEREDOC_NAME})\1"
    rf"|(?P<escaped>\\)?(?P<bare>{_HEREDOC_NAME}))(?![\w(])"
)
# Shell arithmetic, $((1 << shift)) or ((x = 1 << n)), with one level of inner
# parentheses. Its shift operator is not a here-document, so it is cut out before the
# markers are looked for.
_ARITHMETIC = re.compile(r"\$?\(\((?:[^()]|\([^()]*\))*\)\)")
# Where one shell command ends on a line: ``;``, ``|``, ``||``, ``&&`` and a lone ``&``,
# not the ``&`` of ``2>&1`` or ``&>file``. Only a single ``|`` passes output on.
_COMMAND_END = re.compile(r"\|\||&&|[;|]|(?<![<>&])&(?![>&])")
# A redirection of output to a file: "> x", ">> x", "2> x", "&> x". Not a copy of a
# descriptor (``2>&1``), and not /dev/null, which keeps nothing.
_FILE_REDIRECT = re.compile(r"(?:&|\d*)>>?(?!&)\s*(?!/dev/null(?![\w/.-]))[^\s<>|;&]")
# The file a redirection of output names: "> x", ">> x", "2> x", "&> x".
_REDIRECT_TARGET = re.compile(r"(?:&|\d*)>>?(?!&)\s*(?P<file>[^\s<>|;&]+)")
# A redirection or a here-document marker among the words of a command.
_REDIRECT_WORD = re.compile(r"(?:&|\d*)>>?\s*\S*|<<-?\s*[\"'\\]?\w+[\"']?")
# What _split_substitutions leaves in place of a command substitution, $(...) or
# `...`: one word, with no shell metacharacter in it, that no package spelling matches.
_SUBSTITUTION_WORD = "$(...)"
# A positional or special parameter given as a whole word: $@, $*, $1, ${2}. In a script
# written to a file it is whatever the script's caller passes, which is checked where
# the caller is. Any other expansion names packages no lookup can see.
_POSITIONAL_PARAMETER = re.compile(r"\$(?:[@*]|\d+|\{(?:[@*]|\d+)\})")
# A comment line above a RUN that says the bodies of its here-documents are not scripts.
_SKIP_FILE_BODIES = re.compile(r"#\s*apt-pin-check:\s*skip\s*")
# Shells, which run the body of a here-document they are given, and the commands that
# start the user's shell and give it their input: ``su - user <<EOF``.
_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ash", "ksh", "su", "runuser"})
# The sudo options that start a shell: -s, -i, --shell, --login, in a cluster too (-Hs).
_SUDO_SHELL_OPTION = re.compile(r"--shell|--login|-[A-Za-z]*[si][A-Za-z]*")
# The commands that copy their input to a file or to their output unchanged, so a
# here-document given to one of them is that file's content: ``cat > f <<'EOF'``,
# ``tee f <<'EOF'``, ``install /dev/stdin f <<'EOF'``, ``cp /dev/stdin f <<'EOF'``,
# ``dd of=f <<'EOF'``. Any other command (``xargs apt-get install -y``) reads its input
# as it pleases.
_COPIERS = frozenset({"cat", "tee", "install", "cp", "dd"})
# Commands that run the command after them, and the options of each that take their
# value as the next word. ``sudo -u builder cat`` runs cat.
_WRAPPER_VALUE_OPTIONS = {
    "sudo": frozenset("-C -D -g -h -p -R -r -T -t -U -u".split()),
    "nice": frozenset({"-n"}),
    "env": frozenset({"-u", "-C", "-S"}),
    "command": frozenset(),
    "exec": frozenset(),
    "nohup": frozenset(),
    "time": frozenset(),
}
_ENV_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=\S*")
# A shell redirection among the arguments of the install: "> /dev/null", "2>".
_REDIRECTION = re.compile(r"(?:(?<=\s)|^)\d*(?:>>|>|<)\s*\S*")
# The options of apt-get that take their value as the next word. A short option takes
# it as the next word only when it is the last letter of its cluster: -yt suite, but
# -tsuite.
_APT_OPTIONS_WITH_VALUE = frozenset(
    {"-o", "--option", "-t", "--target-release", "-c", "--config-file"}
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


def _heredoc_markers(line: str) -> list[tuple[str, bool]]:
    """The here-documents opened on one line, as (name, body is a file's content).

    A body is a file's content, and not commands run now, when the command it is given
    to is a copier (``cat``, ``tee``, ``install`` or ``cp`` of ``/dev/stdin``, ``dd``),
    every command it is piped on to is a copier that writes a file, one of them writes
    a file (``cat > setup.sh <<'EOF'``, ``cat <<EOF >> conf``, ``tee setup.sh <<EOF``,
    ``cat <<EOF | tee setup.sh``, ``install -D /dev/stdin x <<EOF``), and none of them is
    a shell. A body given to a shell (``bash <<EOF > log``), to commands that write no
    file, or to any other command (``xargs apt-get install -y <<EOF > log`` writes a
    file, but its first reader is no copier) is that command's input, read as commands.
    Both are read for installs; the flag only decides whether a positional parameter in
    an install (``"$@"``) is skipped as the caller's. A marker that is not quoted
    (``<<EOF``, not ``<<'EOF'`` or ``<<\\EOF``) has the build shell expand the body as
    it is written, so what lands in the file is whatever the RUN's variables were; that
    body is read as commands too. So is the body of a file the same instruction goes on
    to run (``cat > x.sh <<'EOF' && sh x.sh jq``, ``... && chmod +x x.sh && x.sh``): its
    caller is on the line, so a ``"$@"`` in it is the caller's package, installed now.
    """
    cleaned = _ARITHMETIC.sub(" ", line)
    segments: list[tuple[int, int, str]] = []  # (start, stop, what ended the command)
    start = 0
    for end in _COMMAND_END.finditer(cleaned):
        segments.append((start, end.start(), end.group()))
        start = end.end()
    segments.append((start, len(cleaned), ""))
    markers: list[tuple[str, bool]] = []
    for match in _HEREDOC_MARKER.finditer(cleaned):
        first = next(
            (i for i, (_, stop, _) in enumerate(segments) if match.start() < stop),
            len(segments) - 1,
        )
        # The body is the input of its command, whose output goes on down the pipe.
        sinks = [first]
        while segments[sinks[-1]][2] == "|":
            sinks.append(sinks[-1] + 1)
        writes = shell = False
        written: set[str] = set()
        # The body is a file's content only if every command it reaches copies it: the
        # one it is given to by what it is, those piped on to by what it is and by
        # writing a file.
        copies = True
        for position, index in enumerate(sinks):
            begin, stop, _ = segments[index]
            command = cleaned[begin:stop]
            words = _REDIRECT_WORD.sub(" ", command).split()
            writes_here = bool(_FILE_REDIRECT.search(command)) or _writes_a_file(words)
            writes = writes or writes_here
            written.update(_written_files(command, words))
            shell = shell or _runs_a_shell(words)
            copies = copies and _program(words) in _COPIERS
            copies = copies and (writes_here or position == 0)
        # A quoted name (<<'EOF') or a backslash before it (<<\EOF) is a marker the
        # shell does not expand the body for.
        quoted = bool(match.group(1) or match.group("escaped"))
        name = match.group("name") or match.group("bare")
        # A file the same instruction runs is not kept for later: its body is the
        # commands of this build, whatever the marker.
        runs_it = bool(written) and _runs_a_file(
            [
                cleaned[begin:end]
                for index, (begin, end, _) in enumerate(segments)
                if index not in sinks
            ],
            written,
        )
        is_file = writes and copies and not shell and quoted and not runs_it
        markers.append((name, is_file))
    return markers


def _written_files(command: str, words: list[str]) -> set[str]:
    """The files one command writes its input to, as the names it spells them.

    These are the names of ``> f``, ``>> f``, ``tee f``, ``install /dev/stdin f``,
    ``cp /dev/stdin f`` and ``dd of=f``. ``/dev/null`` keeps nothing.
    """
    files = {
        match.group("file").strip("'\"") for match in _REDIRECT_TARGET.finditer(command)
    }
    names = [word.strip("(){}").rsplit("/", 1)[-1] for word in words]
    if "tee" in names:
        after_tee = words[names.index("tee") + 1 :]
        files.update(w for w in after_tee if not w.startswith("-"))
    if "/dev/stdin" in words:
        files.update(
            w for w in words[words.index("/dev/stdin") + 1 :] if not w.startswith("-")
        )
    files.update(w[3:] for w in words if w.startswith("of="))
    files.discard("/dev/null")
    files.discard("")
    return files


def _runs_a_file(commands: list[str], files: set[str]) -> bool:
    """Whether one of the commands runs one of the files, by its name or its path.

    A file is run when it is the program (``x.sh``, ``./x.sh``, ``sudo /tmp/x.sh``), or
    when a shell, ``.`` or ``source`` has its name among the words (``sh x.sh``,
    ``bash -e /tmp/x.sh jq``, ``. x.sh``), or inside a ``-c`` script (``sh -c
    'chmod +x x.sh && x.sh'``). The names are matched
    without their directory, so a different directory is taken for the same file: the
    body is then read as commands, which is the side of caution.
    """
    wanted = {path.rsplit("/", 1)[-1] for path in files} - {""}
    for command in commands:
        words = [w.strip("'\"") for w in _REDIRECT_WORD.sub(" ", command).split()]
        program = _program(words)
        if program in wanted:
            return True
        if program in _SHELLS or program in {".", "source"}:
            if any(word.rsplit("/", 1)[-1] in wanted for word in words):
                return True
            # A script given to the shell as a string names the file somewhere in it.
            script = words[words.index("-c") + 1 :] if "-c" in words else []
            if any(name in word for word in script for name in wanted):
                return True
    return False


def _program(words: list[str]) -> str:
    """The program a command runs: its first word past assignments and wrappers.

    ``FOO=1 cat`` and ``sudo -u builder cat`` run ``cat``. A word this cannot place (a
    wrapper's option it does not know) is taken for the program, which no copier
    matches, so the body is read as commands.
    """
    index = 0
    while index < len(words):
        word = words[index].strip("(){}")
        name = word.rsplit("/", 1)[-1]
        index += 1
        if not name or _ENV_ASSIGNMENT.fullmatch(word):
            continue
        value_options = _WRAPPER_VALUE_OPTIONS.get(name)
        if value_options is None:
            return name
        while index < len(words) and words[index].startswith("-"):
            index += 2 if words[index] in value_options else 1
    return ""


def _writes_a_file(words: list[str]) -> bool:
    """Whether the words of a command write what they read to a named file."""
    names = [word.strip("(){}").rsplit("/", 1)[-1] for word in words]
    if "tee" in names:
        # tee with no file argument only copies to its output.
        return any(not w.startswith("-") for w in words[names.index("tee") + 1 :])
    if "/dev/stdin" in words and ("install" in names or "cp" in names):
        return True
    return "dd" in names and any(
        w.startswith("of=") and w != "of=/dev/null" for w in words
    )


def _runs_a_shell(words: list[str]) -> bool:
    """Whether the words of a command start a shell that reads its input."""
    names = [word.strip("(){}").rsplit("/", 1)[-1] for word in words]
    if any(name in _SHELLS for name in names):
        return True
    return "sudo" in names and any(_SUDO_SHELL_OPTION.fullmatch(w) for w in words)


@dataclass(frozen=True)
class _RunBlock:
    """The (line number, text) lines of one RUN instruction, or of a file body in it."""

    lines: list[tuple[int, str]]
    # The lines are the content of a file the instruction writes with a quoted marker
    # (``cat > x <<'EOF'``), a script that may be run later. They are read as commands
    # all the same, but a positional parameter in them (``"$@"``) is whatever the
    # script's caller passes, not a package this check can look up.
    file_content: bool = False


def _run_blocks(text: str) -> list[_RunBlock]:
    """Each RUN instruction as its (line number, text) lines, comments dropped.

    The instruction name is read without regard to case. Inside a continued
    instruction a blank line and a comment line are skipped, as Docker skips them.
    The body of a here-document belongs to the instruction, each of its lines ended
    with ``;`` as the shell ends a command at a newline, except a line that ends with
    a backslash, which continues on the next. The body of a here-document written to
    a file with a quoted marker (``cat > setup.sh <<'EOF'``) is a block of its own,
    flagged ``file_content``: the file may be run later in the build, so its installs
    are read, not skipped. Those bodies are dropped instead when a comment line
    ``# apt-pin-check: skip`` stands directly above the RUN (blank lines and other
    comments may come between), for a file that is not a script. An instruction still
    open at the end of the file is kept.
    """
    blocks: list[_RunBlock] = []
    current: list[tuple[int, str]] | None = None
    # here-documents (name, body is a file's content) whose body is being read, in the
    # order the shell reads them
    terminators: list[tuple[str, bool]] = []
    file_body: list[tuple[int, str]] = []  # the body being read, if it is a file's
    skip_bodies = False  # a skip comment stands above the next RUN
    run_skips_bodies = False  # the RUN being read has one
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if current is not None and terminators:
            if line == terminators[0][0]:
                if terminators[0][1] and file_body and not run_skips_bodies:
                    blocks.append(_RunBlock(file_body, file_content=True))
                file_body = []
                terminators.pop(0)
                if not terminators:
                    blocks.append(_RunBlock(current))
                    current = None
            elif line and not line.startswith("#"):
                # A command ends at a newline, unless the line ends with a backslash:
                # then the next line continues it, as in the body of a here-document.
                target = file_body if terminators[0][1] else current
                if line.endswith("\\"):
                    target.append((number, line[:-1]))
                else:
                    target.append((number, f"{line} ;"))
            continue
        if current is None:
            if not line:
                continue
            if line.startswith("#"):
                skip_bodies = skip_bodies or bool(_SKIP_FILE_BODIES.fullmatch(line))
                continue
            if not _RUN_INSTRUCTION.match(line):
                skip_bodies = False
                continue
            current = []
            run_skips_bodies, skip_bodies = skip_bodies, False
            line = line[3:].strip()
        elif not line or line.startswith("#"):
            continue
        continued = line.endswith("\\")
        body = line[:-1] if continued else line
        current.append((number, body))
        if continued:
            continue
        # The command is the whole logical line, as Docker joins it: a shell named on
        # one physical line takes the here-document marker on the next.
        terminators = _heredoc_markers(" ".join(part for _, part in current))
        if terminators:
            continue
        blocks.append(_RunBlock(current))
        current = None
    if file_body and not run_skips_bodies:
        blocks.append(_RunBlock(file_body, file_content=True))
    if current:
        blocks.append(_RunBlock(current))
    return blocks


def _block_text(block: list[tuple[int, str]]) -> str:
    """The shell text of a RUN instruction: its lines joined, an exec form unpacked.

    ``RUN ["apt-get", "install", "-y", "curl=1.2"]`` is a JSON array of the words of
    one command, which is the command the shell form spells with spaces.
    """
    joined = " ".join(text for _, text in block)
    if joined.lstrip().startswith("["):
        try:
            words = json.loads(joined)
        except ValueError:
            return joined
        if isinstance(words, list) and all(isinstance(word, str) for word in words):
            return " ".join(words)
    return joined


def _line_words(text: str) -> set[str]:
    """The words of one Dockerfile line, without quotes, commas and brackets."""
    return {word.strip("'\"") for word in re.split(r"[\s;&|,\[\]]+", text)}


def _takes_separate_value(option: str) -> bool:
    """Whether an apt-get option word takes the next word as its value."""
    if option in _APT_OPTIONS_WITH_VALUE:
        return True
    if option.startswith("--") or "=" in option:
        return False
    for position, flag in enumerate(option[1:], start=1):
        if flag in "otc":
            return position == len(option) - 1
    return False


def _install_words(args: str) -> list[str]:
    """The package words of the arguments after ``install``.

    Options are not packages, and neither are the value an option takes as the next
    word (``-t bookworm-backports``, ``-o Name=value``) or a redirection. The quotes
    of a command given to a wrapper (``with-retry 'apt-get install -y curl=1.2'``) are
    not part of a word.
    """
    words: list[str] = []
    value_next = False
    for raw in _REDIRECTION.sub(" ", args).split():
        word = raw.strip("'\"")
        if value_next:
            value_next = False
        elif not word:
            continue
        elif word.startswith("-"):
            value_next = _takes_separate_value(word)
        else:
            words.append(word)
    return words


def _split_substitutions(text: str) -> list[str]:
    """``text`` with each command substitution cut out, then each one's own text.

    ``$(...)``, backticks and arithmetic ``$((...))`` become one word,
    ``_SUBSTITUTION_WORD``, so a ``|``, ``;`` or ``&`` inside one does not end the
    install it belongs to part way (``apt-get install -y $(grep x list | xargs)``),
    and so the word is named in the refusal instead of the half of it that was left.
    What is inside is read after the text around it, because it can hold an install
    of its own. A substitution that is not closed is left as written.
    """
    outer: list[str] = []
    inner: list[str] = []
    position = 0
    while position < len(text):
        char = text[position]
        end = -1
        if text.startswith("$(", position):
            depth = 0
            for index in range(position + 1, len(text)):
                if text[index] == "(":
                    depth += 1
                elif text[index] == ")":
                    depth -= 1
                    if depth == 0:
                        end = index
                        break
            start = position + 2
        elif char == "`":
            end = text.find("`", position + 1)
            start = position + 1
        if end == -1:
            outer.append(char)
            position += 1
            continue
        outer.append(_SUBSTITUTION_WORD)
        inner.append(text[start:end])
        position = end + 1
    found = ["".join(outer)]
    for part in inner:
        found.extend(_split_substitutions(part))
    return found


def _xargs_input(shell: str, install: re.Match[str]) -> str:
    """What ``xargs`` reads the packages of this install from, or ``""`` if not xargs.

    ``xargs apt-get install -y <<EOF`` takes the words of the body as the packages. The
    body lines are joined to the instruction as commands of their own, so no package in
    them is an argument of the install and none can be read as one. The same holds when
    the here-document is opened by an earlier stage of the pipeline that feeds xargs
    (``cat <<'EOF' | xargs apt-get install -y``), when a redirection such as ``2>&1``
    comes between the install and the marker, and when xargs reads a file
    (``< packages.txt``, ``-a packages.txt``), a here-string or a pipe: the words it
    reads are not in the Dockerfile at all. Packages given as arguments of the install
    (``xargs apt-get install -y curl=1.2``) are read like any install.
    """
    text = shell.replace("|&", "| ")
    ends = list(_COMMAND_END.finditer(text, 0, install.start()))
    own_start = ends[-1].end() if ends else 0
    runner = _XARGS.search(text, own_start, install.start())
    if runner is None:
        return ""
    # The pipeline xargs ends: step back over every stage a single ``|`` joins.
    first = len(ends)
    while first and ends[first - 1].group() == "|":
        first -= 1
    pipeline_start = ends[first - 1].end() if first else 0
    after = _COMMAND_END.search(text, install.end())
    stage_end = after.start() if after else len(text)
    if _HEREDOC_MARKER.search(text, pipeline_start, stage_end):
        return "a here-document"
    if _XARGS_STDIN_FILE.search(text, own_start, stage_end):
        return "a file or a here-string"
    if _XARGS_ARG_FILE.search(text, runner.end(), install.start()):
        return "a file named by its -a or --arg-file option"
    if ends and ends[-1].group() == "|":
        return "a pipe"
    return ""


def enumerate_apt_pins(dockerfile: Path = DOCKERFILE) -> list[AptPin]:
    """Every ``package=version`` an ``apt-get install`` in ``dockerfile`` names.

    Raises:
        PinEnumerationError: for an installed package with no ``=version``, or one
            pinned to two different versions. Both are refused rather than skipped:
            the first is a pin this check cannot see, the second is two images.
    """
    versions: dict[str, str] = {}
    lines: dict[str, list[int]] = {}
    for run in _run_blocks(dockerfile.read_text(encoding="utf-8")):
        block = run.lines
        for shell in _split_substitutions(_block_text(block)):
            for match in _APT_INSTALL.finditer(shell):
                where = f"{dockerfile.name}:{block[0][0]}"
                if source := _xargs_input(shell, match):
                    raise PinEnumerationError(
                        f"{where} installs packages with apt-get through xargs, which "
                        f"reads them from {source}. The words it reads are not "
                        "arguments this check can read. Spell each package as an "
                        "argument of the install, as package=version."
                    )
                for word in _install_words(match.group("args")):
                    if run.file_content and _POSITIONAL_PARAMETER.fullmatch(word):
                        # A script the image gets: "$@" is whatever its caller
                        # passes, and the caller's install is checked where it is.
                        continue
                    if _SUBSTITUTION_WORD in word:
                        raise PinEnumerationError(
                            f"{where} installs {word!r} with apt-get, naming a "
                            "package through a command substitution that this check "
                            "cannot read. Spell each package as package=version."
                        )
                    if _APT_PIN_EXPANSION.fullmatch(word):
                        raise PinEnumerationError(
                            f"{where} installs {word!r} with apt-get, pinning the "
                            "version through an expansion that this check cannot "
                            "read. Spell the version out, as package=version."
                        )
                    pin = _APT_PIN.match(word)
                    if pin is None:
                        raise PinEnumerationError(
                            f"{where} installs {word!r} with apt-get and no version. "
                            "Pin it as package=version; see the comment above the "
                            "first apt-get install for where versions come from."
                        )
                    package, version = pin.group("package"), pin.group("version")
                    if versions.setdefault(package, version) != version:
                        raise PinEnumerationError(
                            f"{package} is pinned to {versions[package]} and to "
                            f"{version} in {dockerfile.name}; every stage has to "
                            "install the same one."
                        )
                    lines.setdefault(package, []).extend(
                        [number for number, part in block if word in _line_words(part)]
                        or [block[0][0]]
                    )
    return [
        AptPin(package, versions[package], tuple(sorted(set(lines[package]))))
        for package in sorted(versions)
    ]


# The Debian package that installs the Ruby the image runs the gems with. Its version
# is the interpreter's major.minor, behind an epoch: ruby=1:3.1 installs Ruby 3.1.
_RUBY_PACKAGE = "ruby"

# The RubyGems the image has, which the Dockerfile does not pin: it is whatever the
# Debian ruby package bundles. Ruby 3.1.2, the 3.1 release in the pinned Debian
# bookworm package, bundles RubyGems 3.3.7 (``VERSION`` in lib/rubygems.rb at the
# upstream v3_1_2 tag, read 2026-10-30). This is the upstream number: Debian's own
# build of the package was not read, so it is a floor, and a release that needs a newer
# RubyGems than this is treated as not installable. A release's ``rubygems_version``
# is compared with it. IMAGE_RUBYGEMS_RUBY_PIN is the ``ruby=`` apt pin the number was
# taken for; a test fails when the Dockerfile's pin differs, so a Ruby bump makes
# whoever makes it look at this number.
IMAGE_RUBYGEMS: tuple[int, ...] = (3, 3, 7)
IMAGE_RUBYGEMS_RUBY_PIN = "1:3.1"


def image_ruby(apt_pins: Iterable[AptPin]) -> tuple[int, int]:
    """The Ruby the image installs, as (major, minor), read from its apt pin.

    Raises:
        PinEnumerationError: when no apt pin installs ``ruby``, or its version names
            no major.minor. A gem release cannot then be judged installable, and the
            check refuses rather than guess.
    """
    versions = [pin.version for pin in apt_pins if pin.package == _RUBY_PACKAGE]
    if not versions:
        raise PinEnumerationError(
            f"no apt-get install in the Dockerfile pins {_RUBY_PACKAGE}, so this script "
            "cannot tell which gem releases the image's Ruby can run"
        )
    match = re.match(r"^(?:\d+:)?(\d+)\.(\d+)(?:[.+~-]|$)", versions[0])
    if match is None:
        raise PinEnumerationError(
            f"the Dockerfile pins {_RUBY_PACKAGE}={versions[0]}, which names no "
            "major.minor Ruby version, so this script cannot tell which gem releases "
            "the image's Ruby can run"
        )
    return int(match.group(1)), int(match.group(2))


def _base_image_codename(image: str) -> str:
    """The Debian codename in an image reference's tag, or ``""`` when it holds none.

    A digest (``@sha256:...``) is not the tag, and a port in the registry
    (``localhost:5000/python``) is not a tag separator. Of the ``-`` parts of the tag,
    an image variant (``slim``) and anything that is not a lowercase word (a version, a
    build date) are not a codename; the last part left is.
    """
    name, _, tag = image.split("@", 1)[0].rpartition(":")
    if not name or "/" in tag:
        return ""
    words = [
        part
        for part in tag.split("-")
        if part not in _IMAGE_VARIANTS and re.fullmatch(r"[a-z]+", part)
    ]
    return words[-1] if words else ""


def apt_indexes(dockerfile: Path = DOCKERFILE) -> list[AptIndex]:
    """The indexes apt reads in the image the Dockerfile builds.

    The Debian codename is the last word among the ``-`` parts of the ``BASE_IMAGE``
    default's tag that is not an image variant (``python:3.12-slim-bookworm``,
    ``debian:bookworm-slim``, ``debian:bookworm-20241016-slim``), with any
    ``@sha256:...`` digest left out. The NodeSource repository is the major that
    ``NODE_MAJOR``, a ``node_<major>.x`` repository URL or a ``setup_<major>.x`` setup
    script URL names, so a base-image or Node bump moves the lookup with it.

    Raises:
        PinEnumerationError: when the tag holds no codename, when the Dockerfile
            configures NodeSource without a major this can read in either spelling, or
            when the two name different majors. The nodejs pin would
            otherwise be looked up in Debian's own nodejs, reported unavailable, and
            the report would name an older version to pin.
    """
    text = dockerfile.read_text(encoding="utf-8")
    base = re.search(r"^ARG BASE_IMAGE=(?P<image>\S+)$", text, re.MULTILINE)
    codename = _base_image_codename(base.group("image")) if base else ""
    if not codename:
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
    code = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    # The major apt reads is the one in the repository URL, and a Dockerfile usually
    # builds that URL from NODE_MAJOR. Either spelling names it; two values disagree.
    majors = sorted(
        {m.group("major") for m in _NODE_MAJOR.finditer(code)}
        | {m.group("major") for m in _NODESOURCE_URL_MAJOR.finditer(code)}
    )
    if len(majors) > 1:
        raise PinEnumerationError(
            f"{dockerfile.name} names NodeSource major {', '.join(majors)} (in "
            "NODE_MAJOR or in the repository URL); the NodeSource index to look the "
            "nodejs pin up in is ambiguous."
        )
    if not majors and "deb.nodesource.com" in code:
        raise PinEnumerationError(
            f"{dockerfile.name} configures the NodeSource repository, but neither "
            "NODE_MAJOR=<digits> (or ENV NODE_MAJOR <digits>) nor a node_<digits>.x "
            "or setup_<digits>.x URL names its major version, so the nodejs pin "
            "cannot be looked up in the right index."
        )
    if majors:
        major = majors[0]
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
    # dpkg ends the epoch at the first colon: an upstream version may hold more.
    epoch, _, rest = version.partition(":") if ":" in version else ("0", "", version)
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
                body = fetch(url)
                listed = parse_packages_index(body)
                if not listed and body.strip():
                    # A 200 answer with text in it and no package stanza (an error
                    # page) is not an index. Read as one, it would make every pin look
                    # retired. An empty body is an index: Debian empties
                    # <suite>-updates at a point release and may leave it empty.
                    raise ValueError("the index has text but lists no packages")
            except Exception as exc:  # reported per pin, and it fails the run
                failed.append(f"{index.label} ({url}): {type(exc).__name__}: {exc}")
                continue
            for package, versions in listed.items():
                available.setdefault(package, set()).update(versions)
        for pin in pins:
            try:
                results.append(_judge_apt_pin(pin, arch, available, failed))
            except Exception as exc:  # a version dpkg cannot order; reported per pin
                detail = f"{type(exc).__name__}: {exc}"
                results.append(AptResult(pin, arch, None, "error", detail))
    return results


def _judge_apt_pin(
    pin: AptPin, arch: str, available: dict[str, set[str]], failed: list[str]
) -> AptResult:
    """One pin against the versions the indexes list for its package."""
    versions = available.get(pin.package, set())
    candidate = _newest(versions)
    if failed:
        return AptResult(pin, arch, candidate, "error", "; ".join(failed))
    if candidate is None:
        # Gone altogether, not merely moved on: apt cannot install it at any
        # version, so the build is as broken as for a retired version.
        return AptResult(pin, arch, None, "unavailable", "no index lists the package")
    if pin.version not in versions:
        return AptResult(pin, arch, candidate, "unavailable")
    if compare_debian_versions(candidate, pin.version) > 0:
        return AptResult(pin, arch, candidate, "outdated")
    return AptResult(pin, arch, candidate, "current")


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
        widths = _column_widths(columns, rows)
        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
        out.append(fmt.format(*columns))
        out.append(fmt.format(*("-" * w for w in widths)))
        out += [fmt.format(*row).rstrip() for row in rows]

    bullet = "- " if markdown else "  - "
    # One bullet per pin, candidate and status. The status is part of the key: an
    # architecture where the pin is gone has to be told apart from one where it is
    # merely behind, even when both name the same newest version.
    seen: set[tuple[str, str | None, str]] = set()
    for r in results:
        if r.status not in ("unavailable", "outdated"):
            continue
        if (r.pin.package, r.candidate, r.status) in seen:
            continue
        seen.add((r.pin.package, r.candidate, r.status))
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
            detail = _escape_markdown(r.detail) if markdown else r.detail
            out.append(f"{bullet}{r.pin.package} ({r.arch}): lookup failed ({detail})")
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
    widths = _column_widths(_COLUMNS, rows)
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*_COLUMNS), fmt.format(*("-" * w for w in widths))]
    lines += [fmt.format(*row) for row in rows]
    return "\n".join(line.rstrip() for line in lines)


def _escape_markdown(text: str) -> str:
    """Escape what Markdown would misread, outside code spans.

    ``_`` is escaped so ``_DIGESTS`` is not read as emphasis. ``<`` is escaped
    because text shaped like a tag (``<new commit>``, urllib's ``<urlopen error timed
    out>``) is read as raw HTML, and GitHub's job summary drops it; ``&`` so that
    ``&lt;`` in a message is shown as written. A code span prints all of them as they
    are.
    """
    parts = text.split("`")
    return "`".join(
        part
        if i % 2
        else part.replace("&", "&amp;").replace("<", "&lt;").replace("_", "\\_")
        for i, part in enumerate(parts)
    )


def _column_widths(columns: tuple[str, ...], rows: list[tuple[str, ...]]) -> list[int]:
    """The width of each column: its title or its longest entry, whichever is wider.

    A table with no rows is as wide as its titles.
    """
    return [
        max([len(title)] + [len(row[index]) for row in rows])
        for index, title in enumerate(columns)
    ]


def render_report(pins: Any, results: list[Result], markdown: bool = False) -> str:
    out = []
    if markdown:
        out.append("## Pinned tool versions\n")
    out.append(render_table(results, markdown))

    outdated = [r for r in results if r.status == "outdated"]
    errors = [r for r in results if r.status == "error"]
    heading = "### " if markdown else ""
    bullet = "- " if markdown else "  - "

    noted = [r for r in results if r.note]
    if noted:
        out.append("")
    for r in noted:
        note = f"{r.pin.tool}: {r.note}"
        out.append(f"{bullet}{_escape_markdown(note) if markdown else note}")

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
        detail = _escape_markdown(r.detail) if markdown else r.detail
        out.append(f"\n{r.pin.tool}: lookup failed ({detail})")
    if not outdated and not errors:
        # A held row (a bundled library, whose version another pin sets) carries a note
        # that says why it is not compared. That is no release the image cannot use.
        caveats = any(r.note for r in results if r.status != "held")
        if caveats or any(r.status == "ahead" for r in results):
            # Nothing is behind, but a pin newer than upstream's latest, or a newer
            # release the image cannot use, is not "at its upstream's latest release".
            out.append(
                "\nNo pin is behind its upstream, but not every pin is at its "
                "upstream's latest release; see the ahead rows and the notes above."
            )
        else:
            out.append("\nEvery pin is at its upstream's latest release.")
    return "\n".join(out) + "\n"


def _render_fault_notice(
    heading: str, what: str, exc: Exception, markdown: bool
) -> str:
    """A short stand-in for a report that could not be rendered, for the job summary."""
    text = f"could not render the {what}: {type(exc).__name__}: {exc}"
    if markdown:
        return f"## {heading}\n\n{_escape_markdown(text)}\n"
    return f"\n{heading}\n  {text}\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        # Under python -OO there is no module docstring.
        description=(__doc__ or "").split("\n\n", 1)[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--fail-on-outdated",
        action="store_true",
        help=(
            "exit 1 when any pin is behind its upstream's latest release (for a gem, "
            "the newest release the image's Ruby can run)"
        ),
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
        ruby = image_ruby(apt_pins)
    except PinEnumerationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # a pins module that does not import, a missing file
        # Uncaught, this ends as a traceback with exit status 1, which this script
        # means as "a pin is behind".
        print(
            f"error: could not read the pins: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return EXIT_ERROR

    results = check(pin_list, ruby=ruby)
    apt_results = check_apt(apt_pins, indexes, APT_INDEX_FETCHER)
    # The two reports are rendered apart: a fault in one must not take the other with
    # it. The lookups are done, so what can be written is written, and a report that
    # could not be built is a script fault (exit 2).
    render_failed = False
    try:
        report = render_report(pins, results, markdown=args.markdown)
    except Exception as exc:  # bump steps that cannot be built for an outdated pin
        print(
            f"error: could not render the report: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        render_failed = True
        try:
            # stdout is the job summary: the bare table has no notes, bump steps or
            # closing line, and it has to say so.
            report = (
                render_table(results, markdown=args.markdown)
                + "\n"
                + _render_fault_notice(
                    "Pinned tool notes and bump steps",
                    "notes, bump steps and closing line",
                    exc,
                    args.markdown,
                )
            )
        except Exception as table_exc:  # the same fault, one level down
            print(
                "error: could not render the tool table: "
                f"{type(table_exc).__name__}: {table_exc}",
                file=sys.stderr,
            )
            report = _render_fault_notice(
                "Pinned tool versions", "tool report", table_exc, args.markdown
            )
    try:
        apt_report = render_apt_report(apt_results, markdown=args.markdown)
    except Exception as exc:  # a result the apt table cannot be built from
        print(
            f"error: could not render the apt report: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        # stdout is the job summary: it has to say that apt was not reported.
        apt_report = _render_fault_notice(
            "Dockerfile apt pins", "apt report", exc, args.markdown
        )
        render_failed = True
    sys.stdout.write(report)
    sys.stdout.write(apt_report)
    if render_failed:
        return EXIT_ERROR
    # The worse of the two, where an error (2) outranks a failing pin (1).
    return max(
        exit_code(results, args.fail_on_outdated),
        apt_exit_code(apt_results, args.fail_on_outdated),
    )


if __name__ == "__main__":
    sys.exit(main())
