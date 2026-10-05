#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# PEP 723 inline metadata, so `uv run --script` can run this outside the project
# environment. Inside it (`uv run python ...`, or the unit tests) `packaging` is
# already installed.
# /// script
# requires-python = ">=3.10"
# dependencies = ["packaging>=24", "tomli>=2; python_version < '3.11'"]
# ///

"""Regenerate the `resource` block in Formula/ash.rb from uv.lock.

WHY THIS SCRIPT EXISTS

Homebrew builds a virtualenv with `virtualenv_install_with_resources`, and it
installs into that venv using `Formula#std_pip_args`:

    ["--verbose", "--no-deps", "--no-binary=:all:", "--ignore-installed", "--no-compile"]

`--no-deps` is the whole reason this file exists. pip resolves nothing. It
installs exactly the sdists Homebrew staged from `resource` stanzas, plus ASH
itself, and a requirement with no matching stanza is not an error -- it is a
package that never arrives. `brew install` succeeds, the venv is built, and the
first `ash` run dies on `ModuleNotFoundError` naming a module the build never
mentioned. The formula shipped in exactly that state until this script was
written: `virtualenv_install_with_resources` with zero resources.

WHY uv.lock AND NOT A FRESH RESOLUTION

The first version of this script ran `uv pip compile pyproject.toml` once per
platform and read each sdist URL and sha256 from the PyPI JSON API. That made the
block a function of the day it was generated, not of the repository: an upstream
release inside a declared range moved the resolution, and `--check` reported drift
on a formula nobody had touched. It was measured doing exactly that against a
formula generated a few days earlier.

uv.lock already pins the closure the project's own CI installs, with each
package's sdist URL and sha256. Reading it instead gives three properties the
network version could not have:

- the same uv.lock produces a byte-identical Formula/ash.rb, on any machine,
  offline;
- the formula installs the same versions the test suite ran against, rather than
  whatever PyPI served when the block was regenerated;
- `--check` is a real gate. It changes answer only when uv.lock or the formula
  changes, so it can run on every pull request. tests/unit/
  test_homebrew_formula_lock_sync.py does exactly that.

HOW THE CLOSURE IS READ

uv.lock is a universal lock: one file covering every platform and Python version
the project supports, with PEP 508 markers on the edges. The closure is the
runtime dependencies of the root package -- no extras, no dependency groups, so
the optional `cdk` extra (which carries cdk-nag, an actual scanner) is excluded by
construction -- walked once per Homebrew platform with that platform's marker
environment, then merged. A package that resolves to two versions across the
platforms is a hard failure, because one `resource` stanza cannot carry both.

Every Homebrew platform is walked, not only the build machine's. A formula carries
ONE resource list and Homebrew installs it on all four; a dependency conditional
on Linux would otherwise be missing from a list generated on macOS. Windows is
absent because Homebrew does not run there, and including it would pull in pywin32,
which has no sdist.

THE RESOURCE NAME

Derived from the sdist URL the same way `brew audit --strict` derives the name it
compares against (Homebrew's resource auditor takes the URL basename up to its last
hyphen and maps `_` and `.` to `-`, compared case-insensitively), and then checked
against the lock's own package name. So the block cannot pass this script and fail
that cop. The earlier PyPI-JSON version wrote `pydantic_core` from PyPI's
`info.name` and the cop rejected it; this derivation cannot produce that spelling.

WHAT IT DELIBERATELY DOES NOT EMIT

`uv`. It is in `[project.dependencies]` because ASH shells out to the uv
executable, and `Formula/ash.rb` already carries `depends_on "uv"` for that.
See EXEMPT below; the short version is that a uv resource would compile a Rust
program Homebrew already ships bottled, into a directory nothing on PATH points at.

KNOWN LIMITATIONS

- One Python minor version, read from the formula's `depends_on "python@X.Y"` so
  the two cannot drift. Markers are evaluated with python_full_version set to
  "X.Y.0"; a marker that keys on a patch release above .0 would be evaluated
  against .0. None in the lock does today.

- pip runs with build isolation ON (`Virtualenv#pip_install` defaults to
  `build_isolation: true`), so pip fetches build backends -- maturin for the
  Rust extensions, setuptools for the rest -- from PyPI during the build rather
  than from a resource. That is un-pinned network access inside a Homebrew build,
  and it is not something uv.lock can pin, because the lock records runtime
  dependencies and not PEP 517 backends.

- `std_pip_args` also passes `--uploaded-prior-to`, a release cooldown. A
  resource whose version was published inside that window is refused by pip.
  That is now governed by when uv.lock was last updated rather than when this
  script ran.

USAGE

    python packaging/homebrew/refresh-resources.py            # print the block
    python packaging/homebrew/refresh-resources.py --write     # rewrite the formula
    python packaging/homebrew/refresh-resources.py --check     # exit 1 on drift
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable
from typing import Any
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from packaging.markers import Marker

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - the unit tests import this module on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
FORMULA_PATH = REPO_ROOT / "Formula" / "ash.rb"
LOCK_PATH = REPO_ROOT / "uv.lock"

# The root package in uv.lock, which is this repository.
ROOT_PACKAGE = "automated-security-helper"

BEGIN_MARKER = (
    "  # BEGIN generated resources -- packaging/homebrew/refresh-resources.py"
)
END_MARKER = "  # END generated resources"

# Every platform Homebrew supports, as the PEP 508 marker variables that differ
# between them. The rest of the environment comes from base_environment().
PLATFORMS: dict[str, dict[str, str]] = {
    "aarch64-apple-darwin": {
        "sys_platform": "darwin",
        "platform_system": "Darwin",
        "platform_machine": "arm64",
    },
    "x86_64-apple-darwin": {
        "sys_platform": "darwin",
        "platform_system": "Darwin",
        "platform_machine": "x86_64",
    },
    "aarch64-unknown-linux-gnu": {
        "sys_platform": "linux",
        "platform_system": "Linux",
        "platform_machine": "aarch64",
    },
    "x86_64-unknown-linux-gnu": {
        "sys_platform": "linux",
        "platform_system": "Linux",
        "platform_machine": "x86_64",
    },
}

# Requirement name -> the Homebrew formula that supplies it instead of a
# resource. tests/unit/test_homebrew_formula_resources.py carries the same map
# and asserts the formula actually declares each `depends_on`, so an exemption
# cannot quietly become a hole.
EXEMPT = {
    "uv": "uv",
}

# The only sdist host a resource may point at. uv.lock records whatever index a
# package came from; a lock that started naming another host would otherwise flow
# straight into a formula users install from.
SDIST_HOST = "files.pythonhosted.org"
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

# One [[package]] table, or one dependency edge, as tomllib returns it.
LockPackage = dict[str, Any]


class RefreshError(RuntimeError):
    """Anything that should stop generation rather than produce a partial block."""


def canonical(name: str) -> str:
    """PEP 503 normalization. `GitPython` and `gitpython` are one package."""
    return re.sub(r"[-_.]+", "-", name).lower()


def formula_python_version(formula_text: str) -> str:
    """The Python minor version the formula builds against.

    Read from the formula rather than hardcoded so that bumping
    `depends_on "python@3.12"` to 3.13 changes which markers hold. A hardcoded
    version here would compute the closure for an interpreter the formula does not
    use, and the mismatch would only show up as a missing conditional dependency
    at runtime.
    """
    match = re.search(r'depends_on\s+"python@(?P<version>\d+\.\d+)"', formula_text)
    if match is None:
        raise RefreshError(
            f'No `depends_on "python@X.Y"` in {FORMULA_PATH}. The closure needs to '
            "know which interpreter the venv is built against; add the dependency "
            "back."
        )
    return match.group("version")


def base_environment(python_version: str) -> dict[str, str]:
    """The marker variables that are the same on every Homebrew platform."""
    return {
        "implementation_name": "cpython",
        "implementation_version": f"{python_version}.0",
        "os_name": "posix",
        "platform_python_implementation": "CPython",
        "platform_release": "",
        "platform_version": "",
        "python_full_version": f"{python_version}.0",
        "python_version": python_version,
        "extra": "",
    }


def load_lock(lock_path: Path) -> dict[str, list[LockPackage]]:
    """uv.lock's packages, grouped by canonical name.

    A list per name because a forked resolution can lock one name at two
    versions (networkx does today, split on python_full_version).
    """
    try:
        with lock_path.open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError as error:
        raise RefreshError(f"{lock_path} does not exist") from error
    packages: dict[str, list[LockPackage]] = {}
    for package in data.get("package", []):
        packages.setdefault(canonical(package["name"]), []).append(package)
    if ROOT_PACKAGE not in packages:
        raise RefreshError(
            f"{lock_path} has no [[package]] named {ROOT_PACKAGE!r}; it is not this "
            "repository's lock."
        )
    return packages


def _edge_applies(edge: LockPackage, environment: dict[str, str]) -> bool:
    marker = edge.get("marker")
    return marker is None or Marker(marker).evaluate(environment)


def _select(packages: dict[str, list[LockPackage]], edge: LockPackage) -> LockPackage:
    """The locked package an edge points at.

    uv writes `version` (and `source`) on an edge exactly when the name alone is
    ambiguous, so an unqualified edge to a name locked twice is a lock this script
    does not understand, and it stops rather than guessing.
    """
    name = canonical(edge["name"])
    candidates = packages.get(name)
    if not candidates:
        raise RefreshError(f"uv.lock references {name!r} but does not lock it")
    if "version" in edge:
        candidates = [p for p in candidates if p["version"] == edge["version"]]
    if len(candidates) != 1:
        raise RefreshError(
            f"uv.lock edge {edge} matches {len(candidates)} locked packages; "
            "expected exactly one"
        )
    return candidates[0]


def closure_for(
    packages: dict[str, list[LockPackage]], environment: dict[str, str]
) -> dict[str, LockPackage]:
    """The runtime closure of the root package in one marker environment."""
    root = packages[ROOT_PACKAGE][0]
    resolved: dict[str, LockPackage] = {}
    # (package, extras requested of it). The root contributes its plain
    # dependencies only: no optional-dependencies and no dev-dependencies.
    pending: list[tuple[LockPackage, frozenset[str]]] = []
    for edge in root.get("dependencies", []):
        if _edge_applies(edge, environment):
            pending.append((_select(packages, edge), frozenset(edge.get("extra", []))))
    expanded: set[tuple[str, str, frozenset[str]]] = set()
    while pending:
        package, extras = pending.pop()
        name = canonical(package["name"])
        key = (name, package["version"], extras)
        if key in expanded:
            continue
        expanded.add(key)
        previous = resolved.setdefault(name, package)
        if previous["version"] != package["version"]:
            raise RefreshError(
                f"{name} is reached at {previous['version']} and {package['version']} "
                "in the same environment"
            )
        edges: list[LockPackage] = list(package.get("dependencies", []))
        optional = package.get("optional-dependencies", {})
        for extra in sorted(extras):
            if extra not in optional:
                raise RefreshError(
                    f"uv.lock asks for {name}[{extra}] but {name} locks no such extra"
                )
            edges.extend(optional[extra])
        for edge in edges:
            if _edge_applies(edge, environment):
                pending.append(
                    (_select(packages, edge), frozenset(edge.get("extra", [])))
                )
    resolved.pop(ROOT_PACKAGE, None)
    return resolved


def merge_platform_closures(
    per_platform: dict[str, dict[str, LockPackage]],
) -> dict[str, LockPackage]:
    """One version per package across all platforms, or a hard failure.

    A Homebrew formula has no way to express "this version on Linux, that one on
    macOS" inside a single `resource` stanza. If the platforms disagree the block
    cannot be generated correctly, so say so with the disagreement in hand rather
    than picking one platform's answer.
    """
    merged: dict[str, LockPackage] = {}
    conflicts: list[str] = []
    for platform in sorted(per_platform):
        for name, package in per_platform[platform].items():
            existing = merged.setdefault(name, package)
            if existing["version"] != package["version"]:
                conflicts.append(
                    f"{name}: {existing['version']} elsewhere, "
                    f"{package['version']} on {platform}"
                )
    if conflicts:
        raise RefreshError(
            "The platforms lock different versions of the same package, and one "
            "`resource` stanza cannot carry both:\n  " + "\n  ".join(sorted(conflicts))
        )
    return merged


def resource_name(url: str) -> str:
    """The name `brew audit --strict` expects for a resource with this sdist URL.

    Homebrew's resource auditor matches `/(?<package_name>[^/]+)-` against the URL,
    which on a basename is everything up to its LAST hyphen, then maps `_` and `.`
    to `-` and compares case-insensitively. Done here the same way, on the
    basename.
    """
    basename = PurePosixPath(urlparse(url).path).name
    stem, hyphen, _ = basename.rpartition("-")
    if not hyphen or not stem:
        raise RefreshError(f"cannot read a package name out of the sdist URL {url}")
    return re.sub(r"[_.]", "-", stem)


def sdist_of(name: str, package: LockPackage) -> tuple[str, str, str]:
    """(resource name, url, sha256) for one locked package, from uv.lock alone."""
    sdist = package.get("sdist")
    if not sdist or "url" not in sdist or "hash" not in sdist:
        raise RefreshError(
            f"{name} {package['version']} has no sdist url and hash in uv.lock. "
            "Homebrew installs with --no-binary=:all:, so pip will refuse a wheel "
            "and there is nothing to point a `resource` at."
        )
    url = sdist["url"]
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != SDIST_HOST:
        raise RefreshError(
            f"{name} {package['version']}'s sdist is {url}, not an https URL on "
            f"{SDIST_HOST}. A formula resource is a download every user performs."
        )
    algorithm, _, digest = sdist["hash"].partition(":")
    if algorithm != "sha256" or not SHA256_HEX.match(digest):
        raise RefreshError(
            f"{name} {package['version']}'s sdist hash in uv.lock is "
            f"{sdist['hash']!r}; a Homebrew resource needs a 64-hex sha256."
        )
    display = resource_name(url)
    if canonical(display) != name:
        raise RefreshError(
            f"{name}'s sdist URL {url} names {display!r}. brew audit --strict "
            "derives the resource name from that URL, so the stanza would fail it."
        )
    return display, url, digest


def compute_closure(lock_path: Path, python_version: str) -> dict[str, LockPackage]:
    packages = load_lock(lock_path)
    per_platform = {}
    for platform, variables in PLATFORMS.items():
        environment = {**base_environment(python_version), **variables}
        closure = closure_for(packages, environment)
        if not closure:
            raise RefreshError(
                f"uv.lock yields an empty closure for {platform}. An empty resource "
                "block is the defect this script exists to fix."
            )
        per_platform[platform] = closure
    return merge_platform_closures(per_platform)


def render_block(closure: dict[str, LockPackage]) -> str:
    """The Ruby text between the two markers, markers included.

    Sorted by canonical name, so the output depends on the lock's contents and not
    on its ordering.
    """
    lines = [BEGIN_MARKER]
    for name in sorted(closure):
        if name in EXEMPT:
            continue
        display, url, sha256 = sdist_of(name, closure[name])
        lines.append(f'  resource "{display}" do')
        lines.append(f'    url "{url}"')
        lines.append(f'    sha256 "{sha256}"')
        lines.append("  end")
        lines.append("")
    lines.append(END_MARKER)
    return "\n".join(lines)


def splice(formula_text: str, block: str) -> str:
    begin = formula_text.find(BEGIN_MARKER)
    end = formula_text.find(END_MARKER)
    if begin == -1 or end == -1:
        raise RefreshError(
            f"{FORMULA_PATH} has no generated-resources markers. Add\n"
            f"{BEGIN_MARKER}\n{END_MARKER}\n"
            "between the depends_on lines and `def install`, then re-run. The "
            "markers are what makes this rewrite safe -- without them the script "
            "would have to guess where the block ends, and a wrong guess would "
            "delete `def install`."
        )
    if end < begin:
        raise RefreshError(
            f"{FORMULA_PATH} has the END marker before the BEGIN marker."
        )
    return formula_text[:begin] + block + formula_text[end + len(END_MARKER) :]


def generate(formula_text: str, lock_path: Path = LOCK_PATH) -> tuple[str, int]:
    """The formula text with its block regenerated from the lock, and the count.

    Pure: the same formula text and the same lock bytes give the same output.
    """
    python_version = formula_python_version(formula_text)
    closure = compute_closure(lock_path, python_version)
    emitted = sum(1 for name in closure if name not in EXEMPT)
    return splice(formula_text, render_block(closure)), emitted


def drift(formula_text: str, lock_path: Path = LOCK_PATH) -> list[str]:
    """Unified-diff lines between the formula and its regeneration; empty if none."""
    import difflib

    regenerated, _ = generate(formula_text, lock_path)
    return list(
        difflib.unified_diff(
            formula_text.splitlines(),
            regenerated.splitlines(),
            "Formula/ash.rb (committed)",
            f"Formula/ash.rb (from {lock_path.name})",
            lineterm="",
        )
    )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate the Homebrew resource block from uv.lock."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--write",
        action="store_true",
        help="rewrite Formula/ash.rb in place between the generated-resources markers",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if Formula/ash.rb differs from its regeneration from uv.lock",
    )
    parser.add_argument(
        "--lock",
        type=Path,
        default=LOCK_PATH,
        help="the uv.lock to read (default: the repository's)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        formula_text = FORMULA_PATH.read_text(encoding="utf-8")
        if args.check:
            lines = drift(formula_text, args.lock)
            if not lines:
                print("resource block matches uv.lock", file=sys.stderr)
                return 0
            print("\n".join(lines), file=sys.stderr)
            print(
                "error: Formula/ash.rb's resource block does not match uv.lock. Run "
                "`uv run python packaging/homebrew/refresh-resources.py --write`.",
                file=sys.stderr,
            )
            return 1
        regenerated, emitted = generate(formula_text, args.lock)
    except RefreshError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if args.write:
        FORMULA_PATH.write_text(regenerated, encoding="utf-8")
        print(f"wrote {emitted} resources into {FORMULA_PATH}", file=sys.stderr)
        return 0

    begin = regenerated.find(BEGIN_MARKER)
    end = regenerated.find(END_MARKER) + len(END_MARKER)
    print(regenerated[begin:end])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
