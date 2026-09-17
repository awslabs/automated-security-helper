#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regenerate the `resource` block in Formula/ash.rb from pyproject.toml.

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

WHY IT IS GENERATED RATHER THAN HAND-MAINTAINED

The transitive runtime closure of `[project.dependencies]` is 78 packages. A
hand-maintained list of 78 names, versions, URLs and hashes is a second copy of
the dependency set, and the long `[tool.commitizen]` comment block in
pyproject.toml is about exactly this failure: three separate hand-maintained
lists of the files that pin ASH's version, and a file absent from all three was
invisible to every one of them. A stale resource block fails the same way --
silently, one release later, on a user's machine.

So the closure is re-derived on demand instead. `uv` resolves it, the PyPI JSON
API supplies each sdist URL and sha256, and `--check` turns drift into a
non-zero exit.

WHY NOT `brew update-python-resources`

That is the normal tool and it is the right one to use when Homebrew is
installed. It was not available on the machine this was written on, and writing
the block by hand was the alternative being avoided. The PyPI JSON API returns
the same two fields the brew command writes -- the entry whose
`packagetype` is `"sdist"`, and its `digests.sha256` -- so the output is
equivalent, and `brew audit --strict` in CI checks it against Homebrew's own
rules either way.

WHAT IT DELIBERATELY DOES NOT EMIT

`uv`. It is in `[project.dependencies]` because ASH shells out to the uv
executable, and `Formula/ash.rb` already carries `depends_on "uv"` for that.
See EXEMPT below for the full reasoning; the short version is that a uv resource
would compile a Rust program Homebrew already ships bottled, into a directory
nothing on PATH points at.

KNOWN LIMITATIONS

- The resolution is pinned to one Python minor version, read from the formula's
  own `depends_on "python@X.Y"` so the two cannot drift. It is not a universal
  resolution across Python versions; Homebrew builds against one interpreter.

- `std_pip_args` also passes `--uploaded-prior-to`, a release cooldown. A
  resource whose version was published inside that window is refused by pip, so
  regenerating immediately after an upstream release can produce a block that
  fails to install for a few days. The fix is to wait, not to edit the formula.

- pip runs with build isolation ON (`Virtualenv#pip_install` defaults to
  `build_isolation: true`), so pip fetches build backends -- maturin for the
  Rust extensions, setuptools for the rest -- from PyPI during the build rather
  than from a resource. That is un-pinned network access inside a Homebrew
  build. Pinning it would mean abandoning `virtualenv_install_with_resources`
  for hand-rolled install code that stages build backends first, which is a
  larger change than the problem currently justifies.

USAGE

    python packaging/homebrew/refresh-resources.py            # print the block
    python packaging/homebrew/refresh-resources.py --write     # rewrite the formula
    python packaging/homebrew/refresh-resources.py --check     # exit 1 on drift
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess  # nosec B404 - uv is invoked as a subprocess; it is the resolver this script delegates to
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
FORMULA_PATH = REPO_ROOT / "Formula" / "ash.rb"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

BEGIN_MARKER = "  # BEGIN generated resources -- packaging/homebrew/refresh-resources.py"
END_MARKER = "  # END generated resources"

# Every platform Homebrew supports, as uv spells them. The resolution is run
# once per platform and the results must agree.
#
# Resolving on only the build machine would be the obvious shortcut and is
# wrong: a formula carries ONE resource list and Homebrew installs it on all
# four of these. A dependency that only appears on Linux would be missing from a
# list resolved on macOS, and the failure would land on Linux users as a
# ModuleNotFoundError rather than on whoever regenerated the block.
#
# Windows is absent because Homebrew does not run there. Including it would pull
# in Windows-only requirements (pywin32 and friends) that pip would then refuse
# to install on the platforms Homebrew does support.
PLATFORMS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
)

# Requirement name -> the Homebrew formula that supplies it instead of a
# resource. tests/unit/test_homebrew_formula_resources.py carries the same map
# and asserts the formula actually declares each `depends_on`, so an exemption
# cannot quietly become a hole.
EXEMPT = {
    "uv": "uv",
}

PYPI_JSON = "https://pypi.org/pypi/{name}/{version}/json"
HTTP_ATTEMPTS = 4
HTTP_TIMEOUT_SECONDS = 30


class RefreshError(RuntimeError):
    """Anything that should stop generation rather than produce a partial block."""


def canonical(name: str) -> str:
    """PEP 503 normalization. `GitPython` and `gitpython` are one package."""
    return re.sub(r"[-_.]+", "-", name).lower()


def formula_python_version(formula_text: str) -> str:
    """The Python minor version the formula builds against.

    Read from the formula rather than hardcoded so that bumping
    `depends_on "python@3.12"` to 3.13 changes what gets resolved. A hardcoded
    version here would resolve a closure for an interpreter the formula does not
    use, and the mismatch would only show up as a missing conditional
    dependency at runtime.
    """
    match = re.search(r'depends_on\s+"python@(?P<version>\d+\.\d+)"', formula_text)
    if match is None:
        raise RefreshError(
            f'No `depends_on "python@X.Y"` in {FORMULA_PATH}. The resolution needs '
            "to know which interpreter the venv is built against; add the "
            "dependency back, or pass the version explicitly by editing "
            "formula_python_version()."
        )
    return match.group("version")


def resolve_closure(python_version: str) -> dict[str, str]:
    """The transitive runtime closure of `[project.dependencies]`.

    Compiled once per Homebrew platform. Compiling `pyproject.toml` directly
    rather than re-reading the dependency array means the optional `cdk` extra
    and the `dev` dependency-group are excluded by construction rather than by a
    filter that could be got wrong -- and getting it wrong would put cdk-nag,
    an actual scanner, into the formula's build.
    """
    if shutil.which("uv") is None:
        raise RefreshError(
            "uv is not on PATH. It is the resolver this script delegates to; "
            "install it (https://docs.astral.sh/uv/) and re-run."
        )

    per_platform: dict[str, dict[str, str]] = {}
    for platform in PLATFORMS:
        command = [
            "uv",
            "pip",
            "compile",
            str(PYPROJECT_PATH),
            "--python-version",
            python_version,
            "--python-platform",
            platform,
            "--no-header",
            "--no-annotate",
            "--quiet",
        ]
        completed = subprocess.run(  # nosec B603 - list-form argv, literal "uv" executable, every element built above
            command, capture_output=True, text=True, cwd=REPO_ROOT
        )
        if completed.returncode != 0:
            raise RefreshError(
                f"`{' '.join(command)}` exited {completed.returncode}:\n"
                f"{completed.stderr.strip()}"
            )
        resolved = {}
        for line in completed.stdout.splitlines():
            match = re.match(r"^(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s;]+)", line)
            if match:
                resolved[canonical(match.group("name"))] = match.group("version")
        if not resolved:
            raise RefreshError(
                f"uv resolved nothing for {platform}. An empty closure would "
                "generate an empty resource block, which is the defect this "
                "script exists to fix, so this is a hard failure rather than a "
                "warning."
            )
        per_platform[platform] = resolved

    return _merge_platform_resolutions(per_platform)


def _merge_platform_resolutions(
    per_platform: dict[str, dict[str, str]],
) -> dict[str, str]:
    """One version per package across all platforms, or a hard failure.

    A Homebrew formula has no way to express "this version on Linux, that one
    on macOS" inside a single `resource` stanza. If the platforms disagree the
    block cannot be generated correctly, so say so with the disagreement in
    hand rather than picking one platform's answer.
    """
    merged: dict[str, str] = {}
    conflicts: list[str] = []
    for platform, resolved in per_platform.items():
        for name, version in resolved.items():
            existing = merged.setdefault(name, version)
            if existing != version:
                conflicts.append(
                    f"{name}: {existing} elsewhere, {version} on {platform}"
                )
    if conflicts:
        raise RefreshError(
            "The platforms resolved different versions of the same package, and "
            "one `resource` stanza cannot carry both:\n  "
            + "\n  ".join(sorted(conflicts))
            + "\nNarrow the constraint in pyproject.toml until the resolutions "
            "agree."
        )
    return merged


def fetch_sdist(name: str, version: str) -> tuple[str, str, str]:
    """The display name, sdist URL and sha256 PyPI reports for one release.

    The display name is PyPI's own spelling (`GitPython`, not `gitpython`)
    because that is what `brew update-python-resources` writes, and a reviewer
    comparing this block against a homebrew-core formula should not have to
    reconcile two spellings of the same package.

    With one correction to that, which `brew audit --strict` found and nothing
    here could have: the SEPARATOR is normalized to a hyphen. PyPI reports
    `info.name` as `pydantic_core` for the project whose canonical name is
    `pydantic-core` -- measured, both `/pypi/pydantic-core/...` and
    `/pypi/pydantic_core/...` answer with the underscore -- and the audit cop
    normalizes before comparing, so it rejected the underscore with

        Stable resource "pydantic_core": `resource` name should be
        'pydantic-core' to match the PyPI package name

    That was the only finding in 77 resources, and `brew install` and `brew test`
    had already passed, so the formula worked and only its spelling was wrong.

    Case is deliberately NOT touched. The same cop accepts `GitPython`, because
    PEP 503 normalization is case-insensitive, so lowercasing would lose the
    spelling a reviewer matches against homebrew-core for no gain. Separators are
    safe to rewrite for the same reason the normalization exists: PEP 503 treats
    `-`, `_` and `.` as equivalent, so no PyPI project can depend on which one
    appears in its name.
    """
    url = PYPI_JSON.format(name=name, version=version)
    payload = _get_json(url)

    sdists = [
        entry
        for entry in payload.get("urls", [])
        if entry.get("packagetype") == "sdist"
    ]
    if not sdists:
        raise RefreshError(
            f"{name} {version} publishes no sdist. Homebrew installs with "
            "--no-binary=:all:, so pip will refuse a wheel and there is nothing "
            "to point a `resource` at. Substituting the wheel would work only by "
            "removing that flag, which is a deviation from Homebrew convention a "
            "reviewer has to be told about -- so this fails loudly instead."
        )
    # Exactly one sdist per release is the norm. If a release somehow has more,
    # take the .tar.gz, which is what Homebrew expects to unpack.
    sdists.sort(key=lambda entry: not entry.get("filename", "").endswith(".tar.gz"))
    chosen = sdists[0]

    sha256 = chosen.get("digests", {}).get("sha256")
    if not sha256:
        raise RefreshError(
            f"PyPI reported no sha256 for {name} {version}. A resource without a "
            "hash is an unverified download; refusing to emit one."
        )
    display = re.sub(r"[_.]+", "-", payload["info"]["name"])
    return display, chosen["url"], sha256


def _get_json(url: str) -> dict:
    # The scheme is checked rather than taken on trust, even though every caller
    # passes the PYPI_JSON constant. urlopen honors file:// and ftp://, so an edit
    # that made the index configurable would turn this into a local-file read with
    # no visible change at the call site. Same reasoning, and same annotations, as
    # automated_security_helper/utils/download_utils.py.
    if not url.startswith("https://"):
        raise RefreshError(f"refusing to fetch a URL that is not https: {url}")

    last_error: Exception | None = None
    for attempt in range(1, HTTP_ATTEMPTS + 1):
        try:
            request = urllib.request.Request(
                url, headers={"Accept": "application/json"}
            )
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            with urllib.request.urlopen(  # nosec B310 - the https scheme is checked at the top of this function
                request, timeout=HTTP_TIMEOUT_SECONDS
            ) as response:
                return json.load(response)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            last_error = error
            if attempt < HTTP_ATTEMPTS:
                time.sleep(2**attempt)
    raise RefreshError(f"GET {url} failed after {HTTP_ATTEMPTS} attempts: {last_error}")


def render_block(closure: dict[str, str]) -> str:
    """The Ruby text between the two markers, markers included."""
    lines = [BEGIN_MARKER]
    for name in sorted(closure):
        if name in EXEMPT:
            continue
        display, url, sha256 = fetch_sdist(name, closure[name])
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


def existing_block(formula_text: str) -> str:
    begin = formula_text.find(BEGIN_MARKER)
    end = formula_text.find(END_MARKER)
    if begin == -1 or end == -1 or end < begin:
        return ""
    return formula_text[begin : end + len(END_MARKER)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Regenerate the Homebrew resource block from pyproject.toml's "
            "[project.dependencies]."
        )
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
        help=(
            "exit 1 if the checked-in block differs from a fresh resolution, "
            "without writing anything"
        ),
    )
    args = parser.parse_args(argv)

    try:
        formula_text = FORMULA_PATH.read_text(encoding="utf-8")
        python_version = formula_python_version(formula_text)
        print(
            f"resolving [project.dependencies] for python {python_version} across "
            f"{len(PLATFORMS)} platforms",
            file=sys.stderr,
        )
        closure = resolve_closure(python_version)
        emitted = sorted(name for name in closure if name not in EXEMPT)
        print(
            f"{len(closure)} packages resolved, {len(emitted)} emitted "
            f"({', '.join(sorted(EXEMPT))} covered by a Homebrew dependency)",
            file=sys.stderr,
        )
        block = render_block(closure)
    except RefreshError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if args.check:
        if existing_block(formula_text).strip() == block.strip():
            print("resource block is up to date", file=sys.stderr)
            return 0
        print(
            "error: Formula/ash.rb's resource block does not match a fresh "
            "resolution of [project.dependencies]. Run "
            "`python packaging/homebrew/refresh-resources.py --write`.",
            file=sys.stderr,
        )
        return 1

    if args.write:
        FORMULA_PATH.write_text(splice(formula_text, block), encoding="utf-8")
        print(f"wrote {len(emitted)} resources into {FORMULA_PATH}", file=sys.stderr)
        return 0

    print(block)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
