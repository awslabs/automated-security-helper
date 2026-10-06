#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Rewrites a copy of the source tree to an older version, for an N-1 upgrade leg.

    python scripts/e2e/lower_version.py --tree <exported tree>

An upgrade leg needs an N-1 artifact whose version sorts below the head's. For a
channel whose artifact carries the version in more than one file (the MSIX stamps
Identity/@Version from the wheel and then checks it against pyproject.toml, and the
winget manifests carry PackageVersion and an InstallerUrl), lowering only
`[project] version` produces a tree that refuses to build. So this applies the
version change the same way a release bump does: every entry of
`[tool.commitizen] version_files`, with commitizen's semantics. For each
`path:regex` entry, every line of `path` that the regex matches has every
occurrence of the current version replaced. An entry with no regex rewrites every
occurrence in the file.

The new version decrements the last non-zero release component (3.7.0 -> 3.6.0,
3.7.2 -> 3.7.1), the derivation scripts/e2e/wheel.sh and packaging/verify-lib.sh
use, unless --to names one. It must sort below the current version, or the
"upgrade" would be a no-op or a downgrade, and that is refused.

It fails when an entry rewrites nothing, because a version_files entry that stopped
matching leaves the old version in that file and the N-1 artifact would then carry
two versions.

It only ever edits the tree it is pointed at, which must not be the checkout this
script lives in: a lowered checkout is a release bump in the wrong direction.

Prints the new version on stdout. Standard library only on Python 3.11+; on 3.10, the
project's floor, it reads TOML with tomli, which the dev environment carries.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - the unit tests run this on 3.10
    import tomli as tomllib

THIS_CHECKOUT = Path(__file__).resolve().parents[2]


class Failure(Exception):
    """A claim that did not hold. Printed without a traceback."""


def release_tuple(version: str) -> Tuple[int, ...]:
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)*", version):
        raise Failure(f"version {version!r} is not dotted integers")
    return tuple(int(part) for part in version.split("."))


def lower(version: str) -> str:
    """Decrement the last non-zero component."""
    parts = list(release_tuple(version))
    for index in range(len(parts) - 1, -1, -1):
        if parts[index] > 0:
            parts[index] -= 1
            return ".".join(str(p) for p in parts)
    raise Failure(f"cannot derive a lower version from {version}")


def version_files(pyproject: Path) -> Tuple[str, List[str]]:
    with pyproject.open("rb") as handle:
        data = tomllib.load(handle)
    try:
        commitizen = data["tool"]["commitizen"]
        return str(commitizen["version"]), list(commitizen["version_files"])
    except KeyError as exc:
        raise Failure(f"{pyproject} has no [tool.commitizen] {exc}") from exc


def rewrite(tree: Path, entry: str, old: str, new: str) -> int:
    """Apply one version_files entry. Returns the number of lines changed."""
    path_part, _, pattern = entry.partition(":")
    path = tree / path_part
    if not path.is_file():
        raise Failure(f"version_files names {path_part}, which is not in {tree}")
    regex = re.compile(pattern) if pattern else None
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    changed = 0
    for index, line in enumerate(lines):
        if (regex is None or regex.search(line)) and old in line:
            lines[index] = line.replace(old, new)
            changed += 1
    if changed:
        path.write_text("".join(lines), encoding="utf-8", newline="")
    return changed


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--tree", required=True, type=Path, help="an exported copy of the repository"
    )
    parser.add_argument(
        "--to", default=None, help="the version to write (default: one below)"
    )
    args = parser.parse_args(argv)

    tree = args.tree.resolve()
    if tree == THIS_CHECKOUT:
        raise Failure(
            f"{tree} is the checkout this script runs from. Point --tree at an "
            f"exported copy (git archive), never at the working tree."
        )
    current, entries = version_files(tree / "pyproject.toml")
    new = args.to or lower(current)
    if release_tuple(new) >= release_tuple(current):
        raise Failure(
            f"{new} does not sort below {current}; the upgrade would not move forward"
        )

    for entry in entries:
        changed = rewrite(tree, entry, current, new)
        if changed == 0:
            raise Failure(
                f"version_files entry {entry!r} rewrote nothing in {tree}. It no "
                f"longer matches, so the lowered tree would still say {current} there."
            )
        print(f"   {entry}: {changed} line(s)", file=sys.stderr)

    # commitizen keeps its own version in [tool.commitizen] and bumps it alongside
    # version_files. `pyproject.toml:^version` already covers it when both lines start
    # with `version`, which this checks rather than assumes.
    remaining, _ = version_files(tree / "pyproject.toml")
    if remaining != new:
        raise Failure(
            f"[tool.commitizen] version is {remaining} after the rewrite, not {new}"
        )

    print(new)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failure as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
