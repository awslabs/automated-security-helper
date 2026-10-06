#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exports the N-1 source tree an e2e upgrade leg builds its old package from.

    prev_tree.py --repo REPO --prev-ref REF --out DIR

An upgrade leg has to cross a real code change and a real version change, or it tests
nothing: a package upgraded to a copy of itself never runs the new install script
against an old install. This does the part of that which is the same for every channel
that packages ASH itself (Chocolatey, MSIX):

1. Resolves REF. When REF has HEAD's tree, as on a push to the branch REF names, it
   uses HEAD's first parent instead, and fails if that has HEAD's tree too.
2. Exports that commit with `git archive` into DIR/src, so no build step writes into
   the checkout. Zip format and Python's zipfile, so it needs no tar on Windows.
3. Lowers the [project] version in DIR/src/pyproject.toml by decrementing its last
   non-zero component (3.7.0 -> 3.6.0), the derivation scripts/e2e/wheel.sh and
   packaging/verify-lib.sh use, and refuses a result that does not sort below HEAD's
   version. Only the first `version = ` line changes, which is [project]'s.
4. Prints one JSON object on stdout: prev_ref, prev_sha, head_sha, head_version,
   prev_base_version, prev_version and src. Progress goes to stderr.

A channel that carries its own version literal (a nuspec, an AppxManifest) lowers that
itself, in its own format. Standard library only, Python 3.9+.

Exit codes: 0 on success, 1 when the N-1 tree cannot be derived.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess  # nosec B404 - runs git on the local checkout only
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

VERSION_LINE = re.compile(r'^version = "(?P<v>[^"]+)"(?P<eol>\r?)$', re.MULTILINE)
DOTTED = re.compile(r"[0-9]+(\.[0-9]+)*")


class DerivationError(Exception):
    """The N-1 tree cannot be derived; the message says why."""


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(  # nosec B603 B607 - fixed git subcommands, no shell
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise DerivationError(
            f"git {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout.strip()


def lower_version(version: str) -> str:
    """Decrements the last non-zero component and zeroes the rest: 3.10.0 -> 3.9.0."""
    if not DOTTED.fullmatch(version):
        raise DerivationError(f"version {version!r} is not dotted integers")
    parts = [int(p) for p in version.split(".")]
    index = len(parts) - 1
    while index >= 0 and parts[index] == 0:
        index -= 1
    if index < 0:
        raise DerivationError(f"cannot derive a lower version from {version}")
    parts[index] -= 1
    for later in range(index + 1, len(parts)):
        parts[later] = 0
    return ".".join(str(p) for p in parts)


def sorts_below(prev: str, head: str) -> bool:
    """Release segments compared as integers, so 3.10.0 sorts above 3.9.0."""
    for v in (prev, head):
        if not DOTTED.fullmatch(v):
            raise DerivationError(f"version {v!r} is not dotted integers")

    def key(v: str) -> List[int]:
        parts = [int(p) for p in v.split(".")]
        return parts + [0] * (8 - len(parts))

    return key(prev) < key(head)


def project_version(text: str, where: str) -> str:
    match = VERSION_LINE.search(text)
    if not match:
        raise DerivationError(f"no [project] version line in {where}")
    return match.group("v")


def set_project_version(text: str, old: str, new: str, where: str) -> str:
    match = VERSION_LINE.search(text)
    if not match or match.group("v") != old:
        raise DerivationError(f"no [project] version line {old!r} in {where}")
    replacement = f'version = "{new}"{match.group("eol")}'
    return text[: match.start()] + replacement + text[match.end() :]


def resolve_prev(repo: Path, prev_ref: str) -> Tuple[str, str]:
    """Returns (ref actually used, its commit sha)."""
    try:
        prev_sha = git(
            repo, "rev-parse", "--verify", "--quiet", f"{prev_ref}^{{commit}}"
        )
    except DerivationError:
        raise DerivationError(f"{prev_ref} does not name a commit in {repo}") from None
    head_tree = git(repo, "rev-parse", "HEAD^{tree}")
    if git(repo, "rev-parse", f"{prev_sha}^{{tree}}") != head_tree:
        return prev_ref, prev_sha
    print(
        f"{prev_ref} has HEAD's tree; using HEAD's first parent as N-1", file=sys.stderr
    )
    try:
        parent = git(repo, "rev-parse", "--verify", "--quiet", "HEAD^1^{commit}")
    except DerivationError:
        raise DerivationError(
            "HEAD has no parent in this clone; fetch at least one more commit of history"
        ) from None
    if git(repo, "rev-parse", f"{parent}^{{tree}}") == head_tree:
        raise DerivationError(
            "HEAD's first parent has HEAD's tree too; there is no code change to upgrade across"
        )
    return "HEAD^", parent


def derive(repo: Path, prev_ref: str, out: Path) -> Dict[str, str]:
    repo = repo.resolve()
    head_sha = git(repo, "rev-parse", "HEAD")
    head_text = (repo / "pyproject.toml").read_text(encoding="utf-8")
    head_version = project_version(head_text, str(repo / "pyproject.toml"))
    used_ref, prev_sha = resolve_prev(repo, prev_ref)

    out.mkdir(parents=True, exist_ok=True)
    out = out.resolve()
    src = out / "src"
    archive = out / "prev.zip"
    if src.exists():
        shutil.rmtree(src)
    if archive.exists():
        archive.unlink()
    git(repo, "archive", "--format=zip", "-o", str(archive), prev_sha)
    with zipfile.ZipFile(archive) as bundle:
        bundle.extractall(src)
    archive.unlink()

    pyproject = src / "pyproject.toml"
    if not pyproject.is_file():
        raise DerivationError(f"{used_ref} ({prev_sha}) has no pyproject.toml")
    # newline="" both ways, so a CRLF checkout keeps its line endings byte for byte.
    with open(pyproject, encoding="utf-8", newline="") as handle:
        text = handle.read()
    base = project_version(text, f"{used_ref}'s pyproject.toml")
    lowered = lower_version(base)
    if not sorts_below(lowered, head_version):
        raise DerivationError(
            f"N-1 version {lowered} does not sort below HEAD's {head_version}; "
            "the upgrade would not move forward"
        )
    with open(pyproject, "w", encoding="utf-8", newline="") as handle:
        handle.write(set_project_version(text, base, lowered, str(pyproject)))

    return {
        "prev_ref": used_ref,
        "prev_sha": prev_sha,
        "head_sha": head_sha,
        "head_version": head_version,
        "prev_base_version": base,
        "prev_version": lowered,
        "src": str(src),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--repo", required=True, type=Path, help="the checkout (HEAD is N)"
    )
    parser.add_argument("--prev-ref", required=True, help="the ref N-1 is built from")
    parser.add_argument(
        "--out", required=True, type=Path, help="scratch dir; <out>/src is replaced"
    )
    args = parser.parse_args(argv)
    try:
        result = derive(args.repo, args.prev_ref, args.out)
    except DerivationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        f"N = {result['head_version']} at {result['head_sha']}; "
        f"N-1 = {result['prev_version']} from {result['prev_ref']} ({result['prev_sha']})",
        file=sys.stderr,
    )
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
