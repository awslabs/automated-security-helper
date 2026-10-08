#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exports the N-1 source tree an e2e upgrade leg builds its old package from.

    prev_tree.py --repo REPO --prev-ref REF --out DIR [--require PATH ...]
    prev_tree.py --repo REPO --prev-ref auto --require PATH [--require PATH ...] --out DIR
    prev_tree.py --repo REPO --prev-ref REF|auto [--require PATH ...] --resolve-only

An upgrade leg has to cross a real code change and a real version change, or it tests
nothing: a package upgraded to a copy of itself never runs the new install script
against an old install. This does the part of that which is the same for every channel
that packages ASH itself (Chocolatey, MSIX):

1. Resolves REF. When REF has HEAD's tree, as on a push to the branch REF names, it
   uses HEAD's first parent instead, and fails if that has HEAD's tree too.

   `--prev-ref auto` names no branch at all, so it keeps working after the branch an
   explicit ref would name is merged and deleted. It takes the newest release tag
   reachable from HEAD (`git describe --tags --match 'v[0-9]*'`), which is the version
   a user actually upgrades from, then HEAD's first parent, then the newest ancestor
   of HEAD in `--date-order`. Each must differ from HEAD's tree and carry every
   --require path: an ancestor that predates a channel has no package of that channel
   to upgrade from, and one with HEAD's tree would upgrade a package to a copy of
   itself, so either is passed over rather than built. The first parent comes before
   the walk because on a pull request's merge commit it is the base branch, which is
   what the pull request is upgraded from; by date alone the walk would usually take
   the pull request's own tip, whose tree is HEAD's when the pull request is up to
   date. When the base predates the channel it is passed over and the walk finds the
   pull request's own side. When nothing qualifies it fails and says whether the clone
   was too shallow to look (fetch with fetch-depth 0) or the history has no such
   commit.
2. Exports that commit with `git archive` into DIR/src, so no build step writes into
   the checkout. Zip format and Python's zipfile, so it needs no tar on Windows.
3. Lowers the [project] version in DIR/src/pyproject.toml by decrementing its last
   non-zero component (3.7.0 -> 3.6.0), the derivation scripts/e2e/wheel.sh and
   packaging/verify-lib.sh use, and refuses a result that does not sort below HEAD's
   version. Only the first `version = ` line changes, which is [project]'s.
4. Prints one JSON object on stdout: prev_ref, prev_sha, head_sha, head_version,
   prev_base_version, prev_version and src. Progress goes to stderr.

`--resolve-only` stops after step 1 and prints one line, `<sha> <label>`, for the legs
that export and build N-1 themselves (scripts/e2e/wheel.sh, container.sh, homebrew.sh
and editors/jetbrains/e2e-ide-cycle.sh, through scripts/e2e/n1-ref.sh). They take the
commit from here so that every leg picks N-1 the same way.

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
from typing import Dict, List, Optional, Sequence, Tuple

VERSION_LINE = re.compile(r'^version = "(?P<v>[^"]+)"(?P<eol>\r?)$', re.MULTILINE)
DOTTED = re.compile(r"[0-9]+(\.[0-9]+)*")
AUTO = "auto"
# How far back `auto` looks for an ancestor. Each candidate costs one line of a single
# batched `git cat-file`, so the bound is about not walking a whole unrelated history
# when every commit predates the channel, not about speed.
AUTO_WALK_LIMIT = 5000


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


def missing_paths(
    repo: Path, commits: Sequence[str], paths: Sequence[str]
) -> Dict[str, List[str]]:
    """{commit: [required paths absent from it]}, from one batched git cat-file."""
    if not commits or not paths:
        return {c: [] for c in commits}
    queries = [f"{c}:{p}" for c in commits for p in paths]
    result = subprocess.run(  # nosec B603 B607 - fixed git subcommand, no shell
        ["git", "-C", str(repo), "cat-file", "--batch-check"],
        input="".join(f"{q}\n" for q in queries),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise DerivationError(
            f"git cat-file --batch-check failed: {result.stderr.strip()}"
        )
    lines = result.stdout.splitlines()
    if len(lines) != len(queries):
        raise DerivationError(
            f"git cat-file answered {len(lines)} of {len(queries)} queries"
        )
    absent: Dict[str, List[str]] = {c: [] for c in commits}
    for query, line in zip(queries, lines):
        if line.endswith(" missing"):
            commit, path = query.split(":", 1)
            absent[commit].append(path)
    return absent


def resolve_auto(repo: Path, require: Sequence[str]) -> Tuple[str, str]:
    """The first commit that can be an N-1: the newest release tag, then HEAD's first
    parent, then the newest ancestor in --date-order.

    Qualifies when its tree differs from HEAD's and it carries every REQUIRE path.
    Each commit is considered once, under the first of those labels it gets.
    """
    if not require:
        raise DerivationError(
            "--prev-ref auto needs at least one --require path naming the channel, "
            "or it cannot tell an ancestor that predates the channel from one that has it"
        )
    head_sha = git(repo, "rev-parse", "HEAD")
    head_tree = git(repo, "rev-parse", "HEAD^{tree}")
    # (label, sha, tree), in order of preference, each commit once under its first label.
    candidates: List[Tuple[str, str, str]] = []
    seen = {head_sha}

    def add(label: str, sha: str, tree: str) -> None:
        if sha not in seen:
            seen.add(sha)
            candidates.append((label, sha, tree))

    try:
        tag = git(
            repo, "describe", "--tags", "--abbrev=0", "--match", "v[0-9]*", "HEAD"
        )
    except DerivationError:
        tag = ""
    if tag:
        tag_sha = git(repo, "rev-parse", f"{tag}^{{commit}}")
        add(
            f"{tag} (newest release tag)",
            tag_sha,
            git(repo, "rev-parse", f"{tag_sha}^{{tree}}"),
        )
    try:
        parent = git(repo, "rev-parse", "--verify", "--quiet", "HEAD^1^{commit}")
    except DerivationError:
        parent = ""  # a root commit, or a shallow clone that stops at HEAD
    if parent:
        add(
            f"HEAD^ {parent[:12]} (first parent)",
            parent,
            git(repo, "rev-parse", f"{parent}^{{tree}}"),
        )
    log = git(
        repo, "log", "--date-order", f"-n{AUTO_WALK_LIMIT}", "--format=%H %T", "HEAD"
    )
    for line in log.splitlines():
        sha, tree = line.split()
        add(f"ancestor {sha[:12]}", sha, tree)
    absent = missing_paths(repo, [c[1] for c in candidates], require)
    passed_over: List[str] = []
    for label, sha, tree in candidates:
        if tree == head_tree:
            passed_over.append(f"{label}: HEAD's tree")
            continue
        if absent[sha]:
            passed_over.append(f"{label}: no {', '.join(absent[sha])}")
            continue
        for reason in passed_over[:5]:
            print(f"passed over {reason}", file=sys.stderr)
        if len(passed_over) > 5:
            print(f"passed over {len(passed_over) - 5} more", file=sys.stderr)
        return label, sha
    shallow = git(repo, "rev-parse", "--is-shallow-repository") == "true"
    walked = len(candidates)
    if shallow:
        raise DerivationError(
            f"none of the {walked} commit(s) in this shallow clone differs from HEAD and "
            f"carries {', '.join(require)}; fetch the full history (fetch-depth: 0) so "
            "the release tags and older ancestors are there to choose from"
        )
    if walked >= AUTO_WALK_LIMIT:
        raise DerivationError(
            f"none of the newest {AUTO_WALK_LIMIT} ancestors differs from HEAD and "
            f"carries {', '.join(require)}"
        )
    raise DerivationError(
        f"no release tag or ancestor of HEAD differs from it and carries "
        f"{', '.join(require)}: this commit introduces the channel, so there is no "
        "earlier package of it to upgrade from"
    )


def resolve(repo: Path, prev_ref: str, require: Sequence[str] = ()) -> Tuple[str, str]:
    """(label, sha) of the N-1 commit: step 1 of the module docstring."""
    if prev_ref == AUTO:
        return resolve_auto(repo, require)
    used_ref, prev_sha = resolve_prev(repo, prev_ref)
    absent = missing_paths(repo, [prev_sha], require)[prev_sha]
    if absent:
        raise DerivationError(
            f"{used_ref} ({prev_sha}) has no {', '.join(absent)}, so it has no "
            "package of this channel to upgrade from"
        )
    return used_ref, prev_sha


def derive(
    repo: Path, prev_ref: str, out: Path, require: Sequence[str] = ()
) -> Dict[str, str]:
    repo = repo.resolve()
    head_sha = git(repo, "rev-parse", "HEAD")
    head_text = (repo / "pyproject.toml").read_text(encoding="utf-8")
    head_version = project_version(head_text, str(repo / "pyproject.toml"))
    used_ref, prev_sha = resolve(repo, prev_ref, require)

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
    parser.add_argument(
        "--prev-ref",
        required=True,
        help=f"the ref N-1 is built from, or {AUTO!r} to derive it from the history",
    )
    parser.add_argument(
        "--require",
        action="append",
        default=[],
        metavar="PATH",
        help="a path N-1 must carry (the channel's packaging); may be repeated",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--out", type=Path, help="scratch dir; <out>/src is replaced")
    mode.add_argument(
        "--resolve-only",
        action="store_true",
        help="print `<sha> <label>` of the N-1 commit and export nothing",
    )
    args = parser.parse_args(argv)
    if args.resolve_only:
        try:
            label, sha = resolve(args.repo.resolve(), args.prev_ref, args.require)
        except DerivationError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
        print(f"{sha} {label}")
        return 0
    try:
        result = derive(args.repo, args.prev_ref, args.out, args.require)
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
