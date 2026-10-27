#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Write the list of test files one unit-test shard runs.

The unit suite is too large for one job per OS and Python version to finish inside its
timeout on a 4-worker GitHub runner. The unit-test job in ash-unified-ci.yml fans each of
those legs out into shards, and this script says which files a shard owns.

The files are every git-tracked ``test_*.py`` under ``tests/``, which is what pytest.ini's
``testpaths`` and ``python_files`` select. They are sorted and dealt round-robin, so
neighbouring modules (``test_a_...`` families run in clusters) land in different
shards. A file belongs to exactly one shard, by construction.

Passing files as arguments also stops each shard from collecting the whole tree, which
alone took several minutes per worker pool on the unsharded run.

A shard is written ``<index>of<count>``, for example ``3of8``. The text carries its own
count, so a matrix entry cannot be re-read against a different total than the one it was
written for, and ``1of1`` is the whole suite.

Usage::

    select-test-shard.py --shard 3of8 --output test-results/shard-files.txt
    select-test-shard.py --self-test

``--self-test`` checks the properties the shards rely on against the current tree: every
file in exactly one shard, for several counts, and malformed shard names refused. It runs
before the selection in CI, so a degenerate selector fails loudly instead of running a
subset and reporting green.

Exit codes: 0 success, 1 a failed check or an empty shard, 2 a usage error.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

#: ``python_files`` in pytest.ini. A test file elsewhere in the tree is not collected.
TEST_FILE_PATTERN = "test_*.py"
#: ``testpaths`` in pytest.ini.
TEST_ROOT = "tests"

_SHARD = re.compile(r"^([1-9][0-9]*)of([1-9][0-9]*)$")


def parse_shard(text: str) -> tuple[int, int]:
    """``'3of8'`` -> ``(3, 8)``. Refuses anything else, and an index past the count."""
    match = _SHARD.fullmatch(text)
    if match is None:
        raise ValueError(f"shard {text!r} is not <index>of<count>, for example 3of8")
    index, count = int(match.group(1)), int(match.group(2))
    if index > count:
        raise ValueError(f"shard {text!r} has an index past its count")
    return index, count


def test_files(repo_root: Path) -> list[str]:
    """Every tracked test file under ``tests/``, sorted, as repo-relative POSIX paths."""
    done = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z", "--", TEST_ROOT],
        check=True,
        capture_output=True,
    )
    names = [p.decode("utf-8") for p in done.stdout.split(b"\0") if p]
    return sorted(
        n for n in names if fnmatch.fnmatch(PurePosixPath(n).name, TEST_FILE_PATTERN)
    )


def select(files: list[str], index: int, count: int) -> list[str]:
    """The files shard ``index`` of ``count`` owns (1-based)."""
    return [f for position, f in enumerate(files) if position % count == index - 1]


def self_test(files: list[str]) -> list[str]:
    """Problems found in the selector, empty when it is sound."""
    problems: list[str] = []
    if len(files) < 100:
        problems.append(
            f"only {len(files)} test files found under {TEST_ROOT}/; "
            "git ls-files read an empty or partial tree"
        )
    for count in (1, 2, 3, 8, 13):
        seen: list[str] = []
        for index in range(1, count + 1):
            seen.extend(select(files, index, count))
        if sorted(seen) != files:
            problems.append(
                f"{count} shards do not cover every file exactly once "
                f"({len(seen)} dealt, {len(files)} files)"
            )
    for bad in ("", "0of8", "9of8", "1of0", "3", "3of", "of8", "1of8x", "-1of8"):
        try:
            parse_shard(bad)
        except ValueError:
            continue
        problems.append(f"malformed shard {bad!r} was accepted")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--shard", help="<index>of<count>, for example 3of8")
    parser.add_argument("--output", help="file to write, one test path per line")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[2]
    files = test_files(repo_root)

    if args.self_test:
        problems = self_test(files)
        for problem in problems:
            print(f"select-test-shard self-test: {problem}", file=sys.stderr)
        if not problems:
            print(f"select-test-shard self-test: ok ({len(files)} test files)")
        return 1 if problems else 0

    if not args.shard or not args.output:
        parser.error("--shard and --output are required unless --self-test is given")
    try:
        index, count = parse_shard(args.shard)
    except ValueError as error:
        parser.error(str(error))

    chosen = select(files, index, count)
    if not chosen:
        print(
            f"shard {args.shard} owns no test files out of {len(files)}",
            file=sys.stderr,
        )
        return 1
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    # "\n" explicitly: the text mode default writes "\r\n" on Windows, and the shard
    # file is read back by pytest as one argument per line.
    with out.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(chosen) + "\n")
    print(f"shard {args.shard}: {len(chosen)} of {len(files)} test files -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
