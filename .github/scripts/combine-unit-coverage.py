#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Combine the coverage data of one set of unit-test artifacts and apply the threshold.

The unit tier runs in four shards per OS and Python version, so a set is four artifacts
(``...-shard1of4`` to ``...-shard4of4``); a set of one (``...-shard1of1``) is still a
complete set, for a run of the tier that was not split. The check below is what makes the
split safe: no single shard of a split run can meet the 80% total-coverage gate, so a
missing shard is a failure, never a lower number. A run measures coverage, writes
``test-results/coverage.data`` and uploads it with the rest of its test results. This
script runs in the ``unit-coverage`` job after they are downloaded, one subdirectory per
artifact, and does what a single whole-suite "Run PyTest" step did in one process:

1. Check that every shard of the set is there. The shard names carry their own count
   (``...-shard3of8``), so a shard that crashed before uploading, or a matrix entry that
   was deleted, shows as a missing index. Combining the shards that happen to exist would
   report coverage for a subset and could pass. A single ``shard1of1`` artifact is a
   complete set of one. Each data file must also read back and hold measured files,
   because ``coverage combine`` skips a file it cannot read with a warning.
2. ``coverage combine`` their data files.
3. Print the Markdown table to the step summary when asked.
4. ``coverage report --fail-under=<threshold>``, whose exit status is this script's.

The set is named by the artifact name up to the shard suffix, which the run-unit-tests
action builds from the operating system, the architecture, the Python version and the
tier marker. This script rebuilds that name from ``--os``, ``--python-version``,
``--marker`` and the runner's own ``RUNNER_ARCH``, so it must run on the same kind of
runner as the runs it combines. ``--marker`` is required, with no default: without it the
name would have no tier segment, so a combine that named no tier would look for the
untiered artifact name no job uploads, or combine whatever set it found under it, and a
gate run over an unmarked shard set could pass without having read the unit tier at all.
That is also what makes path remapping unnecessary: coverage data records absolute source
paths, and a runner of the same image has the same workspace path, so the combine finds
every source file where the shard recorded it. A path that did not match would make
``coverage report`` fail with "No source for code", not pass.

Usage::

    combine-unit-coverage.py --results-dir shard-results \\
        --os ubuntu-latest --python-version 3.12 --marker unit --fail-under 80 \\
        --summary "$GITHUB_STEP_SUMMARY"
    combine-unit-coverage.py --self-test

Exit codes: 0 success, 1 shards missing or malformed, 2 coverage below the threshold
(coverage.py's own status), 64 a usage error.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

DATA_FILE = "coverage.data"
_SHARD_SUFFIX = re.compile(r"-shard([1-9][0-9]*)of([1-9][0-9]*)$")

#: GitHub's closed set of ``runner.arch`` values and the labels the run-unit-tests action
#: puts in an artifact name. tests/unit/test_unit_test_shards.py holds the two to each other.
ARCH_LABELS = {"X64": "x86_64", "ARM64": "arm64", "X86": "i686", "ARM": "armv7l"}


def artifact_prefix(
    os_name: str,
    python_version: str,
    runner_arch: str,
    marker: str | None = None,
) -> str:
    """The artifact name a shard of this OS, Python, architecture and tier uploads under.

    With ``marker`` the tier segment follows the Python version, as the run-unit-tests
    action writes it; without one the name ends at the Python version.
    """
    label = ARCH_LABELS.get(runner_arch)
    if label is None:
        raise ValueError(
            f"RUNNER_ARCH is {runner_arch!r}, which is not one of {sorted(ARCH_LABELS)}"
        )
    prefix = f"test-results-{os_name}-{label}-py{python_version}"
    return prefix if marker is None else f"{prefix}-{marker}"


def check_shards(names: list[str], prefix: str) -> list[str]:
    """Problems with the artifact names found for one set, empty when all are there."""
    found: dict[int, int] = {}
    problems: list[str] = []
    for name in names:
        if not name.startswith(prefix):
            problems.append(f"{name!r} is not one of {prefix!r}'s shards")
            continue
        match = _SHARD_SUFFIX.search(name)
        if match is None or name[: match.start()] != prefix:
            problems.append(f"{name!r} does not end in -shard<index>of<count>")
            continue
        index, count = int(match.group(1)), int(match.group(2))
        if index > count:
            problems.append(f"{name!r} has an index past its count")
            continue
        if index in found:
            problems.append(f"shard {index} appears twice")
        found[index] = count
    counts = set(found.values())
    if len(counts) > 1:
        problems.append(f"the shards disagree on their count: {sorted(counts)}")
    elif counts:
        (count,) = counts
        missing = [i for i in range(1, count + 1) if i not in found]
        if missing:
            problems.append(
                f"missing shard(s) {missing} of {count} for {prefix!r}; "
                "the coverage of the shards that ran would stand in for the whole suite"
            )
    else:
        problems.append(f"no shard artifacts found for {prefix!r}")
    return problems


def self_test() -> list[str]:
    """Positive and negative controls for check_shards."""
    prefix = "test-results-ubuntu-latest-x86_64-py3.12"
    whole = [f"{prefix}-shard{i}of3" for i in range(1, 4)]
    cases = [
        ("complete set", whole, False),
        ("last shard missing", whole[:2], True),
        ("first shard missing", whole[1:], True),
        ("no shards", [], True),
        ("mixed counts", whole[:2] + [f"{prefix}-shard3of4"], True),
        (
            "another set's artifact",
            whole + ["test-results-macos-latest-arm64-py3.12-shard1of3"],
            True,
        ),
        ("no suffix", whole + [prefix], True),
        ("index past count", whole + [f"{prefix}-shard4of3"], True),
        ("duplicate", whole + [whole[0]], True),
    ]
    failures = []
    for label, names, should_fail in cases:
        problems = check_shards(names, prefix)
        if bool(problems) != should_fail:
            failures.append(
                f"{label}: expected {'problems' if should_fail else 'none'}, got {problems}"
            )
    named = [
        ("ubuntu-latest", "3.12", "X64", "test-results-ubuntu-latest-x86_64-py3.12"),
        (
            "ubuntu-24.04-arm",
            "3.12",
            "ARM64",
            "test-results-ubuntu-24.04-arm-arm64-py3.12",
        ),
        ("macos-latest", "3.12", "ARM64", "test-results-macos-latest-arm64-py3.12"),
        ("windows-latest", "3.12", "X64", "test-results-windows-latest-x86_64-py3.12"),
    ]
    for os_name, version, arch, want in named:
        got = artifact_prefix(os_name, version, arch)
        if got != want:
            failures.append(
                f"artifact_prefix({os_name}, {arch}) is {got!r}, not {want!r}"
            )
    try:
        artifact_prefix("ubuntu-latest", "3.12", "RISCV")
    except ValueError:
        pass
    else:
        failures.append("an unknown RUNNER_ARCH was accepted")

    # The tier segment sits between the Python version and the shard suffix.
    unit_prefix = artifact_prefix("ubuntu-latest", "3.12", "X64", "unit")
    if unit_prefix != "test-results-ubuntu-latest-x86_64-py3.12-unit":
        failures.append(f"artifact_prefix with a marker is {unit_prefix!r}")
    tiered = [f"{unit_prefix}-shard{i}of3" for i in range(1, 4)]
    tiered_cases = [
        ("tiered complete set", tiered, False),
        ("tiered last shard missing", tiered[:2], True),
        # The unsharded unit run uploads one artifact, a complete set of one.
        ("tiered single set", [f"{unit_prefix}-shard1of1"], False),
        # An artifact from another tier is not one of this set's shards.
        (
            "another tier's artifact",
            tiered + [f"{prefix}-integration-shard1of4"],
            True,
        ),
    ]
    for label, names, should_fail in tiered_cases:
        problems = check_shards(names, unit_prefix)
        if bool(problems) != should_fail:
            failures.append(
                f"{label}: expected {'problems' if should_fail else 'none'}, got {problems}"
            )
    return failures


def data_problem(path: Path) -> str | None:
    """Why a shard's data file cannot stand in for its slice of the suite, or None.

    ``coverage combine`` warns and skips a data file it cannot read, and fails only when it
    read none, so a truncated file from one shard would otherwise be combined without it.
    Reading each file first, and requiring it to hold measured files, closes that.
    """
    try:
        from coverage import CoverageData

        data = CoverageData(basename=str(path))
        data.read()
        measured = data.measured_files()
    except Exception as error:  # noqa: BLE001 - any failure to read is the finding
        return f"{path.parent.name}/{path.name} cannot be read: {error}"
    if not measured:
        return f"{path.parent.name}/{path.name} holds no measured files"
    return None


def _coverage(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "coverage", *args], check=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--results-dir", help="directory holding one subdirectory per artifact"
    )
    parser.add_argument(
        "--os", help="the runs-on value of the shards, e.g. macos-latest"
    )
    parser.add_argument("--python-version", help="the Python version of the shards")
    parser.add_argument(
        "--marker",
        help="the tier marker in the artifact names, e.g. unit (required, no default)",
    )
    parser.add_argument(
        "--fail-under", type=float, help="minimum total coverage, percent"
    )
    parser.add_argument(
        "--summary", help="file to append the Markdown coverage table to"
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        failures = self_test()
        for failure in failures:
            print(f"combine-unit-coverage self-test: {failure}", file=sys.stderr)
        if not failures:
            print("combine-unit-coverage self-test: ok")
        return 1 if failures else 0

    if (
        not args.results_dir
        or not args.os
        or not args.python_version
        or not args.marker
        or args.fail_under is None
    ):
        # Not parser.error(), and not argparse's required=True: argparse exits 2 there,
        # which is coverage's own status for a run below the threshold, and a required
        # option would also refuse --self-test. --marker is required here for the reason
        # the module docstring gives: without a tier the gate reads no tier.
        print(
            "combine-unit-coverage: --results-dir, --os, --python-version, --marker "
            "and --fail-under are required",
            file=sys.stderr,
        )
        return 64
    try:
        prefix = artifact_prefix(
            args.os,
            args.python_version,
            os.environ.get("RUNNER_ARCH", ""),
            args.marker,
        )
    except ValueError as error:
        print(f"combine-unit-coverage: {error}", file=sys.stderr)
        return 64

    results = Path(args.results_dir)
    shard_dirs = sorted(p for p in results.glob(f"{prefix}-shard*") if p.is_dir())
    problems = check_shards([p.name for p in shard_dirs], prefix)
    data_files = []
    for shard_dir in shard_dirs:
        data = shard_dir / DATA_FILE
        if not data.is_file():
            problems.append(f"{shard_dir.name} has no {DATA_FILE}")
            continue
        problem = data_problem(data)
        if problem:
            problems.append(problem)
        else:
            data_files.append(str(data))
    if problems:
        for problem in problems:
            print(f"combine-unit-coverage: {problem}", file=sys.stderr)
        return 1

    combined = results / "combined.data"
    print(f"combining {len(data_files)} shard data files into {combined}")
    done = _coverage("combine", "--keep", f"--data-file={combined}", *data_files)
    if done.returncode != 0:
        print("combine-unit-coverage: coverage combine failed", file=sys.stderr)
        return 1

    if args.summary:
        # Capture first, so a failed report is not half-written into the summary.
        table = subprocess.run(
            [
                sys.executable,
                "-m",
                "coverage",
                "report",
                f"--data-file={combined}",
                "--format=markdown",
                "--fail-under=0",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if table.returncode == 0:
            with open(args.summary, "a", encoding="utf-8") as handle:
                handle.write(
                    f"## Code coverage ({args.os}, Python {args.python_version})\n\n"
                    + table.stdout
                    + "\n"
                )

    report = _coverage(
        "report", f"--data-file={combined}", f"--fail-under={args.fail_under:g}"
    )
    return report.returncode


if __name__ == "__main__":
    raise SystemExit(main())
