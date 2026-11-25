#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Combine the coverage data of every leg of the unit tier and apply the threshold once.

The unit tier runs in shards per OS and Python version (six on Linux, eight on macOS
and Windows), and every leg measures coverage. A set is the artifacts of one OS and one
Python version: that pool's count of them (``...-shard1of8`` to ``...-shard8of8``); a set
of one (``...-shard1of1``) is still a complete set, for a run of the tier that was not
split. No single shard of a split run can meet the 80% total-coverage gate, so the check
below is what makes the split safe: a missing shard, or a whole set that never uploaded,
is a failure, never a lower number. A run measures coverage, writes
``test-results/coverage.data`` and uploads it with the rest of its test results. This
script runs in the ``unit-coverage`` job after they are downloaded, one subdirectory per
artifact, and does what a single whole-suite "Run PyTest" step did in one process:

1. Check that every expected set (the product of ``--os`` and ``--python-version``) is
   there and whole. The shard names carry their own count (``...-shard3of8``), so a shard
   that crashed before uploading, or a matrix entry that was deleted, shows as a missing
   index, and a set with no artifact at all is its own problem. Combining what happens to
   exist would report coverage for a subset and could pass. Each data file must also read
   back and hold measured files, because ``coverage combine`` skips a file it cannot read
   with a warning.
2. ``coverage combine`` every data file of every set into one. The recorded source paths
   differ by operating system (``/home/runner/work/...``, ``/Users/runner/work/...``,
   ``D:\\a\\...``); the ``[paths]`` section of ``.coveragerc`` folds them into the
   checkout's own ``automated_security_helper/``, so one file is one entry in the
   combined data, and a path that matched no alias would fail ``coverage report`` with
   "No source for code" instead of being counted as a second file.
3. Print the Markdown table to the step summary when asked, followed by each OS's own
   combined total. The per-OS totals inform and gate nothing.
4. ``coverage report --fail-under=<threshold>`` on the combined data, whose exit status is
   this script's. This is the one place the threshold is applied.

The gate is weaker than the four per-OS gates it replaced. Each of those held its own
operating system to the threshold, "where the platform specific code paths differ". The
union of every set is never lower than any one set's figure, so it passes everything the
per-OS gates passed and also a run in which one platform lost a large share of its
tests (a Windows-only ``skipif`` that skips 40% of the suite still leaves the union
above the threshold). The union is the gate on purpose, because it is the one figure
that does not depend on how the tier is sharded. The per-OS totals in the step summary
are how a one-platform drop is seen; a lower per-OS floor is the way to gate it.

A set is named by the artifact name up to the shard suffix, which the run-unit-tests
action builds from the operating system, the architecture, the Python version and the
tier marker. The architecture label is the runner's own statement about itself, so this
script reads it from the artifact names it finds (one per set; two for one set is a
problem) instead of naming it. ``--marker`` is required, with no default: without it the
name would have no tier segment, so a combine that named no tier would look for the
untiered artifact name no job uploads, or combine whatever set it found under it, and a
gate run over an unmarked shard set could pass without having read the unit tier at all.

Usage::

    combine-unit-coverage.py --results-dir shard-results \\
        --os "ubuntu-latest ubuntu-24.04-arm macos-latest windows-latest" \\
        --python-version "3.11 3.12 3.13 3.14" --marker unit --fail-under 80 \\
        --summary "$GITHUB_STEP_SUMMARY"
    combine-unit-coverage.py --self-test

``--os`` and ``--python-version`` each take one value or a list separated by commas or
spaces.

Exit codes: 0 success, 1 shards missing or malformed, 2 coverage below the threshold
(coverage.py's own status), 64 a usage error.
"""

from __future__ import annotations

import argparse
import glob
import re
import subprocess
import sys
import tempfile
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
            f"runner arch {runner_arch!r} is not one of {sorted(ARCH_LABELS)}"
        )
    return set_prefix(os_name, label, python_version, marker)


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
        # An unsharded run uploads one artifact, shard1of1, a complete set of
        # one; the check still admits it.
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
    # discover_labels is the path the gate takes; each case plants directories and reads
    # back what it finds, including two image names where one is a dash-prefix of the other.
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        for name in (
            "test-results-ubuntu-24.04-x86_64-py3.12-unit-shard1of1",
            "test-results-ubuntu-24.04-arm-arm64-py3.12-unit-shard1of1",
            "test-results-macos-15-arm64-py3.12-unit-shard1of2",
            "test-results-macos-15-intel-x86_64-py3.12-unit-shard1of2",
            "test-results-windows-latest-x86_64-py3.12-unit-shard1of1",
            "test-results-windows-latest-arm64-py3.12-unit-shard1of1",
            "test-results-ubuntu-latest-x86_64-py3.12-unit-shardjunk",
        ):
            (root / name).mkdir()
        label_cases = [
            ("a dash-prefix image", "ubuntu-24.04", "3.12", (["x86_64"], [])),
            ("the longer image", "ubuntu-24.04-arm", "3.12", (["arm64"], [])),
            ("a dash-prefix macOS image", "macos-15", "3.12", (["arm64"], [])),
            ("the longer macOS image", "macos-15-intel", "3.12", (["x86_64"], [])),
            ("no artifact", "ubuntu-24.04", "3.10", ([], [])),
        ]
        for label, os_name, version, want in label_cases:
            got = discover_labels(root, os_name, version, "unit")
            if got != want:
                failures.append(f"discover_labels, {label}: {got}, not {want}")
        _, two_labels = discover_labels(root, "windows-latest", "3.12", "unit")
        if len(two_labels) != 1:
            failures.append(f"discover_labels, two labels for one set: {two_labels}")
        _, stray = discover_labels(root, "ubuntu-latest", "3.12", "unit")
        if len(stray) != 1:
            failures.append(f"discover_labels, a stray name: {stray}")
    for text, want in [
        ("3.12", ["3.12"]),
        ("3.10, 3.12  3.14", ["3.10", "3.12", "3.14"]),
        ("a a,b", ["a", "b"]),
        ("  ", []),
    ]:
        if split_list(text) != want:
            failures.append(f"split_list({text!r}) is {split_list(text)}, not {want}")
    return failures


def find_shard_dirs(results: Path, prefix: str) -> list[tuple[str, Path]]:
    """(artifact name, directory holding its files) per shard of one set.

    download-artifact extracts straight into its path, with no per-artifact directory,
    only when exactly one artifact matched its pattern. The unit-coverage job expects
    several sets, so that layout is a failure here: the files of a lone artifact cannot
    be told from any one of them, and it is reported as an absent set.
    """
    dirs = sorted(p for p in results.glob(f"{prefix}-shard*") if p.is_dir())
    return [(p.name, p) for p in dirs]


def set_prefix(
    os_name: str, label: str, python_version: str, marker: str | None = None
) -> str:
    """The one place an artifact name is built, up to the shard suffix.

    Without ``marker`` the name ends at the Python version.
    """
    prefix = f"test-results-{os_name}-{label}-py{python_version}"
    return prefix if marker is None else f"{prefix}-{marker}"


def discover_labels(
    results: Path, os_name: str, python_version: str, marker: str
) -> tuple[list[str], list[str]]:
    """The architecture labels one (OS, Python, tier) set was uploaded under, and problems.

    The label sits between the OS and the Python version and is the runner's own
    statement (``runner.arch``), so it is read from the names found, not named here:
    one glob per known label, each with the label spelled out. A wildcard in the label's
    place would let one OS image's glob match another's artifacts when one image name is
    a dash-prefix of the other (``ubuntu-24.04`` and ``ubuntu-24.04-arm``, ``macos-15``
    and ``macos-15-intel``). A directory under a glob whose name is not the set's prefix
    and a shard suffix is a problem.
    """
    labels: set[str] = set()
    problems: list[str] = []
    for label in sorted(set(ARCH_LABELS.values())):
        prefix = set_prefix(os_name, label, python_version, marker)
        for path in sorted(
            p for p in results.glob(f"{glob.escape(prefix)}-shard*") if p.is_dir()
        ):
            suffix = _SHARD_SUFFIX.search(path.name)
            stem = path.name[: suffix.start()] if suffix else path.name
            if stem != prefix:
                problems.append(
                    f"{path.name!r} does not fit the artifact name of a unit set"
                )
            else:
                labels.add(label)
    if len(labels) > 1:
        problems.append(
            f"{os_name} py{python_version} was uploaded under more than one "
            f"architecture label: {sorted(labels)}"
        )
    return sorted(labels), problems


def split_list(text: str) -> list[str]:
    """The values of a comma or space separated option, in order, without repeats."""
    seen: list[str] = []
    for value in re.split(r"[,\s]+", text.strip()):
        if value and value not in seen:
            seen.append(value)
    return seen


def describe_root(results: Path) -> str:
    """One level of what the download root holds, for the 'no shard artifacts' error."""
    try:
        entries = sorted(
            f"{e.name}/" if e.is_dir() else e.name for e in results.iterdir()
        )
    except OSError as error:
        return f"{results} cannot be listed: {error}"
    return f"{results} holds {entries or 'nothing'}"


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


def per_os_table(results: Path, files_by_os: dict[str, list[str]]) -> str:
    """Markdown rows of each OS image's own combined total. Informational, never gated.

    Each image's data files are combined on their own and reported, so a drop confined to
    one platform shows here even when the union of every set stays above the threshold.
    A figure that cannot be computed reads ``n/a``; nothing here changes the exit status.
    """
    rows = ["| OS image | Combined total |", "| --- | --- |"]
    for index, (os_name, files) in enumerate(sorted(files_by_os.items())):
        data = results / f"combined-os-{index}.data"
        total = "n/a"
        combined = subprocess.run(
            [
                sys.executable,
                "-m",
                "coverage",
                "combine",
                "--keep",
                f"--data-file={data}",
                *files,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if combined.returncode == 0:
            report = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "coverage",
                    "report",
                    f"--data-file={data}",
                    "--format=total",
                    "--fail-under=0",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if report.returncode == 0 and report.stdout.strip():
                total = f"{report.stdout.strip()}%"
        rows.append(f"| {os_name} | {total} |")
    return (
        "### Per-OS combined totals (not gated)\n\n"
        "The gate above is the union of every set; these figures only show where a "
        "platform alone fell.\n\n" + "\n".join(rows) + "\n\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--results-dir",
        help="directory holding one subdirectory per artifact",
    )
    parser.add_argument(
        "--os",
        help="the runs-on value of the legs, e.g. macos-latest; several separated by "
        "commas or spaces",
    )
    parser.add_argument(
        "--python-version",
        help="the Python version of the legs; several separated by commas or spaces",
    )
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
    os_names = split_list(args.os)
    python_versions = split_list(args.python_version)
    if not os_names or not python_versions:
        print(
            "combine-unit-coverage: --os and --python-version name no value",
            file=sys.stderr,
        )
        return 64

    results = Path(args.results_dir)
    problems: list[str] = []
    data_files: list[str] = []
    files_by_os: dict[str, list[str]] = {}
    sets = 0
    for os_name in os_names:
        for python_version in python_versions:
            labels, label_problems = discover_labels(
                results, os_name, python_version, args.marker
            )
            problems += label_problems
            if not labels:
                if not label_problems:
                    problems.append(
                        f"no shard artifacts found for {os_name} py{python_version} "
                        f"{args.marker}; {describe_root(results)}"
                    )
                continue
            if len(labels) > 1:
                continue
            sets += 1
            prefix = set_prefix(os_name, labels[0], python_version, args.marker)
            shard_dirs = find_shard_dirs(results, prefix)
            problems += check_shards([name for name, _ in shard_dirs], prefix)
            for name, shard_dir in shard_dirs:
                data = shard_dir / DATA_FILE
                if not data.is_file():
                    problems.append(f"{name} has no {DATA_FILE}")
                    continue
                problem = data_problem(data)
                if problem:
                    problems.append(problem)
                else:
                    data_files.append(str(data))
                    files_by_os.setdefault(os_name, []).append(str(data))
    if problems:
        for problem in problems:
            print(f"combine-unit-coverage: {problem}", file=sys.stderr)
        return 1

    combined = results / "combined.data"
    print(
        f"combining {len(data_files)} shard data files of {sets} sets into {combined}"
    )
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
                    f"## Code coverage (unit tier, {sets} OS and Python sets combined)\n\n"
                    + table.stdout
                    + "\n"
                    + per_os_table(results, files_by_os)
                )

    report = _coverage(
        "report", f"--data-file={combined}", f"--fail-under={args.fail_under:g}"
    )
    return report.returncode


if __name__ == "__main__":
    raise SystemExit(main())
