#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fail unless a pytest log shows every required test passing and nothing skipped.

WHY THIS EXISTS
---------------
A pytest exit status of 0 says nothing failed. It does not say the tests you
meant to run ran. Three ways a run of a planted-defect suite reports green while
testing less than it should:

  * a collection drop: a module stops importing under a guard, a ``testpaths``
    change misses it, or a file is moved, and pytest happily reports the rest;
  * a rename: the test that plants a defect is renamed or deleted, the run's
    count moves by one, and nobody reads the count;
  * a skip: ``pytest.skip`` or ``importorskip`` on a missing optional
    dependency reports as a pass at the exit-status level.

So this script reads the log the run printed and checks four things against
it, all of which a green exit status leaves unchecked:

  1. the final summary line is present, so a truncated or crashed log is not
     read as an empty pass;
  2. it reports at least ``--min-passed`` passes, and no skipped, xfailed,
     xpassed, deselected, failed or errored tests;
  3. the per-test ``PASSED <node id>`` lines in the short test summary (pytest
     prints them under ``-rp``) agree in number with that summary line, so the
     node-id check below cannot be vacuous because ``-rp`` was dropped;
  4. every node id in ``--nodes`` has its own ``PASSED`` line.

Only the "short test summary info" section is read for ``PASSED`` lines. The
repository's pytest.ini turns on live logging, and a log message that happens
to start with "PASSED " would otherwise count as a test.

WHY A LOG AND NOT JUNIT XML
---------------------------
The log is what a reader of the run sees, so the verdict and the evidence are
the same bytes. The script is also dependency-free, so the job that runs it
needs nothing installed beyond the interpreter the runner already has.

NEGATIVE CONTROLS
-----------------
``--self-test`` feeds the checks a good synthetic log and a set of planted
defects (a missing node id, a lowered pass count, a skip, a missing summary,
a dropped ``-rp``, a failure) and exits non-zero if the good log is refused or
any planted one is accepted. ``tests/unit/test_assert_pytest_required_nodes.py``
does the same over output from a real pytest subprocess, which is the second
instrument holding this parser to pytest's actual format.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# "==== 196 passed, 2 warnings in 2.24s ====", optionally "in 2.24s (0:00:02)".
_SUMMARY = re.compile(r"^=+ (?P<body>.+?) in [0-9.]+s(?: \([^)]*\))? =+$")
_SUMMARY_ITEM = re.compile(r"(?P<count>\d+) (?P<kind>[a-z]+)")
_SHORT_SUMMARY_HEADER = re.compile(r"^=+ short test summary info =+$")
# pytest colors its output when it sees a terminal or FORCE_COLOR, and the color
# codes sit inside the summary line, so they are removed before anything is matched.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# Outcomes a planted-defect suite must never report. A skip in particular is the
# one a green exit status hides.
_FORBIDDEN = (
    "failed",
    "error",
    "errors",
    "skipped",
    "xfailed",
    "xpassed",
    "deselected",
)


@dataclass
class Verdict:
    passed: int = 0
    problems: list[str] = field(default_factory=list)


def parse_summary(lines: list[str]) -> dict[str, int] | None:
    """Return the counts on the last pytest summary line, or None if there is none."""
    for line in reversed(lines):
        match = _SUMMARY.match(line.strip())
        if match:
            counts: dict[str, int] = {}
            for item in _SUMMARY_ITEM.finditer(match.group("body")):
                counts[item.group("kind")] = int(item.group("count"))
            return counts
    return None


def passed_node_ids(lines: list[str]) -> list[str]:
    """Return the node ids on PASSED lines inside the short test summary section."""
    nodes: list[str] = []
    inside = False
    for raw in lines:
        line = raw.rstrip("\n")
        if _SHORT_SUMMARY_HEADER.match(line.strip()):
            inside = True
            continue
        if not inside:
            continue
        if _SUMMARY.match(line.strip()):
            break
        if line.startswith("PASSED "):
            nodes.append(line[len("PASSED ") :].rstrip())
    return nodes


def check(log_text: str, required: list[str], min_passed: int) -> Verdict:
    verdict = Verdict()
    lines = _ANSI.sub("", log_text).splitlines()

    if min_passed < 1:
        verdict.problems.append(
            f"--min-passed is {min_passed}; a floor below 1 checks nothing"
        )
    if not required:
        verdict.problems.append(
            "the required node list is empty; the node-id check would be vacuous"
        )
    duplicates = sorted({node for node in required if required.count(node) > 1})
    if duplicates:
        verdict.problems.append(
            f"the required node list repeats: {', '.join(duplicates)}"
        )

    counts = parse_summary(lines)
    if counts is None:
        verdict.problems.append(
            "no pytest summary line found; the run crashed, was truncated, or its output is not this log"
        )
        return verdict

    verdict.passed = counts.get("passed", 0)
    if verdict.passed < min_passed:
        verdict.problems.append(
            f"{verdict.passed} passed, below the floor of {min_passed}: tests were dropped from collection, "
            "deleted or renamed"
        )
    for kind in _FORBIDDEN:
        if counts.get(kind):
            verdict.problems.append(
                f"the run reports {counts[kind]} {kind}; these suites must run every test"
            )

    passed = passed_node_ids(lines)
    if len(passed) != verdict.passed:
        verdict.problems.append(
            f"the short test summary lists {len(passed)} PASSED lines but the summary line says "
            f"{verdict.passed} passed; run pytest with -rp so every pass is named"
        )
    seen = set(passed)
    for node in required:
        if node not in seen:
            verdict.problems.append(f"required test did not pass: {node}")
    return verdict


def read_nodes(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


# --- self-test -----------------------------------------------------------------

_GOOD_NODES = (
    "tests/unit/test_a.py::test_one",
    "tests/unit/test_a.py::test_two[case-a]",
    "tests/unit/test_b.py::TestThing::test_three",
)


def _log(
    passed_nodes: tuple[str, ...], summary: str | None, *, short_summary: bool = True
) -> str:
    out = [
        "============================= test session starts ==============================",
        "INFO     some.logger:mod.py:1 PASSED is how a live log line may begin",
        "PASSED tests/unit/test_a.py::test_one",
    ]
    if short_summary:
        out.append(
            "=========================== short test summary info ============================"
        )
        out.extend(f"PASSED {node}" for node in passed_nodes)
    if summary is not None:
        out.append(
            f"============================== {summary} in 1.23s ==============================="
        )
    return "\n".join(out) + "\n"


def self_test() -> int:
    required = list(_GOOD_NODES)
    floor = len(_GOOD_NODES)
    good = _log(_GOOD_NODES, f"{floor} passed, 1 warning")
    plants = {
        "a required node id is missing (renamed test)": (
            _log(
                _GOOD_NODES[:2]
                + ("tests/unit/test_b.py::TestThing::test_three_renamed",),
                f"{floor} passed",
            ),
            "required test did not pass",
        ),
        "the pass count is lowered below the floor (collection drop)": (
            _log(_GOOD_NODES[:2], "2 passed"),
            "below the floor",
        ),
        "a test was skipped": (
            _log(_GOOD_NODES, f"{floor} passed, 1 skipped"),
            "1 skipped",
        ),
        "a test failed": (
            _log(_GOOD_NODES, f"{floor} passed, 1 failed"),
            "1 failed",
        ),
        "tests were deselected": (
            _log(_GOOD_NODES, f"{floor} passed, 4 deselected"),
            "4 deselected",
        ),
        "a colored log with a renamed test": (
            "\x1b[32m"
            + _log(_GOOD_NODES[:2], f"{floor} passed").replace(
                "passed in", "passed\x1b[0m in"
            ),
            "required test did not pass",
        ),
        "the summary line is missing (crash or truncation)": (
            _log(_GOOD_NODES, None),
            "no pytest summary line",
        ),
        "-rp was dropped, so no pass is named": (
            _log((), f"{floor} passed", short_summary=False),
            "PASSED lines",
        ),
    }

    failures: list[str] = []
    verdict = check(good, required, floor)
    if verdict.problems:
        failures.append(f"the good log was refused: {verdict.problems}")
    colored = "\x1b[32m" + good.replace(" passed,", " \x1b[1mpassed\x1b[0m,")
    if check(colored, required, floor).problems:
        failures.append("the good log was refused once colored")
    for name, (text, expected) in plants.items():
        verdict = check(text, required, floor)
        if not any(expected in problem for problem in verdict.problems):
            failures.append(
                f"planted defect accepted: {name} (problems: {verdict.problems})"
            )
    if not check(good, [], floor).problems:
        failures.append("an empty required node list was accepted")
    if not check(good, required, 0).problems:
        failures.append("a floor of 0 was accepted")

    for failure in failures:
        print(f"::error::self-test: {failure}")
    if failures:
        return 1
    print(
        f"self-test passed: the good log was accepted and all {len(plants) + 2} planted defects were refused"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--self-test", action="store_true", help="run against planted logs and exit"
    )
    parser.add_argument("--log", type=Path, help="the pytest output to judge")
    parser.add_argument(
        "--nodes", type=Path, help="file of required node ids, one per line"
    )
    parser.add_argument(
        "--min-passed", type=int, help="the least number of passes accepted"
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.log is None or args.nodes is None or args.min_passed is None:
        parser.error(
            "--log, --nodes and --min-passed are required unless --self-test is given"
        )

    verdict = check(
        args.log.read_text(encoding="utf-8"), read_nodes(args.nodes), args.min_passed
    )
    for problem in verdict.problems:
        print(f"::error::{problem}")
    if verdict.problems:
        return 1
    print(
        f"{verdict.passed} passed (floor {args.min_passed}); every required node id passed; nothing skipped"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
