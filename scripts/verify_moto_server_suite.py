#!/usr/bin/env python3
"""CI gate for the deploy-tree AWS suite: prove it ran, not just that it was green.

WHY THIS EXISTS RATHER THAN A BARE `pytest tests/unit/deploy`
------------------------------------------------------------
Because a suite can shrink without pytest noticing. Measured against this suite,
with `pytest -q` as the whole check:

  - mark one class skip           -> 44 passed, 2 skipped, exit 0  (GREEN)
  - drop one parametrization      -> 31 passed,            exit 0  (GREEN)
  - rename one test module out of
    the discovery pattern         -> 35 passed,            exit 0  (GREEN)

Three ways to delete a third of this coverage and keep a green check. pytest is
right to exit 0 -- everything it collected passed. The problem is that "everything
it collected" is the quantity nobody is watching. So this gate asserts on the RUN
rather than the status:

  - a floor on how many tests executed, so a suite that shrank goes red
  - zero skips, so the Windows-only guards in the suite cannot quietly widen and
    take the whole thing with them
  - at least one test from each module, so losing a file is caught even if the
    remaining one grew enough to clear the floor
  - both parametrizations present, so the CDK copy silently ceasing to be
    exercised is caught even though the Terraform copy would keep the count up

For completeness: a suite that collects NOTHING at all is the one case pytest does
catch -- it exits 5. This gate reports it as "0 tests" and is red too, but that
path is not why it exists.

WHAT IT DOES NOT DO
-------------------
It does not judge which tests exist or what they assert -- that is the suite's
job. It only refuses to call an empty or half-empty run a pass. It adds no
tolerance for failures either: a single failure or error is a non-zero exit.

FAILURE MODES OF THE GATE ITSELF
--------------------------------
If pytest crashes before writing the report, there is no XML to parse and the gate
exits non-zero saying so rather than treating a missing file as zero problems. The
floor is a FLOOR, deliberately below the current count: it catches a suite that
disappeared without needing an edit every time a test is added. It will not catch
a small number of deletions, which is what code review is for.
"""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

# defusedxml, not xml.etree: the stdlib parsers accept external entities and
# expand nested entities, and this file is read by a CI gate in a security
# project whose own scanners flag exactly that. The input is our own pytest
# report, so the risk is low -- but "the input is trusted" is the assumption that
# stops being true first.
from defusedxml import ElementTree as ET

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SUITE = "tests/unit/deploy"

# A floor, not the exact count. 46 tests exist as this is written; 40 catches a
# suite that stopped being collected without going red on every addition.
MIN_TESTS = 40

# Losing one of these files should be red even if the other one grew.
REQUIRED_MODULES = (
    "test_deploy_s3_sync_moto_server",
    "test_deploy_buildspec_ssm_moto_server",
)

# The two copies of the S3 helper. Each behavior test runs against both, so a
# parametrization that stops being generated means one deployment tree is no
# longer covered while the count still looks healthy.
REQUIRED_PARAMS = ("cdk-template", "terraform")


def run_suite(report: pathlib.Path, workers: str) -> int:
    """Run the suite, writing its own JUnit report to `report`."""
    command = [
        "uv",
        "run",
        "pytest",
        SUITE,
        "-n",
        workers,
        # Coverage is scoped to automated_security_helper, which this suite does
        # not import; measuring it here would only add a fail_under gate that has
        # nothing to do with what is being verified.
        "--no-cov",
        "-q",
        "-p",
        "no:cacheprovider",
        f"--junit-xml={report}",
    ]
    print(f"$ {' '.join(command)}", flush=True)
    return subprocess.run(command, cwd=REPO_ROOT).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workers",
        default="4",
        help="pytest-xdist worker count. Each worker starts its own moto server on "
        "an OS-assigned port; 4 matches a GitHub standard runner.",
    )
    parser.add_argument(
        "--report",
        default="test-results/moto-server-suite.junit.xml",
        help="where to write the JUnit report this gate then reads back",
    )
    args = parser.parse_args()

    report = REPO_ROOT / args.report
    report.parent.mkdir(parents=True, exist_ok=True)
    if report.exists():
        # A stale report from an earlier run would let this gate pass on evidence
        # from a different commit.
        report.unlink()

    pytest_status = run_suite(report, args.workers)

    if not report.is_file():
        print(
            f"::error::pytest wrote no report to {args.report}. It exited "
            f"{pytest_status}, so it most likely failed before collection -- read the "
            f"pytest output above rather than trusting this gate's silence.",
            file=sys.stderr,
        )
        return 1

    root = ET.parse(report).getroot()
    suites = root.findall("testsuite") or [root]
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    for suite in suites:
        for key in totals:
            totals[key] += int(suite.get(key, 0))

    cases = [c for suite in suites for c in suite.iter("testcase")]
    names = [f"{c.get('classname', '')}::{c.get('name', '')}" for c in cases]

    problems: list[str] = []

    if totals["failures"] or totals["errors"]:
        problems.append(
            f"{totals['failures']} failure(s) and {totals['errors']} error(s); "
            f"see the pytest output above"
        )

    if totals["tests"] < MIN_TESTS:
        problems.append(
            f"only {totals['tests']} test(s) ran, below the floor of {MIN_TESTS}. "
            f"Either the suite stopped being collected, or it shrank enough to "
            f"need a deliberate decision about this floor."
        )

    if totals["skipped"]:
        skipped = [
            f"{c.get('classname')}::{c.get('name')}"
            for c in cases
            if c.find("skipped") is not None
        ]
        problems.append(
            f"{totals['skipped']} test(s) skipped. This gate runs on Linux, where "
            f"nothing in this suite is expected to skip: {skipped}"
        )

    for module in REQUIRED_MODULES:
        if not any(module in name for name in names):
            problems.append(
                f"no test ran from {module}. The file was renamed, moved or stopped "
                f"being collected."
            )

    for param in REQUIRED_PARAMS:
        if not any(f"[{param}" in name or f"-{param}" in name for name in names):
            problems.append(
                f"no test ran against the {param!r} copy of the S3 helper, so that "
                f"deployment tree is no longer covered even though the total count "
                f"looks healthy."
            )

    print(
        f"\nmoto server-mode suite: {totals['tests']} tests, "
        f"{totals['failures']} failures, {totals['errors']} errors, "
        f"{totals['skipped']} skipped"
    )

    if problems:
        for problem in problems:
            print(f"::error::{problem}", file=sys.stderr)
        return 1

    # pytest's own status is checked last, so a green report with a non-zero exit
    # (an internal error, a plugin crash) still fails.
    if pytest_status != 0:
        print(
            f"::error::the report looks clean but pytest exited {pytest_status}; "
            f"treating that as a failure rather than trusting the report",
            file=sys.stderr,
        )
        return 1

    print("OK: the suite ran, covered both helper copies, and skipped nothing.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
