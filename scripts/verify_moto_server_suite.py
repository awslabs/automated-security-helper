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

  - a floor on how many tests the moto-server modules together executed
    (``MIN_TESTS``; the rest of the directory does not count), so a suite that
    shrank goes red even when unrelated modules keep the directory total up
  - zero skips, so the Windows-only guards in the suite cannot quietly widen and
    take the whole thing with them
  - a floor per module (``REQUIRED_MODULES``), so losing a file, or a file
    shrinking to a handful of tests, is caught even if the others grew
  - both parametrizations present in the S3 module, so the CDK copy silently
    ceasing to be exercised is caught even though the Terraform copy would keep
    the count up

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

# A floor on the moto-server modules TOGETHER, not the exact count and not the
# whole directory. tests/unit/deploy also holds about thirty modules that never
# start a moto server; counting those let the three moto modules shrink to one
# test each while the directory total kept the floor satisfied. Only tests from
# REQUIRED_MODULES count towards this number.
MIN_TESTS = 45

# Losing any one of these files should be red even if the others grew. Each covers
# a different AWS surface, so one disappearing is not made up for by the rest.
# The value is each module's own floor: a module that still runs but shrank to a
# handful of tests is caught here, where "at least one test ran" was not.
REQUIRED_MODULES = {
    "test_deploy_s3_sync_moto_server": 20,
    "test_deploy_buildspec_ssm_moto_server": 8,
    "test_deploy_mcp_entrypoint_secrets_moto_server": 6,
}

# The two copies of the S3 helper. Each behavior test runs against both, so a
# parametrization that stops being generated means one deployment tree is no
# longer covered while the count still looks healthy. Only the S3 module carries
# this parametrization: matching the id anywhere in the suite let an unrelated
# module's "terraform" satisfy it after the S3 helper's copy was lost.
PARAMETRIZED_MODULE = "test_deploy_s3_sync_moto_server"
REQUIRED_PARAMS = ("cdk-template", "terraform")


def module_of(name: str) -> set[str]:
    """The dotted components of a ``classname::name`` test id's classname.

    A module is matched as a whole component, not as a substring: a module
    renamed to ``test_deploy_s3_sync_moto_server_v2`` must not keep satisfying the
    floor of ``test_deploy_s3_sync_moto_server``.
    """
    classname = name.split("::", 1)[0]
    return set(classname.split("."))


def evaluate_report(
    totals: dict[str, int], names: list[str], skipped: list[str] | None = None
) -> list[str]:
    """The problems a parsed JUnit report shows, as strings; empty means clean.

    ``names`` are ``classname::name`` per test case; ``skipped`` are the names of
    the cases the report marks skipped. A module's tests are the names whose
    classname carries the module as one dotted component.
    """
    problems: list[str] = []

    if totals["failures"] or totals["errors"]:
        problems.append(
            f"{totals['failures']} failure(s) and {totals['errors']} error(s); "
            f"see the pytest output above"
        )

    by_module = {
        module: [name for name in names if module in module_of(name)]
        for module in REQUIRED_MODULES
    }

    # The zero-skip rule guards the moto-server modules, whose Windows-only guards
    # must not widen on Linux. A skip in one of the other modules under
    # tests/unit/deploy is that module's business and does not make this gate red.
    moto_skipped = [
        name
        for name in (skipped or [])
        if any(module in module_of(name) for module in REQUIRED_MODULES)
    ]
    if moto_skipped:
        problems.append(
            f"{len(moto_skipped)} test(s) skipped in the moto-server modules. This "
            f"gate runs on Linux, where nothing in those modules is expected to "
            f"skip: {moto_skipped}"
        )
    moto_total = sum(len(module_names) for module_names in by_module.values())
    if moto_total < MIN_TESTS:
        problems.append(
            f"only {moto_total} test(s) ran from the moto-server modules "
            f"({sorted(REQUIRED_MODULES)}), below the floor of {MIN_TESTS}. The "
            f"directory ran {totals['tests']} in all, but the other modules start "
            f"no moto server and do not count. Either the suite stopped being "
            f"collected, or it shrank enough to need a deliberate decision about "
            f"this floor."
        )

    for module, floor in REQUIRED_MODULES.items():
        ran = len(by_module[module])
        if ran == 0:
            problems.append(
                f"no test ran from {module}. The file was renamed, moved or stopped "
                f"being collected."
            )
        elif ran < floor:
            problems.append(
                f"only {ran} test(s) ran from {module}, below its floor of {floor}. "
                f"The module shrank while the others kept the total healthy."
            )

    s3_names = by_module[PARAMETRIZED_MODULE]
    for param in REQUIRED_PARAMS:
        if not any(f"[{param}" in name or f"-{param}" in name for name in s3_names):
            problems.append(
                f"no test in {PARAMETRIZED_MODULE} ran against the {param!r} copy of "
                f"the S3 helper, so that deployment tree is no longer covered even "
                f"though the total count looks healthy."
            )
    return problems


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
        # not import. pytest.ini measures nothing by default; --no-cov keeps it
        # that way here even if coverage options are added to addopts again.
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

    skipped = [
        f"{c.get('classname', '')}::{c.get('name', '')}"
        for c in cases
        if c.find("skipped") is not None
    ]
    problems = evaluate_report(totals, names, skipped)

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
