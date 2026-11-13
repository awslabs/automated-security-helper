# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check that a runner leg ran every block the census gives it, and skipped none.

    python tests/integration/docs/ci_runners/check_junit.py \\
        --junit <junit xml of the runs> --runner <leg> --page <page> [--controls]

The runner tests make one test per census entry. A test that was skipped, or one that
never ran because the selection went wrong, would leave the job green with less tested
than it says. This reads the pytest junit file of the runs and compares the tests that
ran with the leg's census count for the page. Exit 0 when they match; otherwise each
problem is printed and the exit code is 1.

With ``--controls`` the junit file is that of test_docs_ci_runners_can_fail.py: it
must hold one negative control per install mechanism the leg's blocks on the page use
(pipelines.negative_controls), and the outer-ash test. A block that runs ASH with no
install a control can break (neither a release install line nor ASH's reusable
workflow, nor the image the run builds) fails, and so does a page whose blocks run
ASH with no control at all, so the runs' failures are never taken on trust.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKAGE = "_ash_ci_runners"


def _package_module(stem: str):
    if PACKAGE not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            PACKAGE, HERE / "__init__.py", submodule_search_locations=[str(HERE)]
        )
        assert spec and spec.loader
        package = importlib.util.module_from_spec(spec)
        sys.modules[PACKAGE] = package
        spec.loader.exec_module(package)
    return importlib.import_module(f"{PACKAGE}.{stem}")


def census_problems(junit: Path, *, expected: int) -> list[str]:
    """Problems with ``junit`` for a leg whose census holds ``expected`` blocks."""
    problems = []
    if expected == 0:
        problems.append("the census gives this leg no block on this page")
    verdict = _package_module("verdict")
    return problems + verdict.junit_census_problems(junit, expected=expected)


def uncovered_problems(runs, texts: dict) -> list[str]:
    """A problem for each block that runs ASH and installs it no way a negative
    control breaks, nor on the image the run builds; ``texts`` holds each run's
    composed block."""
    pipelines = _package_module("pipelines")
    problems = []
    for run in runs:
        text = texts[run]
        if pipelines.runs_ash(text, run.kind) and (
            pipelines.install_mechanism(run.runner, text) is None
        ):
            problems.append(
                f"block {run.ordinal} of {run.page} runs ASH, and installs it in no way "
                "a negative control breaks (a release install line, ASH's reusable "
                "workflow) nor runs on the image the run builds, so no control covers "
                "it"
            )
    return problems


def control_problems(junit: Path, *, controls: int, installs: bool) -> list[str]:
    """Problems with the controls' ``junit``: ``controls`` controls and the outer test.

    ``installs`` says whether any of the leg's blocks on the page runs ASH, other than
    on the image the run builds; if one does and there is no control, that is a
    problem of its own.
    """
    problems = []
    if installs and controls == 0:
        problems.append(
            "the leg's blocks on this page install ASH, and the census gives them no "
            "negative control"
        )
    verdict = _package_module("verdict")
    return problems + verdict.junit_census_problems(
        junit,
        expected=controls + 1,
        counted="tests of the leg's negative controls and the outer ash",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--runner", required=True)
    parser.add_argument("--page", required=True)
    parser.add_argument(
        "--controls",
        action="store_true",
        help="the junit file is the negative controls'",
    )
    args = parser.parse_args(argv)
    census = _package_module("census")
    runs = census.leg_runs(args.runner, args.page)
    if args.controls:
        pipelines = _package_module("pipelines")
        texts = {run: pipelines.composed_text(run) for run in runs}
        controls = len(pipelines.negative_controls(runs, composed=texts.__getitem__))
        # Counted apart from the controls: a block that runs ASH, however it installs
        # it, except on the image the run builds, which no control breaks.
        installs = any(
            pipelines.runs_ash(text, run.kind)
            and pipelines.install_mechanism(run.runner, text) != "built"
            for run, text in texts.items()
        )
        problems = [] if runs else ["the census gives this leg no block on this page"]
        problems += uncovered_problems(runs, texts)
        problems += control_problems(args.junit, controls=controls, installs=installs)
        summary = f"{controls} negative controls and the outer-ash test, all ran"
    else:
        problems = census_problems(args.junit, expected=len(runs))
        summary = f"{len(runs)} census blocks, all ran"
    for problem in problems:
        print(problem)
    if not problems:
        print(f"{args.runner} on {args.page}: {summary}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
