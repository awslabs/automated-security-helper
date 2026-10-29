# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Negative controls for test_docs_ci_runners.py: a broken install must fail the run.

WHY THIS EXISTS
---------------
A pipeline under test fails when ASH finds the fixture's planted findings, and it fails
just as well when the install step breaks. test_docs_ci_runners.py tells the two apart
by ASH's verdict line. These controls show that the verdict check has teeth on every
runner and every way a block installs ASH: the first block of each leg and page that
installs the wheel runs with a wheel path that does not exist, and the first that
installs a commit (ASH's reusable workflow, the CodeBuild buildspec) runs with a commit
no repository has. In each run the job's script must start, an output line must name
the broken input, and the run must fail and report "ASH verdict line missing". A
pipeline that found another ASH to run, a runner that never started, or a run that
passed or failed for any other reason, fails its control.

The last test is the outer control: an ``ash`` that records that it ran sits first on
this process's PATH for the whole session, and every runner starts in an environment of
its own, so it must never run.

Same options and opt-in as test_docs_ci_runners.py; the Docs CI Runners workflow runs
this module after the runs, with its own --ci-runner-out and junit file.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import shutil
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.ci_runner

HERE = Path(__file__).resolve().parent
PACKAGE = "_ash_ci_runners"


def _harness(stem: str):
    if PACKAGE not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            PACKAGE,
            HERE / "ci_runners" / "__init__.py",
            submodule_search_locations=[str(HERE / "ci_runners")],
        )
        assert spec and spec.loader
        package = importlib.util.module_from_spec(spec)
        sys.modules[PACKAGE] = package
        spec.loader.exec_module(package)
    return importlib.import_module(f"{PACKAGE}.{stem}")


env = _harness("env")
census = _harness("census")
pipelines = _harness("pipelines")


def _controls() -> list:
    """The first block of each leg, page and install mechanism (wheel or commit).

    pipelines.negative_controls picks them, and check_junit.py --controls counts the
    same list, so a control that stops running fails the leg.
    """
    return [
        pytest.param(
            run,
            mechanism,
            id=f"{run.id}:{mechanism}",
            marks=pytest.mark.ci_runner(runner=run.runner, page=run.page),
        )
        for run, mechanism in pipelines.negative_controls(census.census_runs())
    ]


CONTROLS = _controls()


@pytest.fixture(scope="session")
def ci_runner_session(request, tmp_path_factory):
    """As in test_docs_ci_runners.py: options, the ASH under test, the outer ash."""
    env.require_github_hosted(os.environ)
    yield from pipelines.session_with_poisoned_ash(
        request.config, tmp_path_factory.mktemp("ci-runner-work")
    )


@pytest.mark.parametrize("run,mechanism", CONTROLS)
def test_a_block_whose_install_cannot_succeed_fails_without_a_verdict(
    run, mechanism, ci_runner_session
):
    env.require_github_hosted(os.environ)
    session = ci_runner_session
    out, work = session.directories(f"{run.out_name}-{mechanism}")
    prepared = pipelines.prepare(
        run, session.under_test.broken(mechanism), session=session, out=out, work=work
    )
    launched = pipelines.launch(prepared, session)
    problems = pipelines.control_problems(prepared, launched)
    assert not problems, pipelines.failure_message(problems, launched)


def test_the_outer_ash_is_first_on_path_and_never_ran(ci_runner_session):
    env.require_github_hosted(os.environ)
    session = ci_runner_session
    assert shutil.which("ash") == str(session.poisoned_ash), (
        "the poisoned ash must be the one this process's PATH finds"
    )
    problem = env.poisoned_ash_problem(session.sentinel)
    assert problem is None, problem
