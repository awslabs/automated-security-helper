# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run each pipeline on the CI pages with its CI system's own runner.

WHY THIS EXISTS
---------------
The CI pages show complete pipelines for GitHub Actions, GitLab CI, Jenkins, AWS
CodeBuild and CircleCI. The docs checks parse them and check their ash lines; these
tests run them: GitHub workflows under nektos/act on the host, GitLab pipelines under
gitlab-ci-local, the Jenkinsfile under Jenkinsfile Runner on two Jenkins cores, the
buildspec under the AWS CodeBuild local agent, and the CircleCI config under the
CircleCI CLI's ``local execute``. Each block runs in a new git repository made from the
docs fixture, with the ASH of the checkout under test: the wheel built from it, or its
head commit.

One test per block the census in scripts/docs_checks.py gives a runner leg, named by
its leg, its page and its ordinal among the page's CI blocks. Each asserts that the run
shows what the page says (tests/integration/docs/ci_runners/pipelines.py lists every
check): the runner's own result, ASH's verdict line with the planted findings' count,
the reports where the page keeps them, the findings by file, and which ASH was
installed. Everything a runner prints goes to files under --ci-runner-out, never to
this test's output, and a failure quotes only a short tail.

Opt-in: deselected unless --run-ci-runners is given, and run only in the Docs CI
Runners workflow, one leg and page per job:

    pytest -o addopts= -n 0 tests/integration/docs/test_docs_ci_runners.py \\
        --run-integration --run-ci-runners --ci-runner <leg> --ci-runner-page <page> \\
        --ci-runner-bin <bin> --ci-runner-jenkins-dir <dir> --ci-runner-wheel <whl> \\
        --ci-runner-out <dir> --junit-xml <file>

--ci-runner and --ci-runner-page deselect the other blocks, so the junit file holds the
leg's blocks only and check_junit.py can compare it with the census. The runs start
containers that are given the Docker socket, so anywhere but a GitHub-hosted runner
they are an error, not a skip, unless DOCTEST_CI_RUNNERS_ANYWHERE=1. A machine given
that must not share its Docker daemon with anything else: each launch removes every
container the daemon gained while it ran.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
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

RUNS = [
    pytest.param(
        run, id=run.id, marks=pytest.mark.ci_runner(runner=run.runner, page=run.page)
    )
    for run in census.census_runs()
]


@pytest.fixture(scope="session")
def ci_runner_session(request, tmp_path_factory):
    """The session's options, the ASH under test, and the poisoned outer ash.

    The outer ash goes first on this process's PATH for the whole session. Every
    runner starts with an environment of its own, so no pipeline may ever reach it;
    if one did, its sentinel exists at the end and the session's last test errors.
    """
    env.require_github_hosted(os.environ)
    yield from pipelines.session_with_poisoned_ash(
        request.config, tmp_path_factory.mktemp("ci-runner-work")
    )


@pytest.mark.parametrize("run", RUNS)
def test_the_block_runs_under_its_runner_and_shows_what_the_page_says(
    run, ci_runner_session
):
    env.require_github_hosted(os.environ)
    session = ci_runner_session
    out, work = session.directories(run.out_name)
    prepared = pipelines.prepare(
        run, session.under_test, session=session, out=out, work=work
    )
    launched = pipelines.launch(prepared, session)
    problems = pipelines.run_problems(prepared, launched, session)
    assert not problems, pipelines.failure_message(problems, launched)
