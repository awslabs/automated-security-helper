# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The integration-test job installs bandit before the suite runs, the way users do.

Why this file exists
--------------------
The integration suite runs bandit for real (tests/integration/scanners/test_bandit_scanner.py
validates the scanner's dependencies). Nothing in ash-unified-ci.yml's integration-test
job installed it, so the first test that needed it ran ``uv tool install`` from inside
the suite: one more network fetch at test time, under the suite's own timeouts, and a
failure there read as a test failure. The job now installs it up front with
``ash dependencies install --tool bandit``, the installer users run, and puts the uv tool
directory on the suite step's PATH so the scanner finds that install instead of making
its own.

What this asserts
-----------------
1. A step of the job, before the suite step, runs ``ash dependencies install`` with
   ``--tool bandit`` (run through the step's own shell with ``uv`` stubbed, so the argv
   is what the shell would pass, not a substring of the YAML).
2. The suite step puts ``$HOME/.local/bin``, where ``uv tool install`` writes bandit's
   entry point, on PATH for that step only, not through GITHUB_PATH.

What it does not cover
----------------------
Whether PyPI serves the install on the runner; the step fails the job if it does not.
"""

from __future__ import annotations

import os
import shutil
from typing import Any

import pytest

from tests.utils import github_actions as ga

pytestmark = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="the steps under test are bash steps that run on ubuntu-latest",
)

WORKFLOW = ga.WORKFLOWS_DIR / "ash-unified-ci.yml"
JOB_ID = "integration-test"


def _job() -> tuple[ga.Workflow, dict[str, Any]]:
    workflow = ga.load_workflow(WORKFLOW)
    return workflow, workflow.jobs[JOB_ID]


def _suite_index(steps: list[dict[str, Any]]) -> int:
    found = [
        i
        for i, step in enumerate(steps)
        if "pytest" in str(step.get("run") or "")
        and "tests/integration" in str(step.get("run") or "")
    ]
    assert len(found) == 1, "expected one step that runs the integration suite"
    return found[0]


def _installed_tools(tmp_path, steps: list[dict[str, Any]]) -> list[tuple[int, str]]:
    workflow, job = _job()
    tools = []
    for index, step in enumerate(steps):
        if "ash dependencies install" not in str(step.get("run") or ""):
            continue
        sandbox = ga.StepSandbox(tmp_path / str(index))
        run = ga.run_step(sandbox, workflow, job, step, ga.base_context())
        assert run.proc.returncode == 0, run.describe()
        for call in run.calls_to("uv"):
            argv = call["argv"]
            if "dependencies" in argv and "install" in argv:
                tools += [
                    (index, argv[i + 1])
                    for i, arg in enumerate(argv[:-1])
                    if arg == "--tool"
                ]
    return tools


def test_bandit_is_installed_before_the_suite_runs(tmp_path):
    _, job = _job()
    steps = job.get("steps") or []
    suite = _suite_index(steps)
    installs = _installed_tools(tmp_path, steps)
    bandit = [index for index, tool in installs if tool == "bandit"]
    assert bandit, (
        f"no step of {JOB_ID} installs bandit with `ash dependencies install --tool "
        f"bandit`; the tools it installs are {sorted({t for _, t in installs})}"
    )
    assert all(index < suite for index in bandit), (
        "bandit is installed after the integration suite starts"
    )


def test_the_suite_step_sees_the_uv_tool_directory():
    _, job = _job()
    steps = job.get("steps") or []
    script = str(steps[_suite_index(steps)].get("run") or "")
    exports = [
        line.strip()
        for line in script.splitlines()
        if line.strip().startswith("export PATH=")
    ]
    assert any("$HOME/.local/bin" in line for line in exports), (
        "the suite step does not put $HOME/.local/bin on PATH, so the scanner cannot "
        "find the bandit `uv tool install` put there and installs its own"
    )
    assert "GITHUB_PATH" not in script
