# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""With config-ref, the scan job lets the installed ASH skip tools it does not have.

Why this file exists
--------------------
On ``pull_request`` the required check installs ASH from the base commit, but the
workflow files, and so the tools they ask ``ash dependencies install`` for, are the pull
request's. A pull request that adds a new tool to ASH and asks the check to install it
ran ``--tool <new tool>`` against an ASH that does not know it, which exits 2, so it
could not pass its own required check until it was split in two. A tool that ASH does
not know has no scanner in it either, and the base config cannot enable one, so the
check needs nothing from that tool.

run-ash-security-scan.yml therefore sets ``ASH_DEPENDENCIES_UNKNOWN_TOOLS=skip`` for the
whole scan job when ``config-ref`` is set (the cases where the ASH is an older commit's
than the workflow), and ASH then names and skips each tool it does not know. Set at job
level, it reaches an install step added later without that step saying so. Without
``config-ref`` it is not set, and an unknown tool name is still refused.

What this asserts
-----------------
1. For the required caller on a same-repository pull request, a fork pull request and a
   merge-queue entry, every ``ash dependencies install`` the job runs (Grype, Syft,
   OpenGrep, and a step of the same shape that no current file has) runs with the
   setting.
2. For a caller without ``config-ref`` (an external caller, and the informational job,
   which installs the pull request's own ASH), it runs without it.
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

SCAN_WORKFLOW = ga.WORKFLOWS_DIR / "run-ash-security-scan.yml"
REPO = "awslabs/automated-security-helper"
SETTING = "ASH_DEPENDENCIES_UNKNOWN_TOOLS"

# Shaped like an install step a later change adds: it knows nothing about the setting.
LATER_INSTALL_STEP = {
    "name": "Install a tool a later change adds",
    "env": {"ASH_TOOL_BIN": "${{ runner.temp }}/ash-tools"},
    "run": (
        "set -euo pipefail\n"
        '(cd "${RUNNER_TEMP}" && env -u ASH_CONFIG \\\n'
        '  uvx --from "${ASH_UVX_SOURCE}" ash dependencies install \\\n'
        '    --tool a-tool-this-ash-lacks --bin-path "${ASH_TOOL_BIN}")\n'
    ),
}


def _event(name: str, *, fork: bool = False) -> dict[str, Any]:
    repository = {"default_branch": "main", "full_name": REPO}
    if name == "merge_group":
        return ga.base_context(
            event_name="merge_group",
            repository=REPO,
            repository_owner="awslabs",
            ref="refs/heads/gh-readonly-queue/main/pr-812-" + "3" * 40,
            event={
                "repository": repository,
                "merge_group": {"base_ref": "refs/heads/main", "base_sha": "1" * 40},
            },
        )
    return ga.base_context(
        event_name="pull_request",
        repository=REPO,
        repository_owner="awslabs",
        ref="refs/pull/812/merge",
        head_ref="feature-branch",
        base_ref="main",
        event={
            "repository": repository,
            "pull_request": {
                "head": {
                    "ref": "feature-branch",
                    "sha": "2" * 40,
                    "repo": {
                        "full_name": "contributor/automated-security-helper"
                        if fork
                        else REPO
                    },
                },
                "base": {"ref": "main", "sha": "1" * 40, "repo": {"full_name": REPO}},
            },
        },
    )


def _caller_inputs(context: dict[str, Any], *, informational: bool) -> dict[str, Any]:
    called = ga.load_workflow(SCAN_WORKFLOW)
    name = "ash-repo-scan-pr-head.yml" if informational else "ash-repo-scan.yml"
    caller = ga.load_workflow(ga.WORKFLOWS_DIR / name)
    (job,) = [
        j
        for j in caller.jobs.values()
        if str(j.get("uses") or "").endswith("run-ash-security-scan.yml")
    ]
    return ga.call_inputs(job, called, context)


def _settings(tmp_path, context, inputs) -> list[tuple[str, Any]]:
    workflow = ga.load_workflow(SCAN_WORKFLOW)
    job = workflow.jobs["ash"]
    steps = [
        s
        for s in job.get("steps") or []
        if "ash dependencies install" in str(s.get("run") or "")
    ]
    assert len(steps) >= 3, [s.get("name") for s in steps]
    found = []
    ctx = ga.with_inputs(context, inputs)
    for index, step in enumerate([*steps, LATER_INSTALL_STEP]):
        sandbox = ga.StepSandbox(tmp_path / str(index))
        run = ga.run_step(sandbox, workflow, job, step, ctx)
        calls = [
            c
            for c in run.calls_to("uvx")
            if "dependencies" in c["argv"] and "install" in c["argv"]
        ]
        assert calls, f"step {step.get('name')!r} ran no install:\n" + run.describe()
        found += [(str(step.get("name")), c["env"].get(SETTING)) for c in calls]
    return found


@pytest.mark.parametrize(
    "context",
    [
        pytest.param(_event("pull_request"), id="same-repository pull request"),
        pytest.param(_event("pull_request", fork=True), id="fork pull request"),
        pytest.param(_event("merge_group"), id="merge queue entry"),
    ],
)
def test_the_required_check_lets_its_ash_skip_unknown_tools(tmp_path, context):
    inputs = _caller_inputs(context, informational=False)
    assert inputs.get("config-ref"), "the required check sets no config-ref"
    wrong = [(n, v) for n, v in _settings(tmp_path, context, inputs) if v != "skip"]
    assert not wrong, (
        f"these installs run without {SETTING}=skip, so a tool the base commit's ASH "
        f"does not know fails the required check: {wrong}"
    )


def test_without_config_ref_an_unknown_tool_is_still_refused(tmp_path):
    called = ga.load_workflow(SCAN_WORKFLOW)
    context = _event("pull_request")
    for label, inputs in (
        ("external caller", ga.call_inputs({"with": {}}, called, context)),
        ("informational job", _caller_inputs(context, informational=True)),
    ):
        assert not inputs.get("config-ref"), label
        wrong = [
            (n, v)
            for n, v in _settings(tmp_path / label.replace(" ", "-"), context, inputs)
            if v
        ]
        assert not wrong, f"{label}: installs run with {SETTING} set: {wrong}"
