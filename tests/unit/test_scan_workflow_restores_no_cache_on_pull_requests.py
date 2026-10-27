# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan job restores no cache on a pull request or in the merge queue.

Why this file exists
--------------------
On ``pull_request``, actions/cache looks in the run's own scope (``refs/pull/<n>/merge``)
before the base branch's. The scan job never saves there, but any other job that runs
the pull request's code in that scope can: the cache-writing token is held by the
runner process, and on a hosted runner a step can read it. Restoring such an entry hands
the pull request three things in the job that judges it:

* the uv cache (setup-uv ``enable-cache``). uv trusts its cache for a pinned git commit,
  so an entry written in that scope replaces the base commit's ASH in every later
  ``uv``/``uvx`` call;
* the grype database, of which only the age is checked;
* any file the runner user can write. @actions/cache extracts with ``tar -xf ... -P``
  (actions/toolkit packages/cache/src/internal/tar.ts), so an entry's members are not
  confined to the cache path. Hashing the restored OpenGrep binary against its pin
  checks the one file that is meant to be there and nothing else in the archive.

So on ``pull_request`` and ``merge_group`` the scan job restores nothing: no uv cache,
no grype database, no OpenGrep binary. Each is downloaded and verified as on a miss.
Pushes still restore and save as before.

What this asserts
-----------------
For every caller of run-ash-security-scan.yml that a same-repository pull request, a
fork pull request or a merge-queue entry starts, and for an external caller that turns
every install on, no step of the called workflow restores a cache: no
``actions/cache`` or ``actions/cache/restore`` step whose ``if:`` holds, no setup-uv
step with its cache on, no setup-python ``cache:`` and no setup-ruby
``bundler-cache``. Controls: on a push to the default branch the uv cache, the grype
database and the OpenGrep binary are still restored, so the predicate can see each
of the three.

What it does not cover
----------------------
Caching built into an action this file does not list. Whether GitHub lets a job read
the runtime token is GitHub's behavior and is not measured here.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.utils import github_actions as ga

SCAN_WORKFLOW = ga.WORKFLOWS_DIR / "run-ash-security-scan.yml"
REPO = "awslabs/automated-security-helper"
FORK = "contributor/automated-security-helper"
BASE_SHA = "1111111111111111111111111111111111111111"

# Outputs the restore conditions read, as a run that computed a grype key sees them.
STEP_OUTPUTS = {
    "cachekeys": {"outputs": {"week": "2026-W41", "grype-db": "grype-db-v1-w1-b1"}},
}

EXTERNAL_CALLER = {
    "with": {
        "install-grype": True,
        "install-syft": True,
        "install-opengrep": True,
        "install-cfn-nag": True,
    }
}


def _event(name: str, *, fork: bool = False) -> dict[str, Any]:
    repository = {"default_branch": "main", "full_name": REPO}
    if name == "pull_request":
        return ga.base_context(
            event_name="pull_request",
            repository=REPO,
            repository_owner="awslabs",
            ref="refs/pull/812/merge",
            ref_name="812/merge",
            head_ref="feature-branch",
            base_ref="main",
            event={
                "repository": repository,
                "pull_request": {
                    "head": {
                        "ref": "feature-branch",
                        "sha": "2" * 40,
                        "repo": {"full_name": FORK if fork else REPO},
                    },
                    "base": {
                        "ref": "main",
                        "sha": BASE_SHA,
                        "repo": {"full_name": REPO},
                    },
                },
            },
        )
    if name == "merge_group":
        queue = "gh-readonly-queue/main/pr-812-" + "3" * 40
        return ga.base_context(
            event_name="merge_group",
            repository=REPO,
            repository_owner="awslabs",
            ref=f"refs/heads/{queue}",
            ref_name=queue,
            head_ref="",
            base_ref="",
            event={
                "repository": repository,
                "merge_group": {
                    "base_ref": "refs/heads/main",
                    "base_sha": BASE_SHA,
                    "head_ref": f"refs/heads/{queue}",
                    "head_sha": "3" * 40,
                },
            },
        )
    assert name == "push"
    return ga.base_context(
        event_name="push",
        repository=REPO,
        repository_owner="awslabs",
        ref="refs/heads/main",
        ref_name="main",
        event={"repository": repository},
    )


def _callers(context: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """(label, inputs) for every repository caller the event starts, plus an external one."""
    called = ga.load_workflow(SCAN_WORKFLOW)
    found = [("external caller", ga.call_inputs(EXTERNAL_CALLER, called, context))]
    for workflow in ga.all_workflows():
        if not ga.triggers(workflow, context):
            continue
        scoped = dict(context)
        scoped["needs"] = {
            j: {"result": "success", "outputs": {}} for j in workflow.jobs
        }
        for job_id, job in workflow.jobs.items():
            target = ga.local_reusable_workflow(job)
            if target is None or target.path.resolve() != SCAN_WORKFLOW.resolve():
                continue
            if ga.job_runs(job, scoped):
                found.append(
                    (f"{workflow.name}: {job_id}", ga.call_inputs(job, called, scoped))
                )
    return found


def _off(value: Any) -> bool:
    return value is False or ga.to_string(value).strip().lower() in ("false", "")


def _restores(step: dict[str, Any], ctx: dict[str, Any]) -> str | None:
    """Why ``step`` restores a cache in ``ctx``, or None if it does not."""
    uses = str(step.get("uses") or "")
    inputs = step.get("with") or {}
    try:
        runs = ga.condition_holds(step.get("if"), ctx)
    except ga.ExpressionError:
        runs = True
    if not runs:
        return None
    if uses.startswith(("actions/cache@", "actions/cache/restore@")):
        return f"restores {inputs.get('path')!r}"
    if uses.startswith("astral-sh/setup-uv@"):
        # setup-uv's `auto` turns the cache on for pull_request and merge_group.
        enabled = ga.render(inputs.get("enable-cache", "auto"), ctx)
        restore = ga.render(inputs.get("restore-cache", True), ctx)
        if not _off(enabled) and not _off(restore):
            return f"setup-uv restores the uv cache (enable-cache={enabled!r})"
    if uses.startswith("actions/setup-python@") and not _off(
        ga.render(inputs.get("cache", ""), ctx)
    ):
        return "setup-python restores a package cache"
    if uses.startswith("ruby/setup-ruby@") and not _off(
        ga.render(inputs.get("bundler-cache", False), ctx)
    ):
        return "setup-ruby restores a bundler cache"
    return None


def _restoring_steps(context: dict[str, Any]) -> list[str]:
    workflow = ga.load_workflow(SCAN_WORKFLOW)
    found = []
    for label, inputs in _callers(context):
        ctx = ga.with_inputs({**context, "steps": STEP_OUTPUTS}, inputs)
        workflow_env = ga.render_env(workflow.data.get("env"), {**ctx, "env": {}})
        for job_id, job in workflow.jobs.items():
            job_env = ga.render_env(job.get("env"), {**ctx, "env": workflow_env})
            scoped = {**ctx, "env": {**workflow_env, **job_env}}
            for step in job.get("steps") or []:
                why = _restores(step, scoped)
                if why:
                    found.append(
                        f"  {label}: job {job_id!r}, step {step.get('name')!r}: {why}"
                    )
    return found


@pytest.mark.parametrize(
    "context",
    [
        pytest.param(_event("pull_request"), id="same-repository pull request"),
        pytest.param(_event("pull_request", fork=True), id="fork pull request"),
        pytest.param(_event("merge_group"), id="merge queue entry"),
    ],
)
def test_no_cache_is_restored_on_a_pull_request_or_in_the_merge_queue(context):
    restoring = _restoring_steps(context)
    assert not restoring, (
        "on this event the scan job restores a cache entry that a job running the "
        "pull request's code may have written, and a restored archive can place "
        "files anywhere the runner user can write:\n" + "\n".join(restoring)
    )


def test_a_push_to_the_default_branch_still_restores_all_three():
    """Control: the predicate sees each restore the fix turns off."""
    restoring = "\n".join(_restoring_steps(_event("push")))
    assert "setup-uv restores the uv cache" in restoring, restoring
    assert "~/.cache/grype/db" in restoring, restoring
    assert "~/.opengrep/cli/latest" in restoring, restoring
