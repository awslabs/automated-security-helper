# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every ``bundle install`` in .github/ installs exactly what its Gemfile.lock records.

Why this file exists
--------------------
run-ash-security-scan.yml installs cfn-nag with ``bundle install`` against ASH's
Gemfile and Gemfile.lock, fetched from the commit the scan pinned. Without frozen mode,
Bundler resolves again whenever the Gemfile and the lockfile disagree or the lockfile
is missing, and installs whatever rubygems.org serves that day, so the lockfile was a
suggestion. With ``BUNDLE_FROZEN=true`` Bundler refuses both cases. Measured with
Bundler 2.4.22 against ASH's own files: a Gemfile that no longer matches its lockfile
exits 16 ("the lockfile can't be updated because frozen mode is set"), and a Gemfile
with no lockfile exits 16 ("requires a lockfile"), each before contacting a gem server;
the matching pair passes resolution. The lockfile's only platform is ``ruby``, which
Bundler 2.5's platform check (``MatchPlatform.platforms_match?``) accepts on any
runner, so frozen mode does not refuse it on x86_64-linux.

What this asserts
-----------------
1. Every step in .github/workflows and .github/actions whose ``run:`` calls
   ``bundle install`` (directly or through a variable holding the bundle path) runs it
   frozen: ``BUNDLE_FROZEN`` or ``BUNDLE_DEPLOYMENT`` true in the step's, job's or
   workflow's ``env:``, or ``--frozen``/``--deployment`` or an inline
   ``BUNDLE_FROZEN=true`` on the command. The scan finds the cfn-nag step, so it
   cannot pass by finding none.
2. Run through the Actions model, the cfn-nag step's ``bundle install`` sees
   ``BUNDLE_FROZEN=true`` and finds the lockfile beside the Gemfile it was handed, both
   fetched from ASH's assets URL.
3. The step stops before ``bundle install`` when the lockfile fetch left no lockfile.
4. Negative controls: the checker flags a bare ``bundle install`` and the same step
   with ``BUNDLE_FROZEN`` removed.
"""

from __future__ import annotations

import copy
import os
import re
import shutil
from pathlib import Path
from typing import Any, Iterator

import pytest
import yaml

from tests.utils import github_actions as ga

REPO_ROOT = Path(__file__).resolve().parents[2]
SCAN_WORKFLOW = ga.WORKFLOWS_DIR / "run-ash-security-scan.yml"
CFN_NAG_STEP = "Install cfn-nag"

# `bundle install`, `bundler install`, or `"${BUNDLE_BIN}" install` for a variable that
# holds the bundle executable.
_INSTALL = re.compile(
    r"""(?:^|[\s;&|(])(?:bundler?|"?\$\{?[A-Z_]*BUNDLE[A-Z_]*\}?"?)\s+install\b"""
)
_INLINE_FROZEN = re.compile(
    r"--frozen\b|--deployment\b|\bBUNDLE_(?:FROZEN|DEPLOYMENT)=(?:true|1)\b"
)


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("true", "1")


def _frozen_by_env(*envs: dict[str, Any] | None) -> bool:
    merged: dict[str, Any] = {}
    for env in envs:
        merged.update(env or {})
    return _truthy(merged.get("BUNDLE_FROZEN")) or _truthy(
        merged.get("BUNDLE_DEPLOYMENT")
    )


def install_is_frozen(step: dict[str, Any], *outer_envs: dict[str, Any] | None) -> bool:
    """Whether every bundle install in the step runs frozen, read from the YAML."""
    script = str(step.get("run") or "")
    if not _INSTALL.search(script):
        return True
    if _frozen_by_env(*outer_envs, step.get("env")):
        return True
    return all(
        _INLINE_FROZEN.search(line)
        for line in script.splitlines()
        if _INSTALL.search(line)
    )


def _steps_with_installs() -> Iterator[tuple[str, dict[str, Any], tuple]]:
    for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for job_id, job in (data.get("jobs") or {}).items():
            for step in (job or {}).get("steps") or []:
                if _INSTALL.search(str(step.get("run") or "")):
                    where = f"{path.relative_to(REPO_ROOT)}:{job_id}:{step.get('name')}"
                    yield where, step, (data.get("env"), job.get("env"))
    for path in sorted((REPO_ROOT / ".github" / "actions").glob("*/action.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for step in ((data.get("runs") or {}).get("steps")) or []:
            if _INSTALL.search(str(step.get("run") or "")):
                yield f"{path.relative_to(REPO_ROOT)}:{step.get('name')}", step, ()


@pytest.mark.unit
def test_every_bundle_install_in_github_runs_frozen():
    found = list(_steps_with_installs())
    assert any(CFN_NAG_STEP in where for where, _, _ in found), (
        "found no bundle install in .github/; the scan is broken, not clean"
    )
    loose = [where for where, step, envs in found if not install_is_frozen(step, *envs)]
    assert not loose, (
        "these steps run `bundle install` without frozen mode, so Bundler re-resolves "
        "when the Gemfile and Gemfile.lock disagree or the lockfile is missing: "
        + ", ".join(loose)
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "step",
    [
        {"run": "bundle install --jobs=4"},
        {"run": 'export BUNDLE_GEMFILE=x\n"${BUNDLE_BIN}" install --jobs=4'},
        {"run": "bundler install"},
        {"env": {"BUNDLE_FROZEN": "false"}, "run": "bundle install"},
    ],
)
def test_the_checker_flags_an_install_that_is_not_frozen(step):
    assert not install_is_frozen(step)


@pytest.mark.unit
@pytest.mark.parametrize(
    "step",
    [
        {"env": {"BUNDLE_FROZEN": "true"}, "run": "bundle install"},
        {"run": "BUNDLE_FROZEN=true bundle install"},
        {"run": "bundle install --deployment"},
        {"run": "echo no bundler here"},
    ],
)
def test_the_checker_accepts_a_frozen_install(step):
    assert install_is_frozen(step)


# The cfn-nag step, run the way a runner would.

pytestmark_bash = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="the step under test is a bash step that runs on ubuntu-latest",
)


def _workflow_and_step() -> tuple[ga.Workflow, dict[str, Any], dict[str, Any]]:
    workflow = ga.load_workflow(SCAN_WORKFLOW)
    job = workflow.jobs["ash"]
    (step,) = [s for s in job.get("steps") or [] if s.get("name") == CFN_NAG_STEP]
    return workflow, job, step


def _context(workflow: ga.Workflow) -> dict[str, Any]:
    context = ga.base_context(
        event_name="pull_request",
        repository="awslabs/automated-security-helper",
        repository_owner="awslabs",
        ref="refs/pull/812/merge",
        event={"repository": {"default_branch": "main"}},
    )
    inputs = ga.call_inputs({"with": {"install-cfn-nag": True}}, workflow, context)
    return ga.with_inputs(context, inputs)


def _run(tmp_path: Path, step: dict[str, Any]) -> ga.StepRun:
    workflow, job, _ = _workflow_and_step()
    return ga.run_step(
        ga.StepSandbox(tmp_path), workflow, job, step, _context(workflow)
    )


def _installs(run: ga.StepRun) -> list[dict[str, Any]]:
    return [c for c in run.calls_to("bundle") if c["argv"][:1] == ["install"]]


def _frozen_at_runtime(call: dict[str, Any]) -> bool:
    return (
        _truthy(call["env"].get("BUNDLE_FROZEN"))
        or _truthy(call["env"].get("BUNDLE_DEPLOYMENT"))
        or "--frozen" in call["argv"]
        or "--deployment" in call["argv"]
    )


@pytest.mark.integration
@pytestmark_bash
def test_the_cfn_nag_install_runs_frozen_against_the_fetched_lockfile(tmp_path):
    _, _, step = _workflow_and_step()
    run = _run(tmp_path, step)
    assert run.proc.returncode == 0, run.describe()
    (install,) = _installs(run)
    assert _frozen_at_runtime(install), run.describe()
    assert install.get("lockfile_present"), (
        "bundle install ran with no Gemfile.lock beside BUNDLE_GEMFILE\n"
        + run.describe()
    )
    fetched = {c.get("url", "").rsplit("/", 1)[-1] for c in run.calls_to("curl")}
    assert {"Gemfile", "Gemfile.lock"} <= fetched, fetched


@pytest.mark.integration
@pytestmark_bash
def test_without_frozen_mode_the_runtime_check_fails(tmp_path):
    """Negative control: the same step with BUNDLE_FROZEN taken out."""
    _, _, step = _workflow_and_step()
    loose = copy.deepcopy(step)
    (loose.get("env") or {}).pop("BUNDLE_FROZEN", None)
    run = _run(tmp_path, loose)
    (install,) = _installs(run)
    assert not _frozen_at_runtime(install), run.describe()
    assert not install_is_frozen(loose, *_outer_envs())


def _outer_envs() -> tuple:
    workflow, job, _ = _workflow_and_step()
    return (workflow.data.get("env"), job.get("env"))


@pytest.mark.integration
@pytestmark_bash
def test_a_missing_lockfile_stops_the_step_before_bundle_install(tmp_path):
    _, _, step = _workflow_and_step()
    broken = copy.deepcopy(step)
    broken["run"] = "\n".join(
        line
        for line in str(step["run"]).splitlines()
        if not ("curl" in line and "Gemfile.lock" in line)
    )
    assert broken["run"] != step["run"], "the step no longer fetches Gemfile.lock"
    run = _run(tmp_path, broken)
    assert run.proc.returncode != 0, run.describe()
    assert _installs(run) == [], run.describe()
    assert "Gemfile.lock" in run.proc.stdout + run.proc.stderr, run.describe()
