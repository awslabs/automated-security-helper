# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace policy gate is wired into CI, and its budget fits the job.

scripts/verify_workspace_policy.py existed for some time with no workflow running
it, so a check in it that no correct scan could satisfy was never seen red. These
tests pin the wiring the way the attribution gates' tests pin theirs: the step
exists in the job it belongs to, the scanners it needs are installed before it,
the scratch directory override sits on the step and not on the job (a ``runner.``
reference in job-level ``env`` makes GitHub reject the whole workflow file with no
annotation), and four scan timeouts plus a setup margin fit inside the job's
``timeout-minutes`` so the script's own diagnostics win the race against a job
cancellation.
"""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"
SCRIPT = "scripts/verify_workspace_policy.py"
JOB = "lint"

#: Seconds the job spends before the gate's first scan: checkout, uv, the ASH
#: install, the schema and docs checks, the two publish-surface censuses, and the
#: scanner install the gate itself needs. The attribution gates reserve 600 s in a
#: 1800 s job; this job is half that, with less in front of the gate.
SETUP_MARGIN_SECONDS = 300

#: The gate runs run A, run B, and the two refusal runs: four scans.
SCANS_PER_RUN = 4


def _steps_running(job: dict, needle: str) -> list[dict]:
    return [step for step in job["steps"] if needle in str(step.get("run", ""))]


class TestWorkflowWiring:
    @pytest.fixture
    def workflow(self):
        return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))

    @pytest.fixture
    def job(self, workflow):
        assert JOB in workflow["jobs"], sorted(workflow["jobs"])
        return workflow["jobs"][JOB]

    @pytest.fixture
    def gate_step(self, job):
        steps = _steps_running(job, SCRIPT)
        assert len(steps) == 1, "the gate runs exactly once in the lint job"
        return steps[0]

    def test_only_the_lint_job_runs_the_gate(self, workflow):
        """One step of an existing gate job, never a job of its own: a new job
        has to be added to required-checks' needs and its expected count bumped."""
        running = [
            name
            for name, job in workflow["jobs"].items()
            if _steps_running(job, SCRIPT)
        ]
        assert running == [JOB]

    def test_the_scanners_are_installed_before_the_gate(self, job, gate_step):
        """`uv pip install -e .` brings ASH and not bandit; without bandit the
        gate reads its fixture as broken and exits 3 for the wrong reason."""
        steps = job["steps"]
        gate_index = steps.index(gate_step)
        installs = [
            step
            for step in steps[:gate_index]
            if "dependencies install" in str(step.get("run", ""))
        ]
        assert installs, "no scanner install step precedes the gate"
        argv = shlex.split(str(installs[-1]["run"]))
        tools = [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == "--tool"]
        assert set(tools) == {"bandit", "checkov"}

    def test_the_gate_runs_after_ash_is_installed(self, job, gate_step):
        steps = job["steps"]
        ash_installs = [
            i
            for i, step in enumerate(steps)
            if str(step.get("name", "")) == "Install ASH"
        ]
        assert ash_installs, "the lint job lost its Install ASH step"
        assert ash_installs[0] < steps.index(gate_step)

    def test_the_temp_dir_override_sits_on_the_step(self, job, gate_step):
        """The gate builds its workspace with tempfile.mkdtemp; pointing TMPDIR
        at the runner's scratch space keeps the tree off the checkout."""
        assert "TMPDIR" in (gate_step.get("env") or {})
        job_env = job.get("env") or {}
        assert not any("runner." in str(value) for value in job_env.values())

    def test_the_gate_passes_an_explicit_timeout(self, gate_step):
        """The script's own default (20 minutes per scan) is sized for a job of
        its own; inside lint the step has to say what it allows."""
        argv = shlex.split(str(gate_step["run"]))
        assert "--timeout" in argv

    def test_four_scans_fit_inside_the_job_budget(self, job, gate_step):
        """Otherwise GitHub cancels the job and the operator gets no diagnostics."""
        argv = shlex.split(str(gate_step["run"]))
        timeout = float(argv[argv.index("--timeout") + 1])
        budget = int(job["timeout-minutes"]) * 60
        assert timeout > 0
        assert SCANS_PER_RUN * timeout + SETUP_MARGIN_SECONDS <= budget, (
            f"{SCANS_PER_RUN} scans x {timeout:g}s + {SETUP_MARGIN_SECONDS}s margin "
            f"exceeds the {budget}s job budget"
        )
