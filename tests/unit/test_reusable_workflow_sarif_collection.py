# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`collect-sarif-report: true`, the default, must not fail a scan on any event.

Why this file exists
--------------------
run-ash-security-scan.yml cannot hold `security-events: write` (its own comments and
upload-ash-sarif.yml say why). Code scanning needs that permission for an upload
except on one event: "Uploading code scanning results for a branch usually requires
the `security-events: write` scope. However, code scanning always allows the
uploading of results when the `pull_request` event triggers the action run."
(https://docs.github.com/en/code-security/code-scanning/troubleshooting-code-scanning/resource-not-accessible-by-integration)
On push and on workflow_dispatch the upload would fail with "Resource not
accessible by integration" and take the job down with it, so a caller that left
the default on would get a red job on every push; the step's condition keeps it
to the events that can upload.

What is asserted
----------------
Both steps are in the `report` job, which runs after the scan job on a runner of its
own; the tests read that job's steps. The notice loads the one_line helper, which
write_helper writes from the scan job's definer, the one in the file. That a job
which loads the helper writes it itself is asserted in
test_workflow_commands_print_no_unchecked_value.py.

The upload step's condition is evaluated for each event the workflow can be called
on, with the input on and off and with the scan passing and failing: it uploads on
every pull_request event, from a fork as well as from the repository itself, and
wherever the input is on but the event is not a pull request, a notice step runs
instead. Its shell is run for each event: merge_group gets its own reason, and every
other event is pointed at upload-ash-sarif.yml. It prints the artifact name, which is
the caller's input, and the event name through one_line, so neither can add a
workflow command of its own.

The conditions are evaluated here, not by GitHub, with a small evaluator for the
operators these steps use; it is checked first against expressions whose values are
known, including one that only the documented precedence gets right.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.utils.github_expressions import evaluate
from tests.utils.workflow_one_line import (
    COMMAND_TEXT,
    COMMAND_TEXT_SHOWN,
    command_lines,
    write_helper,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"


def _jobs() -> dict[str, dict]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def _report_steps() -> list[dict]:
    """The steps of the job that holds the upload and the notice.

    They are in the `report` job, not the scan job (`ash`): the scan job runs ASH and
    its scanners and no longer holds a token that can write checks or comments, so the
    reporting job, which runs after it on a runner of its own, does the reporting.
    """
    return _jobs()["report"]["steps"]


def _steps() -> dict[str, dict]:
    return {step["name"]: step for step in _report_steps() if "name" in step}


def test_the_evaluator_reads_known_expressions():
    context = {"inputs.on": True, "github.event_name": "push"}
    assert evaluate("inputs.on && github.event_name == 'push'", context, "success")
    assert evaluate("github.event_name == 'PUSH'", context, "success")
    assert not evaluate("!inputs.on || github.event_name != 'push'", context, "success")
    assert evaluate("(success() || failure())", context, "failure")
    assert not evaluate("success()", context, "failure")
    # && binds tighter than ||; read left to right this would be false.
    assert evaluate("true || false && false", context, "success")
    with pytest.raises(AssertionError):
        evaluate("contains(github.event_name, 'p')", context, "success")


EVENTS = {
    "same-repo pull request": {
        "github.event_name": "pull_request",
        "github.event.pull_request.head.repo.full_name": "org/repo",
    },
    "fork pull request": {
        "github.event_name": "pull_request",
        "github.event.pull_request.head.repo.full_name": "fork/repo",
    },
    "push": {"github.event_name": "push"},
    "workflow_dispatch": {"github.event_name": "workflow_dispatch"},
    "merge_group": {"github.event_name": "merge_group"},
    "schedule": {"github.event_name": "schedule"},
}


def _context(event: str, collect: bool) -> dict:
    return {
        "github.repository": "org/repo",
        "inputs.collect-sarif-report": collect,
        **EVENTS[event],
    }


@pytest.mark.parametrize("event", sorted(EVENTS))
@pytest.mark.parametrize("collect", [True, False])
@pytest.mark.parametrize("status", ["success", "failure"])
def test_the_upload_runs_only_where_it_can_succeed(event, collect, status):
    condition = _steps()["Upload ASH SARIF file"]["if"]

    uploads = evaluate(condition, _context(event, collect), status)

    assert uploads == (collect and event.endswith("pull request")), condition


@pytest.mark.parametrize("event", sorted(EVENTS))
@pytest.mark.parametrize("collect", [True, False])
@pytest.mark.parametrize("status", ["success", "failure"])
def test_a_notice_runs_wherever_the_upload_is_skipped(event, collect, status):
    steps = _steps()
    notice = steps.get("Note that the SARIF report was not uploaded")
    assert notice, "no step says why the SARIF report was not uploaded"

    notes = evaluate(notice["if"], _context(event, collect), status)

    assert notes == (collect and not event.endswith("pull request")), notice["if"]


def _notice_for(
    runner_temp: Path, event_name: str, artifact_name: str = "ash_output"
) -> str:
    """The step's output, after the job's definer has written the one_line helper."""
    step = _steps()["Note that the SARIF report was not uploaded"]
    write_helper(_jobs()["ash"]["steps"], runner_temp)
    values = {
        "${{ github.event_name }}": event_name,
        "${{ inputs.artifact-name }}": artifact_name,
    }
    result = subprocess.run(
        [shutil.which("bash") or "bash", "-e", "-o", "pipefail", "-c", step["run"]],
        env={
            "PATH": os.environ.get("PATH", ""),
            "RUNNER_TEMP": str(runner_temp),
            **{name: values[value] for name, value in step.get("env", {}).items()},
        },
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    # Bytes, so a carriage return in the output stays one.
    return result.stdout.decode("utf-8")


posix_only = pytest.mark.skipif(
    os.name == "nt",
    reason="runs the step's bash script, which the workflow runs on Linux",
)


@posix_only
@pytest.mark.parametrize("event_name", ["push", "workflow_dispatch", "schedule"])
def test_the_notice_names_the_workflow_that_can_upload(tmp_path, event_name):
    notice = _notice_for(tmp_path, event_name)
    assert notice.startswith("::notice::"), notice
    assert event_name in notice and "security-events: write" in notice, notice
    assert "upload-ash-sarif.yml" in notice, notice
    assert "the ash_output artifact" in notice, notice


@posix_only
def test_a_merge_group_notice_gives_the_merge_queues_own_reason(tmp_path):
    notice = _notice_for(tmp_path, "merge_group")
    assert notice.startswith("::notice::"), notice
    assert "merge_group" in notice and "merge queue" in notice, notice
    assert "the ash_output artifact" in notice, notice
    assert notice != _notice_for(tmp_path, "push")


@posix_only
@pytest.mark.parametrize(
    "event_name, artifact_name",
    [
        ("merge_group", COMMAND_TEXT),
        ("push", COMMAND_TEXT),
        (COMMAND_TEXT, "ash_output"),
    ],
    ids=["artifact name on merge_group", "artifact name on push", "event name"],
)
def test_the_notice_prints_its_values_on_its_own_line(
    tmp_path, event_name, artifact_name
):
    """The artifact name is the caller's input; a line break in it, or `::`, would
    start a workflow command of its own."""
    notice = _notice_for(tmp_path, event_name, artifact_name)

    (line,) = command_lines(notice)
    assert line.startswith("::notice::The SARIF report was not uploaded"), line
    assert line.count(COMMAND_TEXT_SHOWN) == 1, line
