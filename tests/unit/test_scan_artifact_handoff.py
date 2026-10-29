# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan's `ash_output` artifact must survive "Re-run failed jobs".

Why this file exists
--------------------
run-ash-security-scan.yml uploads its output directory as the artifact
`ash_output`, and upload-ash-sarif.yml downloads it by that name. Artifact names are
immutable within a run, across attempts, so when "Re-run failed jobs" ran the scan
job again its upload failed on the name the first attempt had already taken, and the
re-run went red at "Collect ASH output artifact" whatever the scan found.

The name is a public interface: callers download `ash_output` themselves, and
upload-ash-sarif.yml's own callers pass nothing. So it stays the default, and:

* the scan replaces the artifact of an earlier attempt instead of failing on it, but
  only on a re-run (`overwrite: ${{ github.run_attempt != '1' }}`). In the first
  attempt a second upload under the same name, from a matrix or from a caller that
  calls the workflow twice, still fails loudly rather than replacing the first
  scan's results without a word;
* an `artifact-name` input, default `ash_output`, lets such a caller give each call
  its own artifact, and upload-ash-sarif.yml takes the same input for its download
  by name;
* the scan hands the artifact's ID out as the `artifact-id` output of the job and of
  the workflow;
* upload-ash-sarif.yml takes an optional `artifact-id` input. Set, it is held to a
  number, because download-artifact reads an empty `artifact-ids` as "every artifact
  of the run", and the download is by that ID; unset, the download is by the name;
* this repository's caller passes the scan job's `artifact-id` to its sarif job.

What is left: a re-run of a matrix whose legs share a name replaces one leg's
artifact with another's, because the re-run cannot tell its own earlier upload from
a sibling's. Giving each leg its own artifact-name avoids it.

These are checks over the YAML plus a run of the ID check's shell. Whether GitHub
keeps the job output of a job that "Re-run failed jobs" did not re-run is GitHub's
behavior, not something a unit test can show.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.utils.github_expressions import evaluate
from tests.utils.workflow_one_line import COMMAND_TEXT, command_lines

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
SCAN_WORKFLOW = WORKFLOWS / "run-ash-security-scan.yml"
UPLOAD_WORKFLOW = WORKFLOWS / "upload-ash-sarif.yml"
CALLER_WORKFLOW = WORKFLOWS / "ash-repo-scan.yml"

UPLOAD_ARTIFACT = "actions/upload-artifact@"
DOWNLOAD_ARTIFACT = "actions/download-artifact@"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _workflow_call(document: dict) -> dict:
    # PyYAML reads the bare key `on` as the boolean True (YAML 1.1).
    triggers = document.get("on", document.get(True))
    return triggers["workflow_call"] or {}


def _steps_using(job: dict, action: str) -> list[dict]:
    return [
        step
        for step in job.get("steps", [])
        if str(step.get("uses", "")).startswith(action)
    ]


def _upload_job() -> dict:
    (job,) = _load(UPLOAD_WORKFLOW)["jobs"].values()
    return job


def _inputs(path: Path) -> dict:
    return _workflow_call(_load(path)).get("inputs") or {}


def test_the_scan_replaces_an_earlier_attempts_artifact_and_hands_out_its_id():
    scan = _load(SCAN_WORKFLOW)
    job = scan["jobs"]["ash"]
    (upload,) = _steps_using(job, UPLOAD_ARTIFACT)

    # The artifact-name input, as the scan job's input check wrote it: every string
    # input is read as the check's output there, never as given.
    assert upload["with"]["name"] == "${{ steps.inputs.outputs.artifact_name }}"
    assert upload.get("id"), "the upload step needs an id for its artifact-id output"
    assert job["outputs"]["artifact-id"] == (
        f"${{{{ steps.{upload['id']}.outputs.artifact-id }}}}"
    )
    output = _workflow_call(scan)["outputs"]["artifact-id"]
    assert output["value"] == "${{ jobs.ash.outputs.artifact-id }}"
    assert output.get("description")


@pytest.mark.parametrize(
    "attempt, replaces", [("1", False), ("2", True), ("3", True), ("10", True)]
)
def test_only_a_re_run_replaces_an_artifact_of_the_same_name(attempt, replaces):
    """In the first attempt a duplicate name must fail, not replace the first scan."""
    (upload,) = _steps_using(_load(SCAN_WORKFLOW)["jobs"]["ash"], UPLOAD_ARTIFACT)
    overwrite = upload["with"].get("overwrite")

    assert overwrite == "${{ github.run_attempt != '1' }}", overwrite
    expression = overwrite.removeprefix("${{").removesuffix("}}").strip()
    assert evaluate(expression, {"github.run_attempt": attempt}, "success") is replaces


@pytest.mark.parametrize("path", [SCAN_WORKFLOW, UPLOAD_WORKFLOW], ids=lambda p: p.name)
def test_both_workflows_take_the_artifact_name_defaulting_to_ash_output(path):
    spec = _inputs(path)["artifact-name"]

    assert spec.get("required", False) is False, "existing callers pass nothing"
    assert spec["type"] == "string"
    assert spec.get("default") == "ash_output", "the default name is public"
    assert "matrix" in spec["description"], spec["description"]


def test_the_upload_workflow_takes_an_optional_artifact_id():
    inputs = _inputs(UPLOAD_WORKFLOW)

    assert set(inputs) == {"artifact-id", "artifact-name"}, inputs
    spec = inputs["artifact-id"]
    assert spec.get("required", False) is False, "existing callers pass nothing"
    assert spec["type"] == "string"
    assert spec.get("default") == ""
    assert "upload-artifact" in spec["description"]


def test_no_step_names_the_artifact_ash_output_outright():
    """Every message and step that names the artifact follows artifact-name."""
    for path in (SCAN_WORKFLOW, UPLOAD_WORKFLOW):
        for job in _load(path)["jobs"].values():
            for step in job.get("steps", []):
                text = str({k: v for k, v in step.items() if k != "name"})
                assert "ash_output artifact" not in text, (path.name, step.get("name"))
                assert step.get("with", {}).get("name") != "ash_output", (
                    path.name,
                    step.get("name"),
                )


def test_it_downloads_by_id_when_given_one_and_by_name_otherwise():
    job = _upload_job()
    downloads = _steps_using(job, DOWNLOAD_ARTIFACT)
    by_id = [step for step in downloads if "artifact-ids" in step["with"]]
    by_name = [step for step in downloads if "name" in step["with"]]

    assert len(downloads) == 2 and len(by_id) == 1 and len(by_name) == 1, downloads
    by_id, by_name = by_id[0], by_name[0]
    assert by_id["with"]["artifact-ids"] == "${{ inputs.artifact-id }}"
    assert "name" not in by_id["with"], "name and artifact-ids are mutually exclusive"
    assert by_id["if"] == "inputs.artifact-id != ''"
    assert by_name["with"]["name"] == "${{ inputs.artifact-name }}"
    assert by_name["if"] == "inputs.artifact-id == ''"
    # A single artifact downloaded by ID is extracted into `path` itself, as one
    # downloaded by name is, so the report sits at the same place either way.
    assert by_id["with"]["path"] == by_name["with"]["path"]


def _id_check_step() -> dict:
    job = _upload_job()
    steps = job["steps"]
    (by_id,) = [
        step
        for step in _steps_using(job, DOWNLOAD_ARTIFACT)
        if "artifact-ids" in step["with"]
    ]
    checks = [
        step
        for step in steps[: steps.index(by_id)]
        if step.get("env", {}).get("ARTIFACT_ID") == "${{ inputs.artifact-id }}"
    ]
    assert len(checks) == 1, "the ID must be checked before the download by ID"
    (check,) = checks
    assert check["if"] == "inputs.artifact-id != ''"
    assert "inputs.artifact-id" not in check["run"], "read the ID from env, not inline"
    return check


def _run_check(value: str) -> subprocess.CompletedProcess:
    bash = shutil.which("bash")
    assert bash, "bash is required to run the step"
    return subprocess.run(
        [bash, "-e", "-o", "pipefail", "-c", _id_check_step()["run"]],
        env={"PATH": os.environ.get("PATH", ""), "ARTIFACT_ID": value},
        capture_output=True,
        text=True,
        check=False,
    )


posix_only = pytest.mark.skipif(
    os.name == "nt",
    reason="runs the step's bash script, which the workflow runs on Linux",
)


@posix_only
@pytest.mark.parametrize("value", ["1", "4231987650"])
def test_the_id_check_accepts_a_number(value):
    result = _run_check(value)
    assert result.returncode == 0, result.stdout + result.stderr


@posix_only
@pytest.mark.parametrize(
    "value", ["", "ash_output", "12 34", "12,34", "12\n34", "-1", "0x1f", " 12"]
)
def test_the_id_check_refuses_anything_else(value):
    result = _run_check(value)
    assert result.returncode != 0, value
    assert "::error::" in result.stdout + result.stderr


@posix_only
@pytest.mark.parametrize(
    "value",
    ["12" + COMMAND_TEXT, "##[warning]x", "12\r::warning::cr", "12\n::warning::lf"],
    ids=["all", "legacy", "cr", "lf"],
)
def test_the_id_check_does_not_print_the_value_it_refuses(value):
    """A caller's input reaches this message, and a line break in it would start a
    command of its own. The refusal names the input, not the value."""
    result = _run_check(value)

    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    (line,) = command_lines(output)
    assert line.startswith("::error::artifact-id is not an artifact ID (a number)."), (
        line
    )
    assert value[2:] not in output


def test_this_repositorys_caller_passes_the_scan_jobs_artifact_id():
    sarif = _load(CALLER_WORKFLOW)["jobs"]["sarif"]

    assert sarif["uses"] == "./.github/workflows/upload-ash-sarif.yml"
    assert sarif["needs"] == "ash"
    assert sarif["with"]["artifact-id"] == "${{ needs.ash.outputs.artifact-id }}"


def test_the_usage_comment_shows_the_artifact_id_handoff():
    header = UPLOAD_WORKFLOW.read_text(encoding="utf-8").split("\npermissions:")[0]
    assert "artifact-id: ${{ needs.ash.outputs.artifact-id }}" in header
