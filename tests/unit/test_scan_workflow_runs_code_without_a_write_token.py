# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The job that runs ASH holds a read-only token; the job that reports runs no code.

Why this file exists
--------------------
run-ash-security-scan.yml declares ``checks: write`` and ``pull-requests: write`` for
the PR comment and the JUnit check run. They used to be steps of the scan job itself,
so the job that runs ASH (and the scanners, and the code ASH imports from the
checkout's config) held a token that could create a check run or a comment under any
name. In ash-repo-scan-pr-head.yml that ASH is the pull request's own, so on a
same-repository pull request the pull request's code held that token, whatever the
workflow's inputs switched off. The token is in the persisted checkout credentials
and in the runner process, so turning the reporting inputs off does not take it away.

The reporting steps now run in a job of their own that downloads the scan's
``ash_output`` artifact and runs nothing from it, and the scan job asks for
``contents: read`` only.

What this asserts
-----------------
1. Every job of the reusable workflow that runs a program from the installed ASH, the
   checkout or a scanner (any ``run:`` step that starts uv, uvx, python, bundle or a
   scanner) holds no write scope.
2. Every job that holds a write scope runs no ``run:`` step other than notices, and
   the steps that post the PR comment, publish the JUnit check and upload SARIF are
   in such a job (locator control).
3. For the informational caller, which reports nothing, the reporting job does not
   run; for the required caller it runs after a scan that passed or failed on
   findings.
4. Every job-level permission stays within what the workflow declares at its top level,
   so no caller has to grant anything new.

What it does not cover
----------------------
What an action used by the reporting job does with the token; those actions are pinned
by commit (.github/scripts/assert-actions-pinned.mjs).
"""

from __future__ import annotations

import re
from typing import Any

from tests.utils import github_actions as ga

SCAN_WORKFLOW = ga.WORKFLOWS_DIR / "run-ash-security-scan.yml"
REPORTING_ACTIONS = (
    "mshick/add-pr-comment@",
    "mikepenz/action-junit-report@",
    "github/codeql-action/upload-sarif@",
)
RUNS_CODE = re.compile(
    r"(?<![\w-])(uvx|uv\s+run|python3?|bundle|gem|ruby|cfn_nag_scan|grype|syft|opengrep)(?![\w-])"
)
RANK = {"none": 0, "read": 1, "write": 2}


def _workflow() -> ga.Workflow:
    return ga.load_workflow(SCAN_WORKFLOW)


def _permissions(workflow: ga.Workflow, job: dict[str, Any]) -> dict[str, str]:
    return ga.job_permissions(workflow, job) or {}


def _code_steps(job: dict[str, Any]) -> list[str]:
    found = []
    for step in job.get("steps") or []:
        script = str(step.get("run") or "")
        lines = [
            line for line in script.splitlines() if not line.strip().startswith("#")
        ]
        if any(RUNS_CODE.search(line) for line in lines):
            found.append(str(step.get("name")))
    return found


def test_a_job_that_runs_code_holds_no_write_scope():
    workflow = _workflow()
    offenders = []
    for job_id, job in workflow.jobs.items():
        code = _code_steps(job)
        writes = sorted(
            k for k, v in _permissions(workflow, job).items() if v == "write"
        )
        if code and writes:
            offenders.append(f"  job {job_id!r} holds {writes} and runs {code}")
    assert not offenders, (
        "a job that runs ASH, a scanner or code from the checkout holds a write "
        "token, which that code can read from the runner:\n" + "\n".join(offenders)
    )


def test_the_reporting_steps_run_in_a_job_that_runs_no_code():
    workflow = _workflow()
    reporting = {}
    for job_id, job in workflow.jobs.items():
        for step in job.get("steps") or []:
            uses = str(step.get("uses") or "")
            if uses.startswith(REPORTING_ACTIONS):
                reporting.setdefault(job_id, []).append(uses.split("@")[0])
    assert {a.split("@")[0] for a in REPORTING_ACTIONS} == {
        u for used in reporting.values() for u in used
    }, f"the reporting steps were not all found: {reporting}"
    for job_id in reporting:
        job = workflow.jobs[job_id]
        assert not _code_steps(job), (
            f"job {job_id!r} reports to the pull request and also runs "
            f"{_code_steps(job)}"
        )


UPLOADED = {"artifact-id": "4242"}


def _job_runs(
    job: dict[str, Any],
    inputs: dict[str, Any],
    result: str,
    outputs: dict[str, str] | None = None,
) -> bool:
    """Whether `job` starts after its needs ended `result` with `outputs` (default: uploaded)."""
    context = ga.base_context(event_name="pull_request")
    context["needs"] = {
        need: {"result": result, "outputs": UPLOADED if outputs is None else outputs}
        for need in _needs(job)
    }
    return ga.job_runs(job, ga.with_inputs(context, inputs))


def _needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def _reporting_jobs(workflow: ga.Workflow) -> list[dict[str, Any]]:
    return [
        job
        for job in workflow.jobs.values()
        if any(
            str(step.get("uses") or "").startswith(REPORTING_ACTIONS)
            for step in job.get("steps") or []
        )
    ]


def test_the_reporting_job_runs_only_when_something_is_reported():
    workflow = _workflow()
    jobs = _reporting_jobs(workflow)
    assert jobs, "no job reports to the pull request"
    quiet = ga.call_inputs(
        {
            "with": {
                "post-pr-comment": False,
                "collect-junit-xml-report": False,
                "collect-sarif-report": False,
            }
        },
        workflow,
        ga.base_context(),
    )
    loud = ga.call_inputs(
        {"with": {"collect-sarif-report": False}}, workflow, ga.base_context()
    )
    for job in jobs:
        assert not _job_runs(job, quiet, "success"), (
            "the reporting job runs for a caller that reports nothing"
        )
        for result in ("success", "failure"):
            assert _job_runs(job, loud, result), (
                f"the reporting job does not run after a scan job that ended {result}"
            )
        assert not _job_runs(job, loud, "skipped")


def test_job_level_permissions_ask_for_nothing_the_workflow_does_not_declare():
    workflow = _workflow()
    declared = ga.normalize_permissions(workflow.data.get("permissions"))
    for job_id, job in workflow.jobs.items():
        if "permissions" not in job:
            continue
        for scope, level in ga.normalize_permissions(job["permissions"]).items():
            assert RANK[level] <= RANK[declared.get(scope, "none")], (
                f"job {job_id!r} asks for {scope}: {level}, which the workflow does "
                "not declare, so every caller would have to grant it"
            )


class TestNothingIsReportedWhenTheScanUploadedNothing:
    """A scan that fails before writing its reports gives one red check, not two.

    A refused config-ref, for one, fails the scan job before ASH runs, so it uploads
    no ash_output artifact. The reporting job, and the SARIF job of a caller that
    uploads on its own, would then fail at the download and show a second red check
    that says nothing about the first. The scan job exposes the upload's artifact id,
    the reusable workflow passes it on, and both jobs start only when it is set.
    """

    def _loud(self) -> dict[str, Any]:
        workflow = _workflow()
        return ga.call_inputs({"with": {}}, workflow, ga.base_context())

    def test_the_reporting_job_skips_a_scan_that_uploaded_nothing(self):
        jobs = _reporting_jobs(_workflow())
        assert jobs, "no job reports to the pull request"
        for job in jobs:
            for result in ("success", "failure"):
                assert not _job_runs(job, self._loud(), result, outputs={}), (
                    f"the reporting job starts after a scan that ended {result} "
                    "without uploading ash_output"
                )
                assert _job_runs(job, self._loud(), result), result

    def test_the_artifact_id_is_the_upload_steps_and_reaches_the_caller(self):
        workflow = _workflow()
        scan = workflow.jobs["ash"]
        (upload,) = [
            step
            for step in scan.get("steps") or []
            if str(step.get("uses") or "").startswith("actions/upload-artifact@")
        ]
        assert upload.get("id"), "the ash_output upload step has no id to read it by"
        expected = f"steps.{upload['id']}.outputs.artifact-id"
        job_output = str((scan.get("outputs") or {}).get("artifact-id") or "")
        assert expected in job_output, (
            f"job ash's artifact-id output is {job_output!r}, not {expected}"
        )
        declared = ((workflow.on.get("workflow_call") or {}).get("outputs")) or {}
        value = str((declared.get("artifact-id") or {}).get("value") or "")
        assert "jobs.ash.outputs.artifact-id" in value, (
            "run-ash-security-scan.yml does not pass artifact-id on to its callers"
        )

    def test_the_callers_sarif_job_skips_a_scan_that_uploaded_nothing(self):
        caller = ga.load_workflow(ga.WORKFLOWS_DIR / "ash-repo-scan.yml")
        sarif = caller.jobs["sarif"]
        for result in ("success", "failure"):
            assert not _job_runs(sarif, {}, result, outputs={}), (
                f"ash-repo-scan.yml's sarif job starts after a scan that ended {result} "
                "without uploading ash_output"
            )
            assert _job_runs(sarif, {}, result), result
        # A skipped scan job has no outputs, so it uploaded nothing.
        assert not _job_runs(sarif, {}, "skipped", outputs={})
        # Nor after the run was cancelled, even with an artifact uploaded.
        context = ga.base_context(event_name="pull_request")
        context["needs"] = {"ash": {"result": "failure", "outputs": UPLOADED}}
        assert not ga.job_runs(sarif, {**context, "__status__": "cancelled"})
