"""Pins where `security-events: write` lives in the scan workflows.

What went wrong
---------------
`ash-repo-scan.yml` granted `security-events: write` to its `ash` job, which calls
`run-ash-security-scan.yml`. That workflow's top-level `permissions:` lists only
contents, checks and pull-requests, and a called workflow can only narrow its
caller's token, so the grant never reached the "Upload ASH SARIF file" step. The
job log's "GITHUB_TOKEN Permissions" block had no SecurityEvents line. Uploads
from a same-repo pull request succeeded anyway, but on workflow_dispatch the
step failed with "Resource not accessible by integration".

Why the permission is not simply added to the scan workflow
-----------------------------------------------------------
GitHub validates every permission a called workflow declares when the run
starts. Measured with a caller that granted only `contents: read`:

* a job-level `security-events: write` on a job with a literal `if: false`
  failed at startup;
* the same on a job whose `if:` was a false boolean input failed at startup;
* a top-level `security-events: write` failed at startup;
* the identical callee without the permission ran.

The error was "The nested job 'upload' is requesting 'security-events: write',
but is only allowed 'security-events: none'." So declaring it anywhere in
`run-ash-security-scan.yml` would break every caller that does not grant it,
including callers passing `collect-sarif-report: false`. The permission lives in
`upload-ash-sarif.yml` instead, which only callers that want uploads call.

What this file pins
-------------------
1. `upload-ash-sarif.yml` declares `security-events: write` and runs upload-sarif.
2. `run-ash-security-scan.yml` declares no `security-events` permission at any
   level. This is the property that keeps non-granting callers starting.
3. This repository's own caller grants `security-events: write` to the sarif job
   only, not to the scan job, and turns off the scan workflow's own upload.
4. The upload workflow reads the artifact name and report path the scan
   workflow writes.

These are static checks over YAML. They cannot prove the upload succeeds at
runtime; the workflow_dispatch run on the pull request that added them is what
showed that.
"""

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
SCAN_WORKFLOW = WORKFLOWS / "run-ash-security-scan.yml"
UPLOAD_WORKFLOW = WORKFLOWS / "upload-ash-sarif.yml"
CALLER_WORKFLOW = WORKFLOWS / "ash-repo-scan.yml"

UPLOAD_SARIF_ACTION = "github/codeql-action/upload-sarif"
UPLOAD_ARTIFACT_ACTION = "actions/upload-artifact"
DOWNLOAD_ARTIFACT_ACTION = "actions/download-artifact"


def _load(path):
    return yaml.safe_load(path.read_text())


def _steps_using(job, action):
    return [
        s
        for s in job.get("steps", [])
        if isinstance(s.get("uses"), str) and s["uses"].startswith(action + "@")
    ]


@pytest.fixture(scope="module")
def scan():
    return _load(SCAN_WORKFLOW)


@pytest.fixture(scope="module")
def upload():
    return _load(UPLOAD_WORKFLOW)


@pytest.fixture(scope="module")
def caller():
    return _load(CALLER_WORKFLOW)


def test_upload_workflow_requests_security_events_write(upload):
    assert upload["permissions"].get("security-events") == "write"
    jobs = upload["jobs"]
    sarif_steps = [
        s for job in jobs.values() for s in _steps_using(job, UPLOAD_SARIF_ACTION)
    ]
    assert len(sarif_steps) == 1, (
        "upload-ash-sarif.yml should run upload-sarif exactly once"
    )


def test_scan_workflow_declares_no_security_events(scan):
    """Any declaration here fails non-granting callers at startup, even on a skipped job."""
    assert "security-events" not in (scan.get("permissions") or {})
    for name, job in scan["jobs"].items():
        perms = job.get("permissions") or {}
        assert not isinstance(perms, str), f"job {name!r} sets a permissions shorthand"
        assert "security-events" not in perms, (
            f"job {name!r} in run-ash-security-scan.yml requests security-events; "
            "callers that do not grant it would fail before any job starts"
        )


def test_caller_grants_security_events_to_sarif_job_only(caller):
    jobs = caller["jobs"]
    ash = jobs["ash"]
    assert "security-events" not in ash.get("permissions", {})
    assert ash["with"]["collect-sarif-report"] is False

    sarif = jobs["sarif"]
    assert sarif["uses"] == "./.github/workflows/upload-ash-sarif.yml"
    assert sarif["needs"] == "ash"
    assert sarif["permissions"].get("security-events") == "write"

    others = [
        n
        for n, j in jobs.items()
        if n != "sarif" and "security-events" in (j.get("permissions") or {})
    ]
    assert others == [], f"security-events granted outside the sarif job: {others}"


def test_upload_reads_what_the_scan_writes(scan, upload):
    (artifact_step,) = _steps_using(scan["jobs"]["ash"], UPLOAD_ARTIFACT_ACTION)
    (download_step,) = [
        s
        for job in upload["jobs"].values()
        for s in _steps_using(job, DOWNLOAD_ARTIFACT_ACTION)
    ]
    assert download_step["with"]["name"] == artifact_step["with"]["name"]
    # The artifact root is the scan's output-dir, so the report sits at the same
    # relative path the scan workflow's own upload step reads.
    assert artifact_step["with"]["path"] == "${{ inputs.output-dir }}"
    (scan_sarif_step,) = _steps_using(scan["jobs"]["ash"], UPLOAD_SARIF_ACTION)
    relative = scan_sarif_step["with"]["sarif_file"].removeprefix(
        "${{ inputs.output-dir }}/"
    )
    (upload_sarif_step,) = [
        s
        for job in upload["jobs"].values()
        for s in _steps_using(job, UPLOAD_SARIF_ACTION)
    ]
    assert (
        upload_sarif_step["with"]["sarif_file"]
        == f"{download_step['with']['path']}/{relative}"
    )
