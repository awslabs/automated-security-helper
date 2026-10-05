# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Snapshots of the session tools: source delivery, profiles and workspaces.

Covers set_source_git, set_source_zip_chunk, set_source_zip_finalize,
clear_source, list_profiles, select_profile, resolve_ash_workspace and
run_ash_workspace_scan. Each takes its session from the transport header, so
each has an ``invalid_session_id`` snapshot as well as its own.

Nothing leaves the machine and nothing scans. ``git`` is replaced by a recorder
that creates the clone directory, the zip is built in memory with fixed entry
timestamps so its bytes (and the sizes the tools report) are the same on every
run, and the workspace scan's ``execute_workspace`` is replaced by one that
returns a completed result for each planned project, as
tests/unit/cli/mcp/test_workspace_registration.py does.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import io
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.cli import mcp_server
from tests.snapshot.mcp.mcp_snapshot_support import make_ctx, record

_BAD_SESSION = {"mcp-session-id": "../escape"}
_SESSION = {"mcp-session-id": "session-a"}


async def _call(tool: str, *args, headers=None, **kwargs) -> Dict[str, Any]:
    ctx = make_ctx(headers)
    result = await getattr(mcp_server, tool)(ctx, *args, **kwargs)
    return record(tool, result, ctx)


async def _call_without_ctx(tool: str, **kwargs) -> Dict[str, Any]:
    return record(tool, await getattr(mcp_server, tool)(**kwargs))


def _files_under(root: Path) -> list:
    return sorted(
        p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
    )


def _zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, body in (
            ("src/app.py", "print('hello')\n"),
            ("README.md", "# demo\n"),
        ):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 2, 3, 4, 6))
            # ZipInfo records the OS that made the archive, 0 on Windows and 3
            # elsewhere, so the bytes (and the sha256 the mismatch message quotes)
            # differed on windows-latest. Pinned to 3, Unix, which is also the
            # system external_attr's permission bits are meaningful for.
            info.create_system = 3
            info.external_attr = 0o644 << 16
            archive.writestr(info, body)
    return buffer.getvalue()


@pytest.fixture
def fake_git(monkeypatch):
    """Replace ``git`` in source delivery; clone succeeds unless told otherwise."""
    from automated_security_helper.cli.mcp import source_delivery

    behavior = {"returncode": 0, "stderr": ""}
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if behavior["returncode"] == 0 and cmd[:2] == ["git", "clone"]:
            target = Path(cmd[-1])
            target.mkdir(parents=True, exist_ok=True)
            (target / "README.md").write_text("# cloned\n", encoding="utf-8")
        return subprocess.CompletedProcess(
            cmd, behavior["returncode"], "", behavior["stderr"]
        )

    monkeypatch.setattr(source_delivery.subprocess, "run", fake_run)
    behavior["calls"] = calls
    return behavior


@pytest.mark.asyncio
async def test_set_source_git(fake_git, snapshot):
    cloned = await _call(
        "set_source_git", url="https://example.com/org/repo.git", headers=_SESSION
    )
    at_ref = await _call(
        "set_source_git",
        url="https://example.com/org/repo.git",
        ref="v1.2.3",
        headers=_SESSION,
    )
    git_argv = [list(cmd) for cmd in fake_git["calls"]]

    fake_git["returncode"] = 128
    fake_git["stderr"] = (
        "fatal: repository 'https://example.com/org/missing.git/' not found"
    )
    failed = await _call(
        "set_source_git", url="https://example.com/org/missing.git", headers=_SESSION
    )

    refusals = {
        "option_like_url": await _call(
            "set_source_git", url="--upload-pack=touch owned", headers=_SESSION
        ),
        "ext_transport_url": await _call(
            "set_source_git", url="ext::sh -c touch% owned", headers=_SESSION
        ),
        "option_like_ref": await _call(
            "set_source_git",
            url="https://example.com/org/repo.git",
            ref="--output=owned",
            headers=_SESSION,
        ),
        "invalid_session_id": await _call(
            "set_source_git",
            url="https://example.com/org/repo.git",
            headers=_BAD_SESSION,
        ),
    }

    assert cloned == snapshot(name="cloned")
    assert at_ref == snapshot(name="cloned_at_ref")
    assert git_argv == snapshot(name="git_argv")
    assert failed == snapshot(name="clone_failed")
    for name, result in refusals.items():
        assert result == snapshot(name=name)


@pytest.mark.asyncio
async def test_zip_upload_finalize_and_clear(snapshot):
    payload = _zip_bytes()
    half = len(payload) // 2
    chunks = [payload[:half], payload[half:]]
    digest = hashlib.sha256(payload).hexdigest()

    first = await _call(
        "set_source_zip_chunk",
        upload_id="upload-1",
        sequence=0,
        data_b64=base64.b64encode(chunks[0]).decode(),
        last=False,
        headers=_SESSION,
    )
    out_of_order = await _call(
        "set_source_zip_chunk",
        upload_id="upload-1",
        sequence=5,
        data_b64=base64.b64encode(chunks[1]).decode(),
        last=True,
        headers=_SESSION,
    )
    last = await _call(
        "set_source_zip_chunk",
        upload_id="upload-1",
        sequence=1,
        data_b64=base64.b64encode(chunks[1]).decode(),
        last=True,
        headers=_SESSION,
    )
    bad_base64 = await _call(
        "set_source_zip_chunk",
        upload_id="upload-2",
        sequence=0,
        # The text after "invalid base64 payload:" is binascii's own message, so the
        # input is one whose message is the same on Python 3.10 through 3.14;
        # "not base64!" reads "Non-base64 digit found" on 3.10 and "Only base64
        # data is allowed" from 3.12.
        data_b64="abc",
        last=True,
        headers=_SESSION,
    )
    # The mismatch is tried on a second, complete upload of the same bytes,
    # because a failed finalize discards its upload: retrying upload-1 after a
    # mismatch is refused as "no finalized zip" (pinned below as
    # finalize_after_mismatch).
    await _call(
        "set_source_zip_chunk",
        upload_id="upload-3",
        sequence=0,
        data_b64=base64.b64encode(payload).decode(),
        last=True,
        headers=_SESSION,
    )
    wrong_digest = await _call(
        "set_source_zip_finalize",
        upload_id="upload-3",
        expected_sha256="0" * 64,
        headers=_SESSION,
    )
    after_mismatch = await _call(
        "set_source_zip_finalize",
        upload_id="upload-3",
        expected_sha256=digest,
        headers=_SESSION,
    )
    finalized = await _call(
        "set_source_zip_finalize",
        upload_id="upload-1",
        expected_sha256=digest,
        headers=_SESSION,
    )
    extracted = _files_under(Path(finalized["result"]["source_dir"]))
    unknown_upload = await _call(
        "set_source_zip_finalize",
        upload_id="never-uploaded",
        expected_sha256=digest,
        headers=_SESSION,
    )
    cleared = await _call("clear_source", headers=_SESSION)
    cleared_again = await _call("clear_source", headers=_SESSION)
    scan_after_clear = await _call("run_ash_scan", headers=_SESSION)

    invalid = {
        "set_source_zip_chunk": await _call(
            "set_source_zip_chunk",
            upload_id="u",
            sequence=0,
            data_b64="",
            last=True,
            headers=_BAD_SESSION,
        ),
        "set_source_zip_finalize": await _call(
            "set_source_zip_finalize",
            upload_id="u",
            expected_sha256=digest,
            headers=_BAD_SESSION,
        ),
        "clear_source": await _call("clear_source", headers=_BAD_SESSION),
    }

    assert first == snapshot(name="chunk_0")
    assert out_of_order == snapshot(name="chunk_out_of_order")
    assert last == snapshot(name="chunk_1_last")
    assert bad_base64 == snapshot(name="chunk_invalid_base64")
    assert wrong_digest == snapshot(name="finalize_sha256_mismatch")
    assert after_mismatch == snapshot(name="finalize_after_mismatch")
    assert finalized == snapshot(name="finalize")
    assert extracted == snapshot(name="finalize_extracted_files")
    assert unknown_upload == snapshot(name="finalize_unknown_upload")
    assert cleared == snapshot(name="clear_source")
    assert cleared_again == snapshot(name="clear_source_idempotent")
    assert scan_after_clear == snapshot(name="run_ash_scan_after_clear")
    for tool, result in invalid.items():
        assert result == snapshot(name=f"{tool}_invalid_session_id")


def _register_profile(directory: Path, name: str, body: str):
    from automated_security_helper.cli.mcp.profile_registry import (
        register_profiles,
        set_profile_registry,
    )

    path = directory / f"{name}.yaml"
    path.write_text(body, encoding="utf-8")
    set_profile_registry(register_profiles([f"{name}={path}"]))
    return path


@pytest.mark.asyncio
async def test_profiles(allowed, tmp_path, snapshot, snapshot_normalizer):
    from automated_security_helper.cli.mcp.profile_registry import (
        get_profile_registry,
    )

    none_registered = await _call_without_ctx("list_profiles")
    select_with_none = await _call("select_profile", profile_name="strict")

    operator = tmp_path / "operator"
    operator.mkdir()
    _register_profile(
        operator,
        "strict",
        "project_name: strict-profile\n"
        "fail_on_findings: true\n"
        "global_settings:\n"
        "  severity_threshold: LOW\n",
    )
    snapshot_normalizer.add_literal(
        get_profile_registry()["strict"].path_sha256, "PROFILE_PATH_SHA256"
    )

    listed = await _call_without_ctx("list_profiles")
    results = {
        "static": await _call("select_profile", profile_name="strict"),
        "unknown_profile": await _call("select_profile", profile_name="lenient"),
        "patch_and_override_together": await _call(
            "select_profile",
            profile_name="strict",
            patch_ops=[{"op": "replace", "path": "/fail_on_findings", "value": False}],
            override_yaml="project_name: x\n",
        ),
        "patch_denied": await _call(
            "select_profile",
            profile_name="strict",
            patch_ops=[{"op": "replace", "path": "/fail_on_findings", "value": False}],
        ),
        "override": await _call(
            "select_profile",
            profile_name="strict",
            override_yaml="project_name: overridden\nfail_on_findings: false\n",
        ),
        "override_unknown_field": await _call(
            "select_profile",
            profile_name="strict",
            override_yaml="project_name: overridden\nnot_a_setting: 1\n",
        ),
        "override_unparseable": await _call(
            "select_profile", profile_name="strict", override_yaml="key: [unclosed\n"
        ),
        "invalid_session_id": await _call(
            "select_profile", profile_name="strict", headers=_BAD_SESSION
        ),
    }

    assert none_registered == snapshot(name="list_profiles_none_registered")
    assert select_with_none == snapshot(name="select_profile_none_registered")
    assert listed == snapshot(name="list_profiles")
    for name, result in results.items():
        assert result == snapshot(name=f"select_profile_{name}")


def _workspace(root: Path, folders) -> Path:
    path = root / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": entry} for entry in folders]}),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def fake_execute_workspace(monkeypatch):
    """Return a completed result per planned project; scan nothing.

    Returns the semaphore the scan's ``report_progress`` must release on each
    report; see test_workspace_tools.
    """
    import threading

    progress_reports = threading.Semaphore(0)
    from automated_security_helper.cli.mcp import workspace as mcp_workspace
    from automated_security_helper.models.workspace import (
        ProjectRunStatus,
        WorkspaceProjectResult,
        WorkspaceResults,
    )
    from automated_security_helper.workspace import execution as execution_module
    from automated_security_helper.workspace.execution import (
        PROJECTS_DIR_NAME,
        WorkspaceRunResult,
    )

    AGGREGATED_RESULTS_FILENAME = mcp_workspace.AGGREGATED_RESULTS_FILENAME

    def _execute(plan, settings, **kwargs):
        # The progress monitor runs beside this on the event loop and reports what
        # it sees, so its messages depend on timing unless this waits for them:
        # the initial report first, then one "complete" report per project after
        # each project's results file appears, as a real run would write it.
        # One file at a time: the monitor sweeps the projects in plan order, and a
        # sweep that had already passed "api" when both files landed reported "web"
        # first (seen in a full-suite run under xdist).
        assert progress_reports.acquire(timeout=60), "no initial progress report"
        for project in plan.active_projects:
            output = Path(settings.output_dir) / PROJECTS_DIR_NAME / project.key
            (output / AGGREGATED_RESULTS_FILENAME).write_text("{}", encoding="utf-8")
            assert progress_reports.acquire(timeout=60), (
                f"no completion report for {project.key}"
            )
        projects = [
            WorkspaceProjectResult(
                project=project.key,
                relative_path=project.relative_path,
                display_label=project.display_label,
                status=ProjectRunStatus.COMPLETED,
                severity_threshold=project.gate_threshold,
                output_path=f"projects/{project.key}",
                finding_count=0,
                actionable_finding_count=0,
            )
            for project in plan.projects
        ]
        payload = WorkspaceResults(
            workspace_file=plan.workspace_file,
            workspace_root=plan.workspace_root,
            status="completed",
            exit_code=0,
            projects=projects,
            unconvertible_finding_paths=0,
        )
        return WorkspaceRunResult(
            results_path=Path(settings.output_dir) / "ash_workspace_results.json",
            exit_code=0,
            payload=payload,
        )

    monkeypatch.setattr(execution_module, "execute_workspace", _execute)
    monkeypatch.setattr(mcp_workspace, "execute_workspace", _execute)
    # The monitor's real 5 s poll interval only changes how long this waits, not
    # what it reports.
    monkeypatch.setattr(
        mcp_workspace,
        "monitor_workspace_progress",
        functools.partial(mcp_workspace.monitor_workspace_progress, poll_interval=0.01),
    )
    return progress_reports


@pytest.mark.asyncio
async def test_workspace_tools(
    allowed, tmp_path, fake_execute_workspace, snapshot, snapshot_normalizer
):
    root = allowed / "work"
    for project in ("api", "web"):
        (root / project).mkdir(parents=True)
    (root / "web" / ".ash").mkdir()
    (root / "web" / ".ash" / ".ash.yaml").write_text(
        "project_name: web\nglobal_settings:\n  severity_threshold: HIGH\n",
        encoding="utf-8",
    )
    workspace = _workspace(root, ["api", "web", "gone"])
    (root / "gone").mkdir()

    resolved = await _call("resolve_ash_workspace", workspace_file=str(workspace))
    (root / "gone").rmdir()
    missing_project = await _call(
        "resolve_ash_workspace", workspace_file=str(workspace)
    )
    allowed_missing = await _call(
        "resolve_ash_workspace",
        workspace_file=str(workspace),
        allow_missing_projects=True,
    )
    no_file = await _call(
        "resolve_ash_workspace", workspace_file=str(root / "absent.code-workspace")
    )
    unknown_profile = await _call(
        "resolve_ash_workspace", workspace_file=str(workspace), profile="nope"
    )

    ctx = make_ctx()
    ctx.report_progress.side_effect = lambda **_: fake_execute_workspace.release()
    scanned = record(
        "run_ash_workspace_scan",
        await mcp_server.run_ash_workspace_scan(
            ctx, workspace_file=str(workspace), allow_missing_projects=True
        ),
        ctx,
    )
    for scan_id in scanned["result"].get("scan_ids", {}).values():
        snapshot_normalizer.add_literal(scan_id, "PROJECT_SCAN_ID")

    outside = tmp_path / "outside-project"
    outside.mkdir()
    (allowed / "escaping").mkdir()
    escaping = _workspace(allowed / "escaping", [str(outside)])
    refused = await _call("run_ash_workspace_scan", workspace_file=str(escaping))

    invalid = {
        "resolve_ash_workspace": await _call(
            "resolve_ash_workspace", workspace_file=str(workspace), headers=_BAD_SESSION
        ),
        "run_ash_workspace_scan": await _call(
            "run_ash_workspace_scan",
            workspace_file=str(workspace),
            headers=_BAD_SESSION,
        ),
    }

    assert resolved == snapshot(name="resolve")
    assert missing_project == snapshot(name="resolve_missing_project")
    assert allowed_missing == snapshot(name="resolve_allow_missing_projects")
    assert no_file == snapshot(name="resolve_workspace_file_missing")
    assert unknown_profile == snapshot(name="resolve_unknown_profile")
    assert scanned == snapshot(name="scan")
    assert refused == snapshot(name="scan_project_outside_roots")
    for tool, result in invalid.items():
        assert result == snapshot(name=f"{tool}_invalid_session_id")
