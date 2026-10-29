# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan holds its session's delivered tree for its whole run.

A workspace scan of a session that has delivered a tree reads that tree for as
long as its projects take to scan. It claims the session the way a single scan
does (``MCPSession.try_claim_scan``), from before it resolves the workspace until
nothing of the scan reads the tree any more, so ``clear_source`` and
``set_source_git`` are refused meanwhile with ``error_type: source_delivery_busy``,
and the session's removal waits for the scan. A workspace scan is refused the
same way while one of those calls is changing the tree.

The scan runs on a worker thread, which a cancelled call does not stop. So once
the worker has the run, the worker releases the claim when it returns, and a
worker that had not started when the call was cancelled never runs. The worker
also holds the session's ``ScanPresence``, for the TTL sweep of other servers,
and the ``ASH_OFFLINE`` setting of an offline scan.

A session that has delivered nothing (no tree and no profile config in its
sandbox) has nothing of its own for the scan to hold: a workspace scan of a
directory the operator granted takes no claim and creates nothing under the
workspace root.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import threading
import zipfile
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.cli.mcp.sessions import (
    end_session,
    reset_default_registry_for_tests,
)

pytestmark = pytest.mark.unit

SESSION = "workspace-session"
WORKSPACE_FILE = "dev.code-workspace"


@pytest.fixture(autouse=True)
def _environment(tmp_path, monkeypatch):
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    for name in (
        "ASH_MCP_ALLOWED_ROOTS",
        "ASH_MCP_ALLOWED_CONFIG_ROOTS",
        "ASH_CONFIG",
        "ASH_OFFLINE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.invalid")
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    monkeypatch.setattr(
        sd, "_run_git", lambda *a, **k: pytest.fail("git ran during the scan")
    )
    reset_default_registry_for_tests()
    profile_registry.clear_all_session_state()
    yield
    reset_default_registry_for_tests()
    profile_registry.clear_all_session_state()


def _zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            WORKSPACE_FILE,
            json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}),
        )
        archive.writestr("api/app.py", "print('api')\n")
        archive.writestr("web/app.py", "print('web')\n")
    return buffer.getvalue()


@pytest.fixture
def delivered() -> Path:
    data = _zip()
    sd.set_source_zip_chunk(
        "tree", 0, base64.b64encode(data).decode(), True, session_id=SESSION
    )
    return sd.set_source_zip_finalize(
        "tree", hashlib.sha256(data).hexdigest(), session_id=SESSION
    )


@pytest.fixture
def blocking_execution(monkeypatch) -> Dict[str, Any]:
    """Replace ``execute_workspace`` with one that waits until released."""
    from automated_security_helper.models.workspace import (
        ProjectRunStatus,
        WorkspaceProjectResult,
        WorkspaceResults,
    )
    from automated_security_helper.workspace.execution import WorkspaceRunResult

    state: Dict[str, Any] = {
        "started": threading.Event(),
        "release": threading.Event(),
    }

    def _execute(plan, settings, **kwargs):
        import os

        state["offline_during"] = os.environ.get("ASH_OFFLINE")
        state["started"].set()
        state["release"].wait(30)
        state["tree_present"] = all(
            (Path(project.path) / "app.py").is_file() for project in plan.projects
        )
        payload = WorkspaceResults(
            workspace_file=plan.workspace_file,
            workspace_root=plan.workspace_root,
            status="completed",
            exit_code=0,
            projects=[
                WorkspaceProjectResult(
                    project=project.key,
                    relative_path=project.relative_path,
                    display_label=project.display_label,
                    status=ProjectRunStatus.COMPLETED,
                    severity_threshold=project.gate_threshold,
                    output_path=f"projects/{project.key}",
                )
                for project in plan.projects
            ],
            unconvertible_finding_paths=0,
        )
        return WorkspaceRunResult(
            results_path=Path(settings.output_dir) / "ash_workspace_results.json",
            exit_code=0,
            payload=payload,
        )

    monkeypatch.setattr(workspace_module, "execute_workspace", _execute)
    return state


def _scan(delivered: Path):
    return workspace_module.mcp_scan_workspace(
        workspace_file=str(delivered / WORKSPACE_FILE), session_id=SESSION
    )


def _while_the_scan_runs(delivered: Path, state: Dict[str, Any], during):
    async def main():
        scan = asyncio.create_task(_scan(delivered))
        started = await asyncio.to_thread(state["started"].wait, 30)
        assert started, "the workspace scan never reached execution"
        try:
            observed = during()
        finally:
            state["release"].set()
        return await scan, observed

    return asyncio.run(main())


def test_clear_source_is_refused_during_a_workspace_scan(
    delivered, blocking_execution
) -> None:
    response, refused = _while_the_scan_runs(
        delivered,
        blocking_execution,
        lambda: mcp_tools.mcp_clear_source(session_id=SESSION),
    )

    assert refused.get("error_type") == "source_delivery_busy", refused
    assert blocking_execution["tree_present"] is True, "the scan read a removed tree"
    assert response.get("success") is True, response
    assert mcp_tools.mcp_clear_source(session_id=SESSION).get("success") is True


def test_a_clone_is_refused_during_a_workspace_scan(
    delivered, blocking_execution
) -> None:
    _response, refused = _while_the_scan_runs(
        delivered,
        blocking_execution,
        lambda: mcp_tools.mcp_set_source_git(
            url="https://git.example.invalid/team/repo.git", session_id=SESSION
        ),
    )

    assert refused.get("error_type") == "source_delivery_busy", refused
    assert blocking_execution["tree_present"] is True


def test_a_session_ending_during_a_workspace_scan_waits_for_it(
    delivered, blocking_execution
) -> None:
    _response, ended_now = _while_the_scan_runs(
        delivered, blocking_execution, lambda: end_session(SESSION)
    )

    assert ended_now is False
    assert blocking_execution["tree_present"] is True, "the scan read a removed tree"
    assert not delivered.exists(), "the tree outlived the scan of an ended session"


def test_a_workspace_scan_is_refused_while_the_tree_is_changing(
    delivered, blocking_execution
) -> None:
    async def main():
        with sd._no_scan_running(SESSION):
            return await _scan(delivered)

    response = asyncio.run(main())

    assert response.get("success") is False, response
    assert response.get("error_type") == "source_delivery_busy", response
    assert not blocking_execution["started"].is_set(), "the workspace scan ran"


def test_a_cancelled_workspace_scan_holds_the_tree_until_its_worker_returns(
    delivered, blocking_execution
) -> None:
    observed: Dict[str, Any] = {}

    async def main():
        scan = asyncio.create_task(_scan(delivered))
        started = await asyncio.to_thread(blocking_execution["started"].wait, 30)
        assert started, "the workspace scan never reached execution"
        scan.cancel()
        with pytest.raises(asyncio.CancelledError):
            await scan
        # The call is gone; its worker is still reading the tree.
        try:
            observed["clear"] = mcp_tools.mcp_clear_source(session_id=SESSION)
            observed["ended_now"] = end_session(SESSION)
        finally:
            blocking_execution["release"].set()

    # asyncio.run waits for the default executor's threads, so the worker has
    # returned when it does.
    asyncio.run(main())

    assert observed["clear"].get("error_type") == "source_delivery_busy", (
        "the tree was released while the cancelled scan's worker still read it"
    )
    assert observed["ended_now"] is False
    assert blocking_execution["tree_present"] is True, "the scan read a removed tree"
    assert not delivered.exists(), "the ended session outlived its scan's worker"


class _ThreadAlreadyStarted(workspace_module.SettleHandoff):
    """A handoff whose thread had passed ``thread_starts`` before the call gave up."""

    def thread_starts(self) -> bool:
        return True

    def task_abandons(self) -> bool:
        return False


def _park_the_scans_worker(monkeypatch, handed: Dict[str, Any]) -> None:
    """Hold the scan's worker in the executor's queue, unstarted.

    ``workspace_module.asyncio`` is the ``asyncio`` module itself, so replacing its
    ``to_thread`` replaces it for every caller. The scan hops to a thread twice:
    its selection pre-check first, then the worker that runs the scan. The
    pre-check goes through to the real ``to_thread``; only the worker is held.
    """
    real_to_thread = asyncio.to_thread

    async def to_thread(func, /, *args, **kwargs):
        if getattr(func, "__qualname__", "") != "_execute.<locals>._run":
            return await real_to_thread(func, *args, **kwargs)
        handed["run"] = lambda: func(*args, **kwargs)
        handed["queued"].set()
        await asyncio.Event().wait()

    monkeypatch.setattr(workspace_module.asyncio, "to_thread", to_thread)


async def _until_the_worker_is_parked(
    scan: "asyncio.Task[Any]", handed: Dict[str, Any], timeout: float = 30
) -> None:
    """Wait until the scan holds its worker back; fail if the scan ends first.

    A scan that returns before it reaches its worker (an error response, say)
    never holds one back, so waiting on ``handed["queued"]`` alone would wait for
    ever instead of failing the cell.
    """
    queued = asyncio.ensure_future(handed["queued"].wait())
    try:
        await asyncio.wait(
            {scan, queued}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        queued.cancel()
    if handed["queued"].is_set():
        return
    if not scan.done():
        state = f"was still running after {timeout} s"
    elif scan.cancelled():
        state = "was cancelled"
    elif scan.exception() is not None:
        state = f"raised {scan.exception()!r}"
    else:
        state = f"returned {scan.result()!r}"
    raise AssertionError(f"the workspace scan never reached its worker: it {state}")


def test_a_worker_that_had_not_started_when_the_call_was_cancelled_never_runs(
    delivered, blocking_execution, monkeypatch
) -> None:
    """The executor had the worker queued and reaches it after the call has gone.

    The call, cancelled first, settles the scan itself and gives up the claim, so
    the worker finds that it was abandoned and returns without running.
    """
    handed: Dict[str, Any] = {}
    _park_the_scans_worker(monkeypatch, handed)

    async def main():
        handed["queued"] = asyncio.Event()
        scan = asyncio.create_task(_scan(delivered))
        await _until_the_worker_is_parked(scan, handed)
        scan.cancel()
        with pytest.raises(asyncio.CancelledError):
            await scan

    asyncio.run(main())
    released = mcp_tools.mcp_clear_source(session_id=SESSION)
    ran = handed["run"]()

    assert ran is None, "the worker the call had left behind ran the scan"
    assert released.get("success") is True, released
    assert not blocking_execution["started"].is_set(), "the abandoned scan ran"


def test_a_worker_that_started_after_the_call_left_never_runs(
    delivered, blocking_execution, monkeypatch
) -> None:
    """The thread began, and the call was cancelled before the worker took the claim.

    The call gave the claim up, so the worker cannot take it over and raises
    instead of running the scan. Only a thread that had already passed its start
    check reaches that point; one the call abandoned first returns before it
    (the cell above).
    """
    handed: Dict[str, Any] = {}
    _park_the_scans_worker(monkeypatch, handed)
    monkeypatch.setattr(workspace_module, "SettleHandoff", _ThreadAlreadyStarted)
    # The thread settles this scan, on a loop that is closed by then, so its
    # future never completes: keep it out of the module's record of running scans.
    monkeypatch.setattr(workspace_module, "_RUNNING", {})

    async def main():
        handed["queued"] = asyncio.Event()
        scan = asyncio.create_task(_scan(delivered))
        await _until_the_worker_is_parked(scan, handed)
        scan.cancel()
        with pytest.raises(asyncio.CancelledError):
            await scan

    asyncio.run(main())
    released = mcp_tools.mcp_clear_source(session_id=SESSION)
    with pytest.raises(RuntimeError, match="cancelled before it started"):
        handed["run"]()

    assert released.get("success") is True, released
    assert not blocking_execution["started"].is_set(), "the abandoned scan ran"


def test_a_workspace_scan_holds_its_sessions_presence(
    delivered, blocking_execution
) -> None:
    from automated_security_helper.cli.mcp.sessions import scan_presence_held

    _response, held = _while_the_scan_runs(
        delivered, blocking_execution, lambda: scan_presence_held(SESSION)
    )

    assert held is True
    assert scan_presence_held(SESSION) is False


def test_an_offline_setting_lasts_as_long_as_the_worker(
    delivered, blocking_execution
) -> None:
    import os

    observed: Dict[str, Any] = {}

    async def main():
        scan = asyncio.create_task(
            workspace_module.mcp_scan_workspace(
                workspace_file=str(delivered / WORKSPACE_FILE),
                session_id=SESSION,
                offline=True,
            )
        )
        await asyncio.to_thread(blocking_execution["started"].wait, 30)
        scan.cancel()
        with pytest.raises(asyncio.CancelledError):
            await scan
        observed["after_cancel"] = os.environ.get("ASH_OFFLINE")
        blocking_execution["release"].set()

    asyncio.run(main())

    assert blocking_execution["offline_during"] == "YES"
    assert observed["after_cancel"] == "YES", "the scan went back online mid-run"
    assert os.environ.get("ASH_OFFLINE") is None


def test_a_session_that_delivered_nothing_takes_no_claim(
    tmp_path, blocking_execution, monkeypatch
) -> None:
    granted = tmp_path / "granted"
    for name in ("api", "web"):
        (granted / name).mkdir(parents=True)
        (granted / name / "app.py").write_text("print('x')\n", encoding="utf-8")
    (granted / WORKSPACE_FILE).write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(granted))
    root = tmp_path / "ws"
    data = _zip()
    observed: Dict[str, Any] = {}

    def deliver_meanwhile():
        observed["root_before"] = (
            sorted(p.name for p in root.iterdir()) if root.exists() else []
        )
        sd.set_source_zip_chunk(
            "late", 0, base64.b64encode(data).decode(), True, session_id=SESSION
        )
        return sd.set_source_zip_finalize(
            "late", hashlib.sha256(data).hexdigest(), session_id=SESSION
        )

    async def main():
        scan = asyncio.create_task(
            workspace_module.mcp_scan_workspace(
                workspace_file=str(granted / WORKSPACE_FILE), session_id=SESSION
            )
        )
        await asyncio.to_thread(blocking_execution["started"].wait, 30)
        try:
            observed["delivered"] = deliver_meanwhile()
        finally:
            blocking_execution["release"].set()
        return await scan

    response = asyncio.run(main())

    assert response.get("success") is True, response
    assert SESSION not in observed["root_before"], (
        "the scan created a session directory"
    )
    assert (observed["delivered"] / WORKSPACE_FILE).is_file()
