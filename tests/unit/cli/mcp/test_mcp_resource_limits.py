# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP server enforces ``max_concurrent_scans`` and ``scan_timeout_seconds``.

Why this file exists
--------------------
``AshConfig`` declares an ``mcp-resource-management`` section of sixteen limits,
and the MCP guide documents them. A server enforces these two, so it does not
accept any number of concurrent scans or let each one run for as long as it takes,
whatever the operator configured.

The other fourteen are marked as not enforced in the
model and the docs. Both are server limits, so they are read from the operator's
config (``ASH_CONFIG``, else the defaults), never from the config of the scan,
which can be the scanned repository's own or a client's: a limit the party being
limited can raise is not a limit.

The timeout stops the scan through the same cancel path as ``cancel_scan``
(core/cancellation.py), so it is measured the same way: a stand-in scanner whose
child runs for longer than the timeout, started through ASH's own subprocess
choke point.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from tests.utils.processes import process_running
from tests.utils.tasks import drain as _drain

_LAUNCHER = "automated_security_helper.interactions.run_ash_scan.run_ash_scan"
CHILD_SECONDS = 10.0

#: The stand-in scanner's child: records its pid, then works for CHILD_SECONDS.
_CHILD = (
    "import os, pathlib, sys, time; "
    "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
    f"time.sleep({CHILD_SECONDS})"
)


@pytest.fixture(autouse=True)
def isolated_mcp_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp.sessions import (
        reset_default_registry_for_tests,
    )
    from automated_security_helper.core.resource_management import scan_registry

    monkeypatch.setattr(scan_registry, "_scan_registry", ScanRegistry())
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()
    reset_default_registry_for_tests()
    for name in ("ASH_MCP_ALLOWED_CONFIG_ROOTS", "ASH_MCP_TRANSPORT", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "allowed"))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    (tmp_path / "allowed").mkdir()
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    yield
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()
    reset_default_registry_for_tests()


def _operator_config(tmp_path: Path, monkeypatch, **limits: Any) -> None:
    """ASH_CONFIG naming an operator file, outside every scanned tree."""
    lines = ["project_name: operator", "mcp-resource-management:"]
    lines += [f"  {key}: {value}" for key, value in limits.items()]
    path = tmp_path / "operator" / "ash.yaml"
    path.parent.mkdir()
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(path))


def _project(tmp_path: Path, name: str, own_limit: int | None = None) -> Path:
    project = tmp_path / "allowed" / name
    project.mkdir(parents=True)
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    if own_limit is not None:
        (project / ".ash").mkdir()
        (project / ".ash" / ".ash.yaml").write_text(
            "project_name: repo\n"
            "mcp-resource-management:\n"
            f"  max_concurrent_scans: {own_limit}\n",
            encoding="utf-8",
        )
    return project


def _ctx(session_id: Optional[str] = None) -> MagicMock:
    """A tool call's context, in the default session or in *session_id*."""
    ctx = MagicMock(spec=Context)
    ctx.headers = {} if session_id is None else {"mcp-session-id": session_id}
    return ctx


@pytest.fixture
def held(monkeypatch) -> threading.Event:
    """A launcher whose scans stay running until the returned event is set."""
    release = threading.Event()

    def scan(**kwargs: Any):
        release.wait(30)
        return None

    monkeypatch.setattr(_LAUNCHER, scan)
    return release


@pytest.mark.asyncio
class TestMaxConcurrentScans:
    async def test_a_scan_over_the_limit_is_refused(self, tmp_path, monkeypatch, held):
        _operator_config(tmp_path, monkeypatch, max_concurrent_scans=1)
        ctx = _ctx()
        try:
            first = await mcp_server.run_ash_scan(
                ctx, source_dir=str(_project(tmp_path, "one"))
            )
            second = await mcp_server.run_ash_scan(
                ctx, source_dir=str(_project(tmp_path, "two"))
            )
        finally:
            held.set()
            await _drain()

        assert first["success"] is True, first
        assert second["success"] is False, (
            f"a second concurrent scan started under max_concurrent_scans=1: {second}"
        )
        assert "max_concurrent_scans" in second["error"], second

    async def test_a_repository_config_cannot_raise_the_limit(
        self, tmp_path, monkeypatch, held
    ):
        _operator_config(tmp_path, monkeypatch, max_concurrent_scans=1)
        ctx = _ctx()
        try:
            first = await mcp_server.run_ash_scan(
                ctx, source_dir=str(_project(tmp_path, "one"))
            )
            second = await mcp_server.run_ash_scan(
                ctx, source_dir=str(_project(tmp_path, "two", own_limit=10))
            )
        finally:
            held.set()
            await _drain()

        assert first["success"] is True, first
        assert second["success"] is False, second

    async def test_a_finished_scan_frees_its_slot(self, tmp_path, monkeypatch, held):
        _operator_config(tmp_path, monkeypatch, max_concurrent_scans=1)
        held.set()
        ctx = _ctx()
        first = await mcp_server.run_ash_scan(
            ctx, source_dir=str(_project(tmp_path, "one"))
        )
        await _drain()
        second = await mcp_server.run_ash_scan(
            ctx, source_dir=str(_project(tmp_path, "two"))
        )
        await _drain()

        assert first["success"] is True, first
        assert second["success"] is True, second


@pytest.mark.asyncio
async def test_a_scan_past_scan_timeout_seconds_is_stopped_and_failed(
    tmp_path, monkeypatch
):
    """The timeout is set to 1 s, below the model's 60 s floor, to keep this fast.

    ``model_copy(update=...)`` skips validation, so the limits object the server
    reads carries a value no config file can; everything that reads it is real.
    """
    from automated_security_helper.config import default_config
    from automated_security_helper.config.ash_config import AshConfig

    base = AshConfig()
    limits = base.mcp_resource_management.model_copy(update={"scan_timeout_seconds": 1})
    operator = base.model_copy(update={"mcp_resource_management": limits})
    # The real function takes the load's confine hook (and the limits reader
    # passes one), a views out-list and the repository-file predicate; this
    # stand-in is the already-loaded operator config.
    monkeypatch.setattr(
        default_config,
        "get_default_config",
        lambda *_args, **_kwargs: operator,
    )

    pid_file = tmp_path / "child.pid"

    def scan(**kwargs: Any):
        from automated_security_helper.utils.subprocess_utils import run_command

        run_command([sys.executable, "-c", _CHILD, str(pid_file)])
        output = Path(kwargs["output_dir"])
        (output / "ash_aggregated_results.json").write_text(
            json.dumps({"scanner_results": {}, "metadata": {}}), encoding="utf-8"
        )

    monkeypatch.setattr(_LAUNCHER, scan)
    project = _project(tmp_path, "slow")
    ctx = _ctx()

    started = time.monotonic()
    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(project))
    assert begun["success"] is True, begun
    await _drain(timeout=CHILD_SECONDS + 30)
    ran_for = time.monotonic() - started

    progress: Dict[str, Any] = await mcp_server.get_scan_progress(ctx, begun["scan_id"])
    outcome = {
        "seconds": round(ran_for, 1),
        "status": progress.get("status"),
        "error_message": progress.get("error_message"),
        "results_file_written": (
            project / ".ash" / "ash_output" / "ash_aggregated_results.json"
        ).exists(),
    }
    assert (
        ran_for < CHILD_SECONDS / 2
        and outcome["status"] == "failed"
        and "scan_timeout_seconds" in (outcome["error_message"] or "")
        and not outcome["results_file_written"]
    ), f"a scan with scan_timeout_seconds=1 ended as {outcome}"
    if os.name == "posix" and pid_file.exists():
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)


# ---------------------------------------------------------------------------
# 0 or null is no limit; the ceilings; when the timeout clock starts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("no_limit", ["0", "null"])
async def test_zero_or_null_concurrency_is_no_limit(
    tmp_path, monkeypatch, held, no_limit
):
    _operator_config(tmp_path, monkeypatch, max_concurrent_scans=no_limit)
    ctx = _ctx()
    try:
        started = [
            await mcp_server.run_ash_scan(
                ctx, source_dir=str(_project(tmp_path, f"p{n}"))
            )
            for n in range(5)
        ]
    finally:
        held.set()
        await _drain()

    assert all(result["success"] for result in started), started


@pytest.mark.parametrize("no_limit", [0, None])
def test_zero_or_null_timeout_is_no_limit(no_limit):
    from automated_security_helper.config.ash_config import (
        MCPResourceManagementConfig,
    )

    limits = MCPResourceManagementConfig(scan_timeout_seconds=no_limit)
    assert limits.scan_timeout_seconds in (0, None)


@pytest.mark.parametrize(
    "field,value,accepted",
    [
        ("max_concurrent_scans", 100, True),
        ("max_concurrent_scans", 101, False),
        ("scan_timeout_seconds", 86400, True),
        ("scan_timeout_seconds", 86401, False),
        ("scan_timeout_seconds", 59, False),
        ("max_concurrent_scans", -1, False),
    ],
)
def test_the_ceilings(field, value, accepted):
    from pydantic import ValidationError

    from automated_security_helper.config.ash_config import (
        MCPResourceManagementConfig,
    )

    if accepted:
        assert getattr(MCPResourceManagementConfig(**{field: value}), field) == value
    else:
        with pytest.raises(ValidationError):
            MCPResourceManagementConfig(**{field: value})


@pytest.mark.asyncio
async def test_the_timeout_counts_from_when_the_scan_gets_its_session_lock(
    tmp_path, monkeypatch
):
    """A scan queued behind another of its session is not timed out for waiting."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp.sessions import get_default_registry
    from automated_security_helper.config import default_config
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )

    base = AshConfig()
    limits = base.mcp_resource_management.model_copy(update={"scan_timeout_seconds": 1})
    operator = base.model_copy(update={"mcp_resource_management": limits})
    # The real function takes the load's confine hook (and the limits reader
    # passes one), a views out-list and the repository-file predicate; this
    # stand-in is the already-loaded operator config.
    monkeypatch.setattr(
        default_config,
        "get_default_config",
        lambda *_args, **_kwargs: operator,
    )
    monkeypatch.setattr(_LAUNCHER, lambda **kwargs: None)

    project = _project(tmp_path, "queued")
    output = project / ".ash" / "ash_output"
    output.mkdir(parents=True)
    session_lock = get_default_registry().get_or_create("session-q").lock
    scan_id = get_scan_registry().register_scan(
        directory_path=str(project), output_directory=str(output)
    )
    session_lock.acquire()
    runner = asyncio.create_task(
        mcp_tools._run_scan_async(
            scan_id=scan_id,
            directory_path=str(project),
            output_dir=str(output),
            severity_threshold=None,
            session_id="session-q",
            scan_timeout_seconds=1,
        )
    )
    # Waits for the lock for longer than the timeout.
    await asyncio.sleep(2.0)
    session_lock.release()
    await asyncio.wait_for(runner, timeout=30)

    entry = get_scan_registry().get_scan(scan_id)
    assert entry.status.value == "completed", (entry.status, entry.error_message)


# ---------------------------------------------------------------------------
# Workspace scans: one slot for the whole workspace, one timeout over all of it
# ---------------------------------------------------------------------------
#
# A workspace scan registers one entry per project. Counted per project, a
# workspace with more projects than max_concurrent_scans could never start, so
# a workspace scan takes one slot however many projects it has. The timeout
# covers the whole workspace scan and stops it the way it stops a single scan.


@contextlib.asynccontextmanager
async def _task(coroutine):
    """The coroutine as a task that does not outlive the test.

    On the way out a task still running is cancelled, and every task is awaited
    without raising, so a failed assertion is the error the test reports.
    """
    task = asyncio.create_task(coroutine)
    try:
        yield task
    finally:
        if not task.done():
            task.cancel()
        await asyncio.wait({task}, timeout=60)
        if task.done() and not task.cancelled():
            task.exception()


@contextlib.contextmanager
def _no_loop_errors():
    """Fail the test if an event-loop callback raised inside the block.

    The loop logs an exception from a callback (the timeout's timer, say) and
    carries on, so without this a timer that could not be armed passes for one
    that was armed and never fired.
    """
    loop = asyncio.get_running_loop()
    errors: list = []
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: errors.append(context))
    try:
        yield
    finally:
        loop.set_exception_handler(previous)
    assert errors == [], [
        f"{context.get('message')}: {context.get('exception')!r}" for context in errors
    ]


def _workspace(tmp_path: Path, *names: str) -> Path:
    root = tmp_path / "allowed" / "ws"
    for name in names:
        (root / name).mkdir(parents=True)
        (root / name / "app.py").write_text("x = 1\n", encoding="utf-8")
    path = root / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": name} for name in names]}), encoding="utf-8"
    )
    return path


def _workspace_entries() -> Dict[str, Any]:
    """Every registry entry under the workspace fixture's root, by project name."""
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )

    registry = get_scan_registry()
    return {
        Path(scan["directory_path"]).name: registry.get_scan(scan["scan_id"])
        for scan in registry.list_scans()
        if Path(scan["directory_path"]).parent.name == "ws"
    }


def _completed_run(plan, settings):
    from automated_security_helper.models.workspace import (
        ProjectRunStatus,
        WorkspaceProjectResult,
        WorkspaceResults,
    )
    from automated_security_helper.workspace.execution import WorkspaceRunResult

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
                finding_count=0,
                actionable_finding_count=0,
            )
            for project in plan.projects
        ],
        unconvertible_finding_paths=0,
    )
    return WorkspaceRunResult(
        results_path=Path(settings.output_dir) / "ash_aggregated_results.json",
        exit_code=0,
        payload=payload,
    )


@pytest.fixture
def held_workspace(monkeypatch):
    """An execute_workspace that holds every workspace scan until released."""
    from automated_security_helper.cli.mcp import workspace as workspace_module

    started = threading.Event()
    release = threading.Event()

    def _execute(plan, settings, **kwargs):
        started.set()
        release.wait(30)
        return _completed_run(plan, settings)

    monkeypatch.setattr(workspace_module, "execute_workspace", _execute)
    return started, release


async def _scan_workspace(workspace: Path) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp.workspace import mcp_scan_workspace

    return await mcp_scan_workspace(workspace_file=str(workspace))


@pytest.mark.asyncio
class TestMaxConcurrentScansForWorkspaceScans:
    async def test_a_workspace_scan_over_the_limit_is_refused_like_a_single_scan(
        self, tmp_path, monkeypatch, held, held_workspace
    ):
        _operator_config(tmp_path, monkeypatch, max_concurrent_scans=1)
        started, release = held_workspace
        # Released up front: a workspace scan that is wrongly let through returns
        # at once, and `started` says it ran.
        release.set()
        ctx = _ctx()
        try:
            first = await mcp_server.run_ash_scan(
                ctx, source_dir=str(_project(tmp_path, "one"))
            )
            single = await mcp_server.run_ash_scan(
                ctx, source_dir=str(_project(tmp_path, "two"))
            )
            workspace = await _scan_workspace(_workspace(tmp_path, "api", "web"))
        finally:
            held.set()
            await _drain()

        assert first["success"] is True, first
        assert single["success"] is False, single
        assert workspace["success"] is False, (
            f"a workspace scan started beside a running scan under "
            f"max_concurrent_scans=1: {workspace}"
        )
        # The registry's own refusal; run_ash_scan prefixes it with
        # "Failed to start scan: ".
        assert workspace["error"] in single["error"], (workspace, single)
        assert workspace["error_category"] == "resource_exhausted", workspace
        assert not started.is_set(), "the refused workspace scan ran anyway"
        assert _workspace_entries() == {}, "the refused workspace scan registered"

    async def test_a_workspace_refused_at_its_second_project_frees_its_first(
        self, tmp_path, monkeypatch, held, held_workspace
    ):
        """Registration is all or nothing.

        A single scan holds the second project's directory, so the workspace is
        refused there, after its first project was registered. That registration
        is rolled back: left behind, it would keep the first project's directory
        busy for a scan that never runs.
        """
        _operator_config(tmp_path, monkeypatch, max_concurrent_scans=5)
        started, release = held_workspace
        release.set()
        workspace_file = _workspace(tmp_path, "api", "web")
        ctx = _ctx()
        try:
            holder = await mcp_server.run_ash_scan(
                ctx, source_dir=str(workspace_file.parent / "web")
            )
            refused = await _scan_workspace(workspace_file)
            first_project = await mcp_server.run_ash_scan(
                ctx, source_dir=str(workspace_file.parent / "api")
            )
        finally:
            held.set()
            await _drain()

        assert holder["success"] is True, holder
        assert refused["success"] is False, refused
        assert "already has an active scan" in refused["error"], refused
        assert not started.is_set(), "the refused workspace scan ran anyway"
        assert first_project["success"] is True, (
            f"the refused workspace scan left its first project's directory "
            f"claimed: {first_project}"
        )

    async def test_a_running_workspace_scan_takes_one_slot_whatever_its_size(
        self, tmp_path, monkeypatch, held, held_workspace
    ):
        """Three projects under a limit of two: the workspace runs, as one scan.

        Counted per project, its third project would be refused by its own first
        two. Counted as one, a single scan still fits beside it and a second
        does not.
        """
        _operator_config(tmp_path, monkeypatch, max_concurrent_scans=2)
        started, release = held_workspace
        ctx = _ctx()
        async with _task(
            _scan_workspace(_workspace(tmp_path, "api", "web", "infra"))
        ) as workspace_scan:
            try:
                assert await asyncio.to_thread(started.wait, 30), "workspace never ran"
                beside = await mcp_server.run_ash_scan(
                    ctx, source_dir=str(_project(tmp_path, "one"))
                )
                over = await mcp_server.run_ash_scan(
                    ctx, source_dir=str(_project(tmp_path, "two"))
                )
            finally:
                release.set()
                held.set()
            workspace = await asyncio.wait_for(workspace_scan, timeout=30)
        await _drain()

        assert workspace["success"] is True, workspace
        assert len(workspace["scan_ids"]) == 3, workspace
        assert beside["success"] is True, (
            f"a three-project workspace scan took more than one of two slots: {beside}"
        )
        assert over["success"] is False, over
        assert "max_concurrent_scans" in over["error"], over

    async def test_a_finished_workspace_scan_frees_its_slot(
        self, tmp_path, monkeypatch, held, held_workspace
    ):
        _operator_config(tmp_path, monkeypatch, max_concurrent_scans=1)
        _started, release = held_workspace
        release.set()
        held.set()
        workspace = await _scan_workspace(_workspace(tmp_path, "api", "web"))
        single = await mcp_server.run_ash_scan(
            _ctx(), source_dir=str(_project(tmp_path, "one"))
        )
        await _drain()

        assert workspace["success"] is True, workspace
        assert single["success"] is True, single

    @pytest.mark.parametrize("no_limit", ["0", "null"])
    async def test_zero_or_null_concurrency_is_no_limit_for_a_workspace_scan(
        self, tmp_path, monkeypatch, held, held_workspace, no_limit
    ):
        _operator_config(tmp_path, monkeypatch, max_concurrent_scans=no_limit)
        _started, release = held_workspace
        release.set()
        ctx = _ctx()
        try:
            singles = [
                await mcp_server.run_ash_scan(
                    ctx, source_dir=str(_project(tmp_path, f"p{n}"))
                )
                for n in range(3)
            ]
            workspace = await _scan_workspace(_workspace(tmp_path, "api", "web"))
        finally:
            held.set()
            await _drain()

        assert all(result["success"] for result in singles), singles
        assert workspace["success"] is True, workspace


class _HeldPerProject:
    """A launcher whose scan of each project runs until that project is released."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: Dict[str, threading.Event] = {}
        self._all_released = False

    def _event(self, project: str) -> threading.Event:
        with self._lock:
            event = self._events.setdefault(project, threading.Event())
            if self._all_released:
                event.set()
            return event

    def scan(self, **kwargs: Any) -> None:
        self._event(Path(kwargs["source_dir"]).name).wait(30)

    def release(self, project: str) -> None:
        self._event(project).set()

    def release_all(self) -> None:
        with self._lock:
            self._all_released = True
            events = list(self._events.values())
        for event in events:
            event.set()


@pytest.fixture
def held_per_project(monkeypatch) -> _HeldPerProject:
    held = _HeldPerProject()
    monkeypatch.setattr(_LAUNCHER, held.scan)
    return held


async def _ended(scan_id: str) -> None:
    """Wait for one scan's runner to end and close its entry, the others running."""
    from automated_security_helper.cli import mcp_tools

    task = next((t for t, s in mcp_tools._scan_tasks.items() if s == scan_id), None)
    if task is not None:
        await asyncio.wait_for(task, timeout=30)


@pytest.mark.asyncio
class TestTheRefusalAtTheLimit:
    """A refused scan takes no slot, and its refusal names the limit only.

    The limit is server-wide: every session's scans count against the one
    ``max_concurrent_scans``. A refusal is raised before the registry records the
    scan, so the scan never holds a slot it would have to give back. Its message
    and context name the limit, not the number of scans running, which would tell
    any session how many scans the others are running.
    """

    async def test_a_refused_scan_holds_no_slot(
        self, tmp_path, monkeypatch, held_per_project
    ):
        """Fill the limit of two, be refused once, end one scan, start the next.

        Had the refused scan been counted, the scan still running and the refused
        one would fill both slots, and the last start would be refused too.

        Each scan is in its own session. The scans of one session run one at a
        time, on the session's lock, in whichever order their threads take it:
        in one session, scan two could take it first, and scan one, released,
        would wait behind it until the 30 s wait for its end ran out.
        """
        from automated_security_helper.core.resource_management.scan_registry import (
            get_scan_registry,
        )

        _operator_config(tmp_path, monkeypatch, max_concurrent_scans=2)
        try:
            one = await mcp_server.run_ash_scan(
                _ctx("one"), source_dir=str(_project(tmp_path, "one"))
            )
            two = await mcp_server.run_ash_scan(
                _ctx("two"), source_dir=str(_project(tmp_path, "two"))
            )
            refused_dir = _project(tmp_path, "three")
            refused = await mcp_server.run_ash_scan(
                _ctx("three"), source_dir=str(refused_dir)
            )
            held_per_project.release("one")
            await _ended(one["scan_id"])
            after = await mcp_server.run_ash_scan(
                _ctx("four"), source_dir=str(_project(tmp_path, "four"))
            )
        finally:
            held_per_project.release_all()
            await _drain()

        assert one["success"] is True, one
        assert two["success"] is True, two
        assert refused["success"] is False, refused
        assert "max_concurrent_scans" in refused["error"], refused
        assert get_scan_registry().list_scans(directory_path=str(refused_dir)) == [], (
            "the refused scan was registered"
        )
        assert after["success"] is True, (
            f"a scan was refused after one of two running scans ended, so the "
            f"refused scan held a slot: {after}"
        )

    async def test_the_refusal_names_the_limit_and_not_the_count(
        self, tmp_path, monkeypatch, held, held_workspace
    ):
        """Three scans run, then the operator lowers the limit to two.

        The operator config is read per scan, so the next ones are refused at two
        while three are running: the count and the limit differ, and the refusal
        names only the limit. A single scan's refusal carries the message; a
        workspace scan's carries the context too.
        """
        _operator_config(tmp_path, monkeypatch, max_concurrent_scans=3)
        _started, release = held_workspace
        # A workspace scan wrongly let through returns at once.
        release.set()
        ctx = _ctx()
        try:
            running = [
                await mcp_server.run_ash_scan(
                    ctx, source_dir=str(_project(tmp_path, f"p{n}"))
                )
                for n in range(3)
            ]
            (tmp_path / "operator" / "ash.yaml").write_text(
                "project_name: operator\n"
                "mcp-resource-management:\n"
                "  max_concurrent_scans: 2\n",
                encoding="utf-8",
            )
            single = await mcp_server.run_ash_scan(
                ctx, source_dir=str(_project(tmp_path, "over"))
            )
            workspace = await _scan_workspace(_workspace(tmp_path, "api", "web"))
        finally:
            held.set()
            await _drain()

        assert all(result["success"] for result in running), running
        for refused in (single, workspace):
            assert refused["success"] is False, refused
            assert "max_concurrent_scans limit of 2" in refused["error"], refused
            assert re.search(r"\b3\b", refused["error"]) is None, refused
        assert set(workspace["context"]) == {
            "directory_path",
            "max_concurrent_scans",
            "error_category",
            "suggestions",
        }, workspace["context"]
        assert workspace["context"]["max_concurrent_scans"] == 2, workspace


def _operator_limits(monkeypatch, **limits: Any) -> None:
    """The operator's MCP limits, a timeout below the model's floor included.

    ``model_copy(update=...)`` skips validation, as in the single-scan timeout
    test above.
    """
    from automated_security_helper.config import default_config
    from automated_security_helper.config.ash_config import AshConfig

    base = AshConfig()
    section = base.mcp_resource_management.model_copy(update=limits)
    operator = base.model_copy(update={"mcp_resource_management": section})
    # The real function takes the load's confine hook (and the limits reader
    # passes one), a views out-list and the repository-file predicate; this
    # stand-in is the already-loaded operator config.
    monkeypatch.setattr(
        default_config,
        "get_default_config",
        lambda *_args, **_kwargs: operator,
    )


def _child(seconds: float) -> str:
    """A child that records its pid, then works for ``seconds``."""
    return (
        "import os, pathlib, sys, time; "
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
        f"time.sleep({seconds})"
    )


def _child_process_scans(
    monkeypatch,
    tmp_path: Path,
    seconds: Dict[str, float],
    *,
    parallel: Optional[int] = None,
    scripts: Optional[Dict[str, str]] = None,
) -> Dict[str, threading.Event]:
    """Run the real execute_workspace, with each project's scan a child process.

    Everything from mcp_scan_workspace down to each project's worker thread is
    ASH's own; the orchestrator is the stand-in. Its scan is one child process of
    the project's duration, started through run_command, which is where a
    cancelled scan's running scanner is stopped. Returns, per project, an event
    set as its scan starts. The plugin pre-warm is skipped and no reporter is
    considered: neither runs a scanner, and both take time the timeout counts.

    ``parallel`` is the pool size, every project at once unless given: the
    default comes from the host's CPU count, and on one CPU the second project
    would wait for the first. ``scripts`` replaces a project's child.
    """
    from automated_security_helper.cli.mcp import workspace as workspace_module
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.workspace import execution

    started = {key: threading.Event() for key in seconds}

    class _ChildProcessScan:
        def __init__(self, **kwargs: Any) -> None:
            self.key = Path(kwargs["source_dir"]).name

        def execute_scan(self, phases=None):
            from automated_security_helper.utils.subprocess_utils import run_command

            started[self.key].set()
            script = (scripts or {}).get(self.key) or _child(seconds[self.key])
            run_command(
                [sys.executable, "-c", script, str(tmp_path / f"{self.key}.pid")]
            )
            return AshAggregatedResults()

    real = execution.execute_workspace
    pool = parallel or len(seconds)

    def _execute(plan, settings, **kwargs):
        return real(
            plan,
            dataclasses.replace(settings, max_parallel_projects=pool),
            orchestrator_factory=_ChildProcessScan,
            reporter_classes=[],
            **kwargs,
        )

    monkeypatch.setattr(execution, "prewarm_plugin_registry", lambda *a: 0)
    monkeypatch.setattr(workspace_module, "execute_workspace", _execute)
    return started


async def _wait_for(path: Path) -> None:
    for _ in range(600):
        if await asyncio.to_thread(path.exists):
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"{path} never appeared")


def _assert_stopped(tmp_path: Path, keys) -> None:
    for key in keys:
        pid_file = tmp_path / f"{key}.pid"
        assert pid_file.exists(), f"project {key}'s child never started"
        if os.name == "posix":
            with pytest.raises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)


@pytest.mark.asyncio
async def test_a_workspace_scan_past_scan_timeout_seconds_is_stopped_and_failed(
    tmp_path, monkeypatch
):
    """Ends as a single scan does: failed, its scanners stopped, nothing written."""
    _operator_limits(monkeypatch, scan_timeout_seconds=2)
    _child_process_scans(
        monkeypatch, tmp_path, {"api": CHILD_SECONDS, "web": CHILD_SECONDS}
    )
    workspace_file = _workspace(tmp_path, "api", "web")
    output = workspace_file.parent / ".ash" / "ash_output"

    began = time.monotonic()
    with _no_loop_errors():
        response = await asyncio.wait_for(
            _scan_workspace(workspace_file), timeout=CHILD_SECONDS + 30
        )
    ran_for = time.monotonic() - began

    entries = _workspace_entries()
    outcome = {
        "seconds": round(ran_for, 1),
        "success": response.get("success"),
        "error": response.get("error"),
        "error_category": response.get("error_category"),
        "statuses": {key: entry.status.value for key, entry in entries.items()},
        "errors": {key: entry.error_message for key, entry in entries.items()},
        "results_file_written": (output / "ash_aggregated_results.json").exists(),
    }
    assert (
        ran_for < CHILD_SECONDS / 2
        and outcome["success"] is False
        and "scan_timeout_seconds" in (outcome["error"] or "")
        and outcome["error_category"] == "operation_timeout"
        and outcome["statuses"] == {"api": "failed", "web": "failed"}
        and all("scan_timeout_seconds" in (e or "") for e in outcome["errors"].values())
        and not outcome["results_file_written"]
    ), f"a workspace scan with scan_timeout_seconds=2 ended as {outcome}"
    assert set(response.get("scan_ids") or {}) == {"api", "web"}, response
    assert not any(entry.occupies_its_directory() for entry in entries.values())
    _assert_stopped(tmp_path, ["api", "web"])


@pytest.mark.asyncio
@pytest.mark.parametrize("no_limit", [0, None])
async def test_zero_or_null_timeout_leaves_a_workspace_scan_to_finish(
    tmp_path, monkeypatch, no_limit
):
    """0 is no limit, not a timeout of 0 seconds, and arms no timer."""
    _operator_limits(monkeypatch, scan_timeout_seconds=no_limit)
    _child_process_scans(monkeypatch, tmp_path, {"api": 1.0, "web": 1.0})

    with _no_loop_errors():
        response = await asyncio.wait_for(
            _scan_workspace(_workspace(tmp_path, "api", "web")), timeout=60
        )

    statuses = {key: entry.status.value for key, entry in _workspace_entries().items()}
    assert response["success"] is True, response
    assert "failed" not in statuses.values(), statuses


@pytest.mark.asyncio
async def test_cancelling_one_project_of_a_workspace_scan_stops_that_project_only(
    tmp_path, monkeypatch
):
    """cancel_scan on one project's scan id stops its scanner; the rest finish.

    Through the same cancel path the timeout uses, so a workspace project's
    registry entry is cancelled the way a single scan's is.
    """
    started = _child_process_scans(
        monkeypatch, tmp_path, {"slow": CHILD_SECONDS, "quick": 0.5}
    )
    began = time.monotonic()
    async with _task(
        _scan_workspace(_workspace(tmp_path, "slow", "quick"))
    ) as workspace_scan:
        assert await asyncio.to_thread(started["slow"].wait, 30), "slow never started"
        # Cancelled once its scanner's child runs, so the cancel has a process to
        # stop.
        await _wait_for(tmp_path / "slow.pid")
        slow = _workspace_entries()["slow"]
        cancelled = await mcp_server.cancel_scan(_ctx(), slow.scan_id)
        response = await asyncio.wait_for(workspace_scan, timeout=CHILD_SECONDS + 30)
    ran_for = time.monotonic() - began

    entries = _workspace_entries()
    projects = {project["project"]: project for project in response["projects"]}
    assert cancelled["success"] is True, cancelled
    assert ran_for < CHILD_SECONDS / 2, (
        f"the workspace ran {ran_for:.1f}s after its slow project was cancelled"
    )
    assert response["success"] is True, response
    assert entries["slow"].status.value == "cancelled", entries["slow"].status
    assert projects["slow"]["status"] == "failed", projects["slow"]
    assert entries["quick"].status.value != "failed", entries["quick"].error_message
    assert projects["quick"]["status"] == "completed", projects["quick"]
    _assert_stopped(tmp_path, ["slow"])


@pytest.mark.asyncio
async def test_a_timed_out_workspace_scan_holds_its_slot_until_its_thread_stops(
    tmp_path, monkeypatch, held, held_workspace
):
    """The timeout closes the entries at once; the slot is free when the run ends.

    The stand-in run here ignores the cancel, as a run inside a step that does
    not check (writing the unified results, say) would. Until it ends, its
    projects' directories and its max_concurrent_scans slot are still in use,
    and the call, when it returns, reports the timeout the registry recorded.
    """
    _operator_limits(monkeypatch, max_concurrent_scans=1, scan_timeout_seconds=1)
    started, release = held_workspace
    held.set()
    ctx = _ctx()
    with _no_loop_errors():
        async with _task(
            _scan_workspace(_workspace(tmp_path, "api", "web"))
        ) as workspace_scan:
            try:
                assert await asyncio.to_thread(started.wait, 30), "workspace never ran"
                await _wait_for_status("api", "failed")
                while_stopping = await mcp_server.run_ash_scan(
                    ctx, source_dir=str(_project(tmp_path, "one"))
                )
                same_directory = await mcp_server.run_ash_scan(
                    ctx, source_dir=str(tmp_path / "allowed" / "ws" / "api")
                )
            finally:
                release.set()
            response = await asyncio.wait_for(workspace_scan, timeout=30)
    after = await mcp_server.run_ash_scan(
        ctx, source_dir=str(_project(tmp_path, "two"))
    )
    await _drain()

    assert while_stopping["success"] is False, (
        f"a timed-out workspace scan gave up its slot while its run went on: "
        f"{while_stopping}"
    )
    assert "max_concurrent_scans" in while_stopping["error"], while_stopping
    assert same_directory["success"] is False, same_directory
    assert response["success"] is False, response
    assert "scan_timeout_seconds" in response["error"], response
    assert after["success"] is True, after


async def _wait_for_status(project: str, status: str) -> None:
    for _ in range(600):
        entry = _workspace_entries().get(project)
        if entry is not None and entry.status.value == status:
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"project {project} never became {status}")


# ---------------------------------------------------------------------------
# Every way a workspace call ends stops its projects and frees what it held
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_cancelled_workspace_call_stops_its_projects(tmp_path, monkeypatch):
    """Cancelling the call does not stop its thread; the call stops the projects.

    The entry's runner_done is set once the thread has stopped and settled, so
    waiting on it measures the stop and not a guess at how long it takes.
    """
    _child_process_scans(monkeypatch, tmp_path, {"api": CHILD_SECONDS})
    async with _task(_scan_workspace(_workspace(tmp_path, "api"))) as workspace_scan:
        await _wait_for(tmp_path / "api.pid")
        entry = _workspace_entries()["api"]
        workspace_scan.cancel()
        with pytest.raises(asyncio.CancelledError):
            await workspace_scan
        stopped = await asyncio.to_thread(entry.runner_done.wait, CHILD_SECONDS / 2)

    assert stopped, "the workspace kept scanning after its call was cancelled"
    assert entry.status.value == "failed", entry.status
    _assert_stopped(tmp_path, ["api"])


async def _never_starts(*args: Any, **kwargs: Any) -> None:
    """An _execute whose thread never starts: it waits until it is cancelled."""
    await asyncio.Event().wait()


async def _executor_refuses(*args: Any, **kwargs: Any) -> None:
    """An _execute whose thread never starts: the executor refuses the job."""
    raise RuntimeError("cannot schedule new futures after shutdown")


@pytest.mark.asyncio
@pytest.mark.parametrize("ending", ["cancelled", "raised"])
async def test_a_workspace_call_ending_before_its_thread_starts_frees_its_slot(
    tmp_path, monkeypatch, held, ending
):
    """The thread is what releases the entries, so a call it never ran for must.

    Left to a thread that never runs, the entries would hold their directories
    and the workspace's slot for as long as the server runs.
    """
    from automated_security_helper.cli.mcp import workspace as workspace_module

    _operator_limits(monkeypatch, max_concurrent_scans=1, scan_timeout_seconds=None)
    monkeypatch.setattr(
        workspace_module,
        "_execute",
        _never_starts if ending == "cancelled" else _executor_refuses,
    )
    held.set()
    async with _task(_scan_workspace(_workspace(tmp_path, "api"))) as workspace_scan:
        if ending == "cancelled":
            await _wait_for_status("api", "running")
            workspace_scan.cancel()
            with pytest.raises(asyncio.CancelledError):
                await workspace_scan
        else:
            response = await asyncio.wait_for(workspace_scan, timeout=30)
            assert response["success"] is False, response
    single = await mcp_server.run_ash_scan(
        _ctx(), source_dir=str(_project(tmp_path, "one"))
    )
    await _drain()

    entry = _workspace_entries()["api"]
    assert not entry.occupies_its_directory(), entry.status
    assert single["success"] is True, (
        f"a workspace call that ended ({ending}) before its thread started kept "
        f"its slot: {single}"
    )


@pytest.mark.asyncio
async def test_a_project_cancelled_while_queued_never_starts(tmp_path, monkeypatch):
    """One worker, two projects: the second, cancelled while it waits, never runs."""
    started = _child_process_scans(
        monkeypatch, tmp_path, {"first": 1.0, "queued": 1.0}, parallel=1
    )
    async with _task(
        _scan_workspace(_workspace(tmp_path, "first", "queued"))
    ) as workspace_scan:
        await _wait_for(tmp_path / "first.pid")
        queued = _workspace_entries()["queued"]
        cancelled = await mcp_server.cancel_scan(_ctx(), queued.scan_id)
        response = await asyncio.wait_for(workspace_scan, timeout=30)

    projects = {project["project"]: project for project in response["projects"]}
    assert cancelled["success"] is True, cancelled
    assert not started["queued"].is_set(), (
        "a project cancelled while it waited for a worker started anyway"
    )
    assert projects["queued"]["status"] == "failed", projects["queued"]
    assert projects["first"]["status"] == "completed", projects["first"]


def _slow_to_stop(marker: Path) -> str:
    """A scanner's child that notes SIGTERM in ``marker`` and keeps working.

    It records its pid as _child does and goes on until SIGKILL, so the time
    between the stop and the kill is a window in which the scan is stopping.
    """
    return (
        "import os, pathlib, signal, sys, time\n"
        f"marker = pathlib.Path({str(marker)!r})\n"
        "signal.signal(signal.SIGTERM, lambda *_: marker.write_text('TERM'))\n"
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
        "end = time.monotonic() + 60\n"
        "while time.monotonic() < end:\n"
        "    time.sleep(0.05)\n"
    )


def _alive(pid: int) -> bool:
    # Running, not a zombie waiting to be reaped, which signal 0 still reaches.
    return process_running(pid)


@pytest.mark.asyncio
@pytest.mark.parametrize("held_by", ["slot", "directory"])
async def test_a_project_past_its_project_timeout_is_stopped_before_the_call_returns(
    tmp_path, monkeypatch, held, held_by
):
    """project_timeout comes from the scanned workspace's own config.

    A project past it is stopped as a cancel stops it, and the call holds its
    max_concurrent_scans slot and its directories until the project has
    stopped, so a workspace config with a short project_timeout cannot run its
    scanners outside both operator limits.
    """
    from automated_security_helper.utils import subprocess_utils

    _operator_limits(
        monkeypatch,
        max_concurrent_scans=1 if held_by == "slot" else None,
        scan_timeout_seconds=None,
    )
    # The child ignores SIGTERM, so it is killed this long after it.
    monkeypatch.setattr(subprocess_utils, "SANDBOX_STOP_GRACE_SECONDS", 3.0)
    marker = tmp_path / "api.term"
    _child_process_scans(
        monkeypatch, tmp_path, {"api": 60.0}, scripts={"api": _slow_to_stop(marker)}
    )
    workspace_file = _workspace(tmp_path, "api")
    (workspace_file.parent / ".ash").mkdir()
    (workspace_file.parent / ".ash" / ".ash.yaml").write_text(
        "project_name: ws\nworkspace:\n  project_timeout: 1\n", encoding="utf-8"
    )
    held.set()
    ctx = _ctx()
    during = None
    pid_file = tmp_path / "api.pid"
    try:
        async with _task(_scan_workspace(workspace_file)) as workspace_scan:
            told_to_stop = asyncio.create_task(_wait_for(marker))
            await asyncio.wait(
                {workspace_scan, told_to_stop},
                timeout=30,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if told_to_stop.done() and not workspace_scan.done():
                other = (
                    _project(tmp_path, "one")
                    if held_by == "slot"
                    else workspace_file.parent / "api"
                )
                during = await mcp_server.run_ash_scan(ctx, source_dir=str(other))
            response = await asyncio.wait_for(workspace_scan, timeout=30)
            told_to_stop.cancel()
        alive_at_return = _alive(int(pid_file.read_text()))
        after = await mcp_server.run_ash_scan(
            ctx, source_dir=str(_project(tmp_path, "two"))
        )
        await _drain()
    finally:
        # A child left running is what this test is about; it must not outlive
        # the test when the test fails.
        if pid_file.exists() and _alive(int(pid_file.read_text())):
            os.kill(int(pid_file.read_text()), 9)

    projects = {project["project"]: project for project in response["projects"]}
    assert "project_timeout" in (projects["api"].get("error") or ""), projects["api"]
    assert marker.exists(), "the project past its project_timeout was never stopped"
    assert not alive_at_return, "the call returned while the project's child ran"
    assert during is not None and during["success"] is False, (
        f"the {held_by} was free while the project past its project_timeout was "
        f"still stopping: {during}"
    )
    assert after["success"] is True, after


@pytest.mark.asyncio
async def test_stopping_the_server_stops_a_running_workspace_scan(
    tmp_path, monkeypatch
):
    """stop_running_scans runs before the server exits, and walked single scans only.

    A workspace project's child runs in a session of its own, so the process exit
    did not end it either: it went on scanning after the server had gone, and its
    entry read running to the end. The child here ignores SIGTERM, so only the
    prompt stop's short grace before SIGKILL ends it in time.
    """
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "SANDBOX_STOP_GRACE_SECONDS", 8.0)
    _child_process_scans(
        monkeypatch,
        tmp_path,
        {"api": 60.0},
        scripts={"api": _slow_to_stop(tmp_path / "api.term")},
    )
    pid_file = tmp_path / "api.pid"
    try:
        async with _task(
            _scan_workspace(_workspace(tmp_path, "api"))
        ) as workspace_scan:
            await _wait_for(pid_file)
            entry = _workspace_entries()["api"]
            began = time.monotonic()
            # The wait ends when the scan has settled, well before this timeout.
            await mcp_tools.stop_running_scans(
                "the server is stopping", timeout=CHILD_SECONDS * 3, promptly=True
            )
            took = time.monotonic() - began
            alive_after_stop = _alive(int(pid_file.read_text()))
            status_after_stop = entry.status.value
            assert not alive_after_stop, (
                f"the workspace project's child was still running after "
                f"stop_running_scans returned ({took:.1f}s)"
            )
            assert took < 4.0, (
                f"stop_running_scans took {took:.1f}s: not the prompt stop, or it "
                f"ran out its timeout instead of returning when the workspace scan "
                f"had settled"
            )
            assert status_after_stop == "cancelled", status_after_stop
            response = await asyncio.wait_for(workspace_scan, timeout=30)
    finally:
        if pid_file.exists() and _alive(int(pid_file.read_text())):
            os.kill(int(pid_file.read_text()), 9)

    assert response["success"] is False, response


@pytest.mark.asyncio
async def test_a_timeout_after_every_project_ended_is_not_reported(
    tmp_path, monkeypatch, held_workspace
):
    """As for a single scan, a timer that closes no scan reports no timeout.

    Both projects are cancelled before the timer fires, so when it does there is
    no scan left for it to fail; the call reports how the run ended.
    """
    _operator_limits(monkeypatch, scan_timeout_seconds=1)
    started, release = held_workspace
    ctx = _ctx()
    with _no_loop_errors():
        async with _task(
            _scan_workspace(_workspace(tmp_path, "api", "web"))
        ) as workspace_scan:
            try:
                assert await asyncio.to_thread(started.wait, 30), "workspace never ran"
                for entry in _workspace_entries().values():
                    cancelled = await mcp_server.cancel_scan(ctx, entry.scan_id)
                    assert cancelled["success"] is True, cancelled
                # Past the 1 s timer, which was armed when the run started.
                await asyncio.sleep(2.0)
            finally:
                release.set()
            response = await asyncio.wait_for(workspace_scan, timeout=30)

    statuses = {key: entry.status.value for key, entry in _workspace_entries().items()}
    assert "scan_timeout_seconds" not in str(response), response
    assert response["success"] is True, response
    assert statuses == {"api": "cancelled", "web": "cancelled"}, statuses


@pytest.mark.asyncio
async def test_a_worker_freed_by_a_stopped_project_runs_the_rest_of_the_queue(
    tmp_path, monkeypatch
):
    """One worker, three projects, and the first is stopped at its project_timeout.

    Without cancel events an abandoned worker cannot be stopped and holds its
    slot for good, so once every worker is held the queue is failed as never
    started. Under MCP the abandoned project is stopped and its worker comes back,
    and the queue was failed all the same.
    """
    _operator_limits(monkeypatch, max_concurrent_scans=None, scan_timeout_seconds=None)
    _child_process_scans(
        monkeypatch,
        tmp_path,
        {"slow": 60.0, "next": 0.2, "last": 0.2},
        parallel=1,
    )
    workspace_file = _workspace(tmp_path, "slow", "next", "last")
    (workspace_file.parent / ".ash").mkdir()
    (workspace_file.parent / ".ash" / ".ash.yaml").write_text(
        "project_name: ws\nworkspace:\n  project_timeout: 1\n", encoding="utf-8"
    )
    pid_file = tmp_path / "slow.pid"
    try:
        response = await asyncio.wait_for(_scan_workspace(workspace_file), timeout=60)
    finally:
        if pid_file.exists() and _alive(int(pid_file.read_text())):
            os.kill(int(pid_file.read_text()), 9)

    projects = {project["project"]: project for project in response["projects"]}
    errors = {key: project.get("error") for key, project in projects.items()}
    assert "project_timeout" in (errors["slow"] or ""), errors
    assert not any("never started" in (error or "") for error in errors.values()), (
        f"a project was failed as never started while a worker was free: {errors}"
    )
    assert projects["next"]["status"] == "completed", projects["next"]
    assert projects["last"]["status"] == "completed", projects["last"]


@pytest.mark.asyncio
class TestARefusedScanLeavesNothingOnDisk:
    """A scan the registry refuses creates no output directory.

    Both scans ask the registry for a slot before they create their output
    directories, so a scan refused at max_concurrent_scans leaves no empty
    ``.ash/ash_output`` tree behind, in the scanned repository for a single scan
    or under the workspace root for every project of a workspace scan. The
    registry takes an output directory that does not exist yet, and both
    create theirs once it has given them the scan; when that fails, the claim is
    given back.
    """

    async def test_a_refused_workspace_scan_creates_no_project_output(
        self, tmp_path, monkeypatch, held, held_workspace
    ):
        _operator_config(tmp_path, monkeypatch, max_concurrent_scans=1)
        started, release = held_workspace
        release.set()
        workspace_file = _workspace(tmp_path, "api", "web")
        try:
            first = await mcp_server.run_ash_scan(
                _ctx(), source_dir=str(_project(tmp_path, "one"))
            )
            refused = await _scan_workspace(workspace_file)
        finally:
            held.set()
            await _drain()

        assert first["success"] is True, first
        assert refused["success"] is False, refused
        assert "max_concurrent_scans" in refused["error"], refused
        assert not started.is_set(), "the refused workspace scan ran anyway"
        made = sorted(
            str(path.relative_to(workspace_file.parent))
            for path in (workspace_file.parent / ".ash").rglob("*")
        )
        assert not (workspace_file.parent / ".ash").exists(), (
            f"the refused workspace scan created {made}"
        )

    async def test_a_refused_single_scan_creates_no_output(
        self, tmp_path, monkeypatch, held
    ):
        _operator_config(tmp_path, monkeypatch, max_concurrent_scans=1)
        ctx = _ctx()
        second_project = _project(tmp_path, "two")
        try:
            first = await mcp_server.run_ash_scan(
                ctx, source_dir=str(_project(tmp_path, "one"))
            )
            refused = await mcp_server.run_ash_scan(ctx, source_dir=str(second_project))
        finally:
            held.set()
            await _drain()

        assert first["success"] is True, first
        assert refused["success"] is False, refused
        assert "max_concurrent_scans" in refused["error"], refused
        assert not (second_project / ".ash").exists(), (
            "the refused scan created an output directory in the scanned repository"
        )

    async def test_a_workspace_scan_that_cannot_make_its_outputs_frees_its_claim(
        self, tmp_path, monkeypatch, held, held_workspace
    ):
        """The outputs are made after the claim; failing there gives it back.

        ``projects`` under the output directory is a file, so no project's
        output directory can be created. Left claimed, the projects' directories
        and the only max_concurrent_scans slot would stay taken by a scan that
        never ran, and the scan after it would be refused.
        """
        _operator_config(tmp_path, monkeypatch, max_concurrent_scans=1)
        started, release = held_workspace
        release.set()
        held.set()
        workspace_file = _workspace(tmp_path, "api", "web")
        output = tmp_path / "allowed" / "out"
        output.mkdir()
        (output / "projects").write_text("not a directory\n", encoding="utf-8")
        from automated_security_helper.cli.mcp.workspace import mcp_scan_workspace

        failed = await mcp_scan_workspace(
            workspace_file=str(workspace_file), output_dir=str(output)
        )
        after = await mcp_server.run_ash_scan(
            _ctx(), source_dir=str(workspace_file.parent / "api")
        )
        await _drain()

        assert failed["success"] is False, failed
        assert not started.is_set(), "the workspace scan ran without its outputs"
        assert after["success"] is True, (
            f"the failed workspace scan kept its claim: {after}"
        )
        assert not any(
            entry.occupies_its_directory() for entry in _workspace_entries().values()
        ), _workspace_entries()

    async def test_a_single_scan_that_cannot_make_its_output_frees_its_claim(
        self, tmp_path, monkeypatch, held
    ):
        """``.ash`` in the scanned repository is a file, so ``ash_output`` cannot be made."""
        _operator_config(tmp_path, monkeypatch, max_concurrent_scans=1)
        held.set()
        blocked = _project(tmp_path, "blocked")
        (blocked / ".ash").write_text("not a directory\n", encoding="utf-8")
        ctx = _ctx()

        failed = await mcp_server.run_ash_scan(ctx, source_dir=str(blocked))
        after = await mcp_server.run_ash_scan(
            ctx, source_dir=str(_project(tmp_path, "next"))
        )
        await _drain()

        assert failed["success"] is False, failed
        assert after["success"] is True, f"the failed scan kept its claim: {after}"


@pytest.mark.asyncio
@pytest.mark.parametrize("configured", [64, 2])
async def test_a_scanned_workspace_cannot_raise_its_own_parallelism(
    tmp_path, monkeypatch, configured
):
    """max_parallel_projects comes from the scanned workspace's own config.

    A workspace scan holds one max_concurrent_scans slot however many projects it
    runs at once, so over MCP its parallelism is capped at the default,
    min(4, cpu_count); a workspace may still set less.
    """
    from automated_security_helper.cli.mcp import workspace as workspace_module
    from automated_security_helper.config.ash_config import WorkspaceExecutionConfig

    seen: Dict[str, int] = {}

    def _execute(plan, settings, **kwargs):
        seen["max_parallel_projects"] = settings.max_parallel_projects
        return _completed_run(plan, settings)

    monkeypatch.setattr(workspace_module, "execute_workspace", _execute)
    workspace_file = _workspace(tmp_path, "api", "web")
    (workspace_file.parent / ".ash").mkdir()
    (workspace_file.parent / ".ash" / ".ash.yaml").write_text(
        f"project_name: ws\nworkspace:\n  max_parallel_projects: {configured}\n",
        encoding="utf-8",
    )

    response = await _scan_workspace(workspace_file)

    assert response["success"] is True, response
    default = WorkspaceExecutionConfig().resolved_max_parallel_projects()
    assert seen["max_parallel_projects"] == min(configured, default), (
        f"the workspace's own {configured} gave {seen['max_parallel_projects']} "
        f"workers; the MCP bound is {default}"
    )
