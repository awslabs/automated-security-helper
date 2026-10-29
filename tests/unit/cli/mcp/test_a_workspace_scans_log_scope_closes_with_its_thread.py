# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan's run log scope closes with its last writer.

The workspace tool opens the scan's log scope and the workspace executes on a
thread asyncio.to_thread runs in a copy of that context. Cancelling the tool's
task does not stop that thread: it runs on until the run's next check, and its
last lines -- settling the projects' previous results among them -- are the
scan's. A scope closed in the tool's own finally retires while the thread
still writes under it, so handlers the run adds afterwards are tagged with a
retired scope, stay on the logger with no close coming, and can take the
server's own lines. The cells end a workspace scan each way: cancelled while
the thread runs, failed before the thread starts, and failed on the thread.
"""

import asyncio
import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.utils import log as ash_log

pytestmark = pytest.mark.unit

_PROJECTS = ("api", "web")


class _RecordingHandler(logging.Handler):
    """Formats each record as a handler would, traceback included."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: List[str] = []
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


@pytest.fixture(autouse=True)
def _no_confinement(monkeypatch):
    """No allowlist configured: confinement is not what these cells measure."""
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


@pytest.fixture()
def workspace_file(tmp_path: Path) -> Path:
    import json

    for name in _PROJECTS:
        (tmp_path / name).mkdir()
    path = tmp_path / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": name} for name in _PROJECTS]}),
        encoding="utf-8",
    )
    return path


def _wait_until_closed(scope: str, seconds: float = 30.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if scope not in ash_log._ACTIVE_RUN_LOG_SCOPES:
            return True
        time.sleep(0.05)
    return False


def test_a_cancelled_workspace_scans_scope_stays_open_until_its_thread_ends(
    workspace_file, monkeypatch
):
    before = set(ash_log._ACTIVE_RUN_LOG_SCOPES)
    thread_started = threading.Event()
    let_thread_finish = threading.Event()
    seen: Dict[str, Any] = {}

    def a_run_that_outlives_its_task(*args: Any, **kwargs: Any) -> Any:
        thread_started.set()
        let_thread_finish.wait(30)
        scope = ash_log.current_run_log_scope()
        seen["scope"] = scope
        seen["open_at_its_last_line"] = scope in ash_log._ACTIVE_RUN_LOG_SCOPES
        raise RuntimeError("the run stops here; its settle still runs after this")

    monkeypatch.setattr(
        workspace_module, "execute_workspace", a_run_that_outlives_its_task
    )

    async def start_cancel_then_finish() -> None:
        task = asyncio.ensure_future(
            workspace_module.mcp_scan_workspace(workspace_file=str(workspace_file))
        )
        await asyncio.to_thread(thread_started.wait, 30)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        let_thread_finish.set()

    asyncio.run(start_cancel_then_finish())

    if not thread_started.is_set() or "scope" not in seen:
        # The thread may still be writing `seen`: it runs past the loop.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and "open_at_its_last_line" not in seen:
            time.sleep(0.05)
    if "open_at_its_last_line" not in seen:
        raise RuntimeError(("control: the workspace thread did not run", seen))
    assert seen["scope"] is not None, "the workspace thread ran outside its scope"
    assert seen["open_at_its_last_line"], (
        "the scope closed while the workspace thread still wrote to it"
    )
    assert _wait_until_closed(seen["scope"]), "the scan's log scope is still open"
    assert set(ash_log._ACTIVE_RUN_LOG_SCOPES) == before


def test_a_workspace_start_that_fails_before_the_thread_leaves_no_scope_open(
    workspace_file, monkeypatch
):
    before = set(ash_log._ACTIVE_RUN_LOG_SCOPES)

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise ValueError("the settings could not be built")

    monkeypatch.setattr(workspace_module, "build_project_scan_settings", refuse)

    answer = asyncio.run(
        workspace_module.mcp_scan_workspace(workspace_file=str(workspace_file))
    )

    if answer.get("success") is not False:
        raise RuntimeError(("control: the start did not fail", answer))
    assert ash_log.current_run_log_scope() is None, (
        "the caller's context still holds the scan's scope"
    )
    assert set(ash_log._ACTIVE_RUN_LOG_SCOPES) == before, (
        "the scan's log scope is still open"
    )


def test_a_failing_close_of_the_registrations_still_frees_the_scope(
    workspace_file, monkeypatch
):
    """An error after registration, with the thread never started, reaches the
    arm that closes the registry entries. If closing them raises too, the
    settling -- and with it the thread share's release -- must still run, and
    the arm still maps the run's own error to an answer: a close failure that
    escaped here replaced that mapping with a raw traceback at the caller."""
    before = set(ash_log._ACTIVE_RUN_LOG_SCOPES)

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the output tree could not be made")

    def a_close_that_breaks(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the registry could not be reached")

    monkeypatch.setattr(workspace_module, "_create_project_outputs", refuse)
    monkeypatch.setattr(workspace_module, "_close_registrations", a_close_that_breaks)

    answer = asyncio.run(
        workspace_module.mcp_scan_workspace(workspace_file=str(workspace_file))
    )

    assert answer.get("success") is False, answer
    assert "the output tree could not be made" in str(answer), (
        "the answer does not carry the run's own error",
        answer,
    )
    assert set(ash_log._ACTIVE_RUN_LOG_SCOPES) == before, (
        "the scan's log scope is still open"
    )
    assert ash_log.current_run_log_scope() is None


def test_a_cancelled_scans_raising_close_still_stops_the_run(
    workspace_file, monkeypatch
):
    """Cancellation with a registry close that raises: the projects must still
    be told to stop, and the cancellation must be what propagates -- a close
    failure that replaces it leaves every project scanning after the cancel."""
    thread_started = threading.Event()
    let_thread_finish = threading.Event()
    seen: Dict[str, Any] = {}

    def a_run_that_waits_to_be_stopped(
        plan: Any, settings: Any, cancel_events: Any = None, **kwargs: Any
    ) -> Any:
        thread_started.set()
        deadline = time.monotonic() + 30
        events = list((cancel_events or {}).values())
        while time.monotonic() < deadline:
            if events and all(event.is_set() for event in events):
                break
            time.sleep(0.05)
        seen["stopped"] = bool(events) and all(event.is_set() for event in events)
        let_thread_finish.wait(30)
        raise RuntimeError("the run stops here; its settle still runs after this")

    def a_close_that_breaks(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the registry could not be reached")

    monkeypatch.setattr(
        workspace_module, "execute_workspace", a_run_that_waits_to_be_stopped
    )
    monkeypatch.setattr(workspace_module, "_close_registrations", a_close_that_breaks)

    async def start_cancel_then_finish() -> None:
        task = asyncio.ensure_future(
            workspace_module.mcp_scan_workspace(workspace_file=str(workspace_file))
        )
        await asyncio.to_thread(thread_started.wait, 30)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        let_thread_finish.set()

    asyncio.run(start_cancel_then_finish())

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and "stopped" not in seen:
        time.sleep(0.05)
    assert seen.get("stopped") is True, (
        "the cancelled run's projects were never told to stop",
        seen,
    )


def test_a_close_failures_log_shows_no_environment_value(workspace_file, monkeypatch):
    """The close-failure log line and its traceback redact the values the
    close error carries (carry_environment_values): the arm logs an error
    nothing expected while holding no configuration, so the carried values
    are the only redaction source it has, and a raw exception log printed
    the error's text and traceback with the value in the clear."""
    from automated_security_helper.utils.error_text import carry_environment_values

    canary = "wsenv-canary-c3f81b"
    recorder = _RecordingHandler()

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the output tree could not be made")

    def a_close_that_breaks(*args: Any, **kwargs: Any) -> Any:
        error = RuntimeError(f"the registry refused the token {canary}")
        carry_environment_values(error, (canary,))
        raise error

    monkeypatch.setattr(workspace_module, "_create_project_outputs", refuse)
    monkeypatch.setattr(workspace_module, "_close_registrations", a_close_that_breaks)
    workspace_module._logger.addHandler(recorder)
    try:
        answer = asyncio.run(
            workspace_module.mcp_scan_workspace(workspace_file=str(workspace_file))
        )
    finally:
        workspace_module._logger.removeHandler(recorder)

    assert answer.get("success") is False, answer
    joined = "\n".join(recorder.lines)
    if "closing the scan entries failed after an error" not in joined:
        raise RuntimeError(
            ("control: the close failure was not logged", joined[-2000:])
        )
    assert canary not in joined, (
        "the close error's carried env value reached the log raw"
    )


def test_a_cancelled_runs_close_failure_log_shows_no_environment_value(
    workspace_file, monkeypatch
):
    """The cancellation arm's close-failure log redacts carried values the
    same way; its line and traceback go to the server's own log while the
    cancellation re-raises."""
    from automated_security_helper.utils.error_text import carry_environment_values

    canary = "wsenv-canary-9d04aa"
    recorder = _RecordingHandler()
    thread_started = threading.Event()
    let_thread_finish = threading.Event()

    def a_run_that_waits_to_be_stopped(
        plan: Any, settings: Any, cancel_events: Any = None, **kwargs: Any
    ) -> Any:
        thread_started.set()
        let_thread_finish.wait(30)
        raise RuntimeError("the run stops here; its settle still runs after this")

    def a_close_that_breaks(*args: Any, **kwargs: Any) -> Any:
        error = RuntimeError(f"the registry refused the token {canary}")
        carry_environment_values(error, (canary,))
        raise error

    monkeypatch.setattr(
        workspace_module, "execute_workspace", a_run_that_waits_to_be_stopped
    )
    monkeypatch.setattr(workspace_module, "_close_registrations", a_close_that_breaks)
    workspace_module._logger.addHandler(recorder)
    try:

        async def start_cancel_then_finish() -> None:
            task = asyncio.ensure_future(
                workspace_module.mcp_scan_workspace(workspace_file=str(workspace_file))
            )
            await asyncio.to_thread(thread_started.wait, 30)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            let_thread_finish.set()

        asyncio.run(start_cancel_then_finish())
    finally:
        workspace_module._logger.removeHandler(recorder)

    joined = "\n".join(recorder.lines)
    if "closing the scan entries failed during cancellation" not in joined:
        raise RuntimeError(
            ("control: the close failure was not logged", joined[-2000:])
        )
    assert canary not in joined, (
        "the close error's carried env value reached the log raw"
    )


def test_a_cancel_before_the_thread_starts_still_settles_the_projects(
    workspace_file, monkeypatch
):
    """Cancellation landing before the workspace thread ever starts leaves
    the settling to the task: the cancellation arm must put the previous
    results back and let the scope's thread share go. The stand-in holds the
    task at an await without taking the handoff, so the thread genuinely
    never runs and ``task_abandons()`` answers True."""
    before = set(ash_log._ACTIVE_RUN_LOG_SCOPES)
    entered = threading.Event()

    async def an_execute_that_never_starts_its_thread(*args: Any, **kwargs: Any) -> Any:
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(
        workspace_module, "_execute", an_execute_that_never_starts_its_thread
    )

    planted: Dict[str, Path] = {}
    for name in _PROJECTS:
        # The per-project output layout the run uses (_project_outputs): the
        # workspace's own output tree, one directory per project key.
        output = workspace_file.parent / ".ash" / "ash_output" / "projects" / name
        output.mkdir(parents=True)
        results = output / "ash_aggregated_results.json"
        results.write_text("{}", encoding="utf-8")
        planted[name] = results

    async def start_then_cancel() -> None:
        task = asyncio.ensure_future(
            workspace_module.mcp_scan_workspace(
                workspace_file=str(workspace_file), clean_output=True
            )
        )
        await asyncio.to_thread(entered.wait, 30)
        if not entered.is_set():
            raise RuntimeError("control: the run never reached its execute step")
        still_in_place = [name for name, path in planted.items() if path.exists()]
        if still_in_place:
            # Without the set-aside the restore below would pass vacuously.
            raise RuntimeError(
                ("control: the previous results were not set aside", still_in_place)
            )
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(start_then_cancel())

    for name, results in planted.items():
        assert results.exists(), (
            "the cancelled run left the previous results set aside",
            name,
        )
    assert set(ash_log._ACTIVE_RUN_LOG_SCOPES) == before, (
        "the scan's log scope is still open"
    )
    assert ash_log.current_run_log_scope() is None


def test_a_workspace_run_that_fails_on_its_thread_leaves_no_scope_open(
    workspace_file, monkeypatch
):
    before = set(ash_log._ACTIVE_RUN_LOG_SCOPES)

    def a_run_that_breaks(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the run broke on its thread")

    monkeypatch.setattr(workspace_module, "execute_workspace", a_run_that_breaks)

    answer = asyncio.run(
        workspace_module.mcp_scan_workspace(workspace_file=str(workspace_file))
    )

    if answer.get("success") is not False:
        raise RuntimeError(("control: the run did not fail", answer))
    held = set(ash_log._ACTIVE_RUN_LOG_SCOPES) - before
    for scope in held:
        # The thread lets go after the answer: its settle runs past the await.
        assert _wait_until_closed(scope), "the scan's log scope is still open"
    assert ash_log.current_run_log_scope() is None
