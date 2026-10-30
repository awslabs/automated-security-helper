# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refused scan start completes its session's deferred end off the loop, and answers.

``mcp_scan_directory`` gives a scan's claim back on two paths of its own: the
per-session limit refusal, and its outer finally for every start that made no
task (a start error, an output directory it could not create). Both completed
the end of a session that ended meanwhile through ``_release_what_the_scan_held``,
which runs ``sessions.finish_ended_session`` on the calling thread, the event
loop every session's tool calls share, and lets it raise. The runner's own
finally had already been moved off the loop for the same removal
(``_run_scan_async``) and the never-run callback guards the call, but the two
start paths did neither, so:

* a removal that failed at the limit refusal replaced the ``session_scan_limit``
  reply with an exception, and in the outer finally it replaced whatever the
  tool was returning (the ``output_dir_not_usable`` refusal, the exit-coded
  "Unexpected error starting scan" reply), so the client got an unhandled
  exception for a scan that was refused;
* the tree removal blocked every session's tool calls while it ran.

Now both paths await ``_release_what_the_scan_held_off_the_loop``: the claim and
the count are given back first, the removal runs on a worker thread, shielded,
and a failure is logged (redacted) instead of raised. The done callback keeps the
synchronous form, guarded, because a done callback cannot await.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path
from typing import Any, Dict, List

import pytest

pytestmark = pytest.mark.unit

SESSION = "client-one"


@pytest.fixture
def layout(tmp_path, monkeypatch) -> Dict[str, Path]:
    from automated_security_helper.cli.mcp import sessions, source_delivery
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_all_session_state,
        clear_profile_registry,
    )
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    monkeypatch.setattr(source_delivery, "_SESSION_SOURCE_DIRS", {})
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    clear_profile_registry()
    clear_all_session_state()
    sessions.reset_default_registry_for_tests()
    yield {"scan": scan, "tmp": tmp_path}
    sessions.reset_default_registry_for_tests()
    clear_profile_registry()
    clear_all_session_state()


@pytest.fixture
def at_the_limit(layout, monkeypatch):
    """A session already at a per-session limit of one, given back afterwards."""
    from automated_security_helper.cli.mcp import sessions

    operator = layout["tmp"] / "operator.yaml"
    operator.write_text(
        "project_name: operator\n"
        "mcp-resource-management:\n"
        "  max_concurrent_scans_per_session: 1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    session = sessions.get_default_registry().session_for(SESSION)
    assert session.try_start_scan(1)
    yield session
    session.scan_returned()


@pytest.fixture
def no_task(monkeypatch) -> None:
    """A loop that cannot start the scan's task: the start fails after the claim."""
    from automated_security_helper.cli import mcp_tools

    def cannot_start(scan_id, coroutine, **kwargs) -> None:
        coroutine.close()
        raise RuntimeError("the loop is gone")

    monkeypatch.setattr(mcp_tools, "_start_scan_task", cannot_start)


@pytest.fixture
def removal_fails(monkeypatch) -> List[Any]:
    """``finish_ended_session`` raises; the ids it was asked for are recorded."""
    from automated_security_helper.cli.mcp import sessions

    asked: List[Any] = []

    def cannot_remove(session_id) -> None:
        asked.append(session_id)
        raise OSError("Device or resource busy: the workspace")

    monkeypatch.setattr(sessions, "finish_ended_session", cannot_remove)
    return asked


@pytest.fixture
def removal_records_its_thread(monkeypatch) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp import sessions

    seen: Dict[str, Any] = {}

    def record(session_id) -> None:
        seen["thread"] = threading.get_ident()
        seen["session_id"] = session_id

    monkeypatch.setattr(sessions, "finish_ended_session", record)
    return seen


def _scan(**kwargs: Any) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    return asyncio.run(mcp_scan_directory(session_id=SESSION, **kwargs))


def _scan_recording_the_loop_thread(
    seen: Dict[str, Any], **kwargs: Any
) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    async def run() -> Dict[str, Any]:
        seen["loop_thread"] = threading.get_ident()
        return await mcp_scan_directory(session_id=SESSION, **kwargs)

    return asyncio.run(run())


class TestARefusalIsAnsweredWhenTheRemovalFails:
    def test_the_limit_refusal_is_still_the_reply(
        self, layout, at_the_limit, removal_fails, caplog
    ) -> None:
        with caplog.at_level(logging.ERROR):
            response = _scan(directory_path=str(layout["scan"]))

        assert response["error_type"] == "session_scan_limit", response
        assert response["success"] is False
        assert removal_fails == [SESSION], removal_fails
        assert any(
            "could not complete the end of its session" in record.getMessage()
            and "resource busy" in record.getMessage()
            for record in caplog.records
        ), [record.getMessage() for record in caplog.records]

    def test_a_start_that_fails_after_the_claim_is_still_answered(
        self, layout, no_task, removal_fails, caplog
    ) -> None:
        with caplog.at_level(logging.ERROR):
            response = _scan(directory_path=str(layout["scan"]))

        assert response["success"] is False, response
        assert "Unexpected error starting scan" in response["error"], response
        assert response["exit_code"] is not None
        assert removal_fails == [SESSION], removal_fails
        assert any(
            "could not complete the end of its session" in record.getMessage()
            for record in caplog.records
        ), [record.getMessage() for record in caplog.records]

    def test_the_claim_and_the_count_went_back_before_the_removal_failed(
        self, layout, no_task, removal_fails
    ) -> None:
        from automated_security_helper.cli.mcp import sessions

        _scan(directory_path=str(layout["scan"]))

        session = sessions.get_default_registry().session_for(SESSION)
        # No claim held: a change can begin. No count held: a limit of one admits.
        assert session.try_begin_change() is None, "the scan's claim is still held"
        session.end_change()
        assert session.try_start_scan(1), "the scan is still counted"
        session.scan_returned()


class TestTheRemovalRunsOffTheEventLoop:
    def test_at_the_limit_refusal(
        self, layout, at_the_limit, removal_records_its_thread
    ) -> None:
        response = _scan_recording_the_loop_thread(
            removal_records_its_thread, directory_path=str(layout["scan"])
        )

        assert response["error_type"] == "session_scan_limit", response
        seen = removal_records_its_thread
        assert seen["session_id"] == SESSION
        assert seen["thread"] != seen["loop_thread"], "the removal ran on the loop"

    def test_at_a_start_that_made_no_task(
        self, layout, no_task, removal_records_its_thread
    ) -> None:
        response = _scan_recording_the_loop_thread(
            removal_records_its_thread, directory_path=str(layout["scan"])
        )

        assert response["success"] is False, response
        seen = removal_records_its_thread
        assert seen["session_id"] == SESSION
        assert seen["thread"] != seen["loop_thread"], "the removal ran on the loop"


class TestControls:
    def test_a_caller_with_no_session_removes_nothing(
        self, layout, no_task, removal_fails
    ) -> None:
        """Nothing to complete for a caller the server could not identify."""
        from automated_security_helper.cli.mcp_tools import (
            UNIDENTIFIED_SESSION_ID,
            mcp_scan_directory,
        )

        response = asyncio.run(
            mcp_scan_directory(
                directory_path=str(layout["scan"]), session_id=UNIDENTIFIED_SESSION_ID
            )
        )

        assert response["success"] is False, response
        assert removal_fails == [], removal_fails

    def test_a_removal_that_succeeds_is_asked_once_and_logs_no_error(
        self, layout, at_the_limit, caplog
    ) -> None:
        from automated_security_helper.cli.mcp import sessions

        asked: List[Any] = []
        with (
            pytest.MonkeyPatch.context() as patch,
            caplog.at_level(logging.ERROR),
        ):
            patch.setattr(sessions, "finish_ended_session", asked.append)
            response = _scan(directory_path=str(layout["scan"]))

        assert response["error_type"] == "session_scan_limit", response
        assert asked == [SESSION], asked
        assert not [
            record
            for record in caplog.records
            if "could not complete the end of its session" in record.getMessage()
        ]
