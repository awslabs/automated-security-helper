# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each sweep pass that meets the held presence guard starts no second thread.

A pending end the sweep could not finish is completed on a thread of its own
(``_complete_a_pending_end_off_the_sweep``), which waits for the presence guard
for as long as another server keeps it. The sweep runs again and again while the
guard stays held, and every pass that met it for the same pending session used to
start one more thread blocked on the same guard. One thread per pending end is
enough: a pass that finds one in flight starts none, and once it has finished a
later pass that finds the end pending again starts a new one.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, Iterator

import pytest

from automated_security_helper.cli.mcp import sessions

pytestmark = pytest.mark.unit

STALE = "stale-session"
_SLACK_SECONDS = 5.0
_THREAD_NAME = f"ash-mcp-finish-ended-session-{STALE}"


@pytest.fixture(autouse=True)
def clean_state(tmp_path, monkeypatch) -> Iterator[None]:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()
    yield
    sessions._ended_while_scanning.clear()
    sessions.reset_default_registry_for_tests()


def _join_completion_threads() -> None:
    for thread in threading.enumerate():
        if thread.name == _THREAD_NAME:
            thread.join(_SLACK_SECONDS)


@pytest.fixture
def blocked_finish(monkeypatch) -> Iterator[Dict[str, Any]]:
    """``finish_ended_session`` stood in for: it records each call and waits."""
    seen: Dict[str, Any] = {
        "calls": [],
        "entered": threading.Event(),
        "release": threading.Event(),
    }

    def record(session_id: str) -> None:
        seen["calls"].append(session_id)
        seen["entered"].set()
        seen["release"].wait(_SLACK_SECONDS * 4)

    monkeypatch.setattr(sessions, "finish_ended_session", record)
    yield seen
    seen["release"].set()
    _join_completion_threads()


def test_a_second_pass_starts_no_second_thread_for_the_same_pending_end(
    blocked_finish,
) -> None:
    sessions._ended_while_scanning.add(STALE)

    sessions._complete_a_pending_end_off_the_sweep(STALE)
    assert blocked_finish["entered"].wait(_SLACK_SECONDS), "no thread was started"
    sessions._complete_a_pending_end_off_the_sweep(STALE)
    sessions._complete_a_pending_end_off_the_sweep(STALE)
    blocked_finish["release"].set()
    _join_completion_threads()

    assert blocked_finish["calls"] == [STALE], blocked_finish["calls"]


def test_a_pass_after_the_thread_has_finished_starts_a_new_one(
    blocked_finish,
) -> None:
    """The control: the guard on a second thread is the one in flight, not a
    record that the end was once completed."""
    sessions._ended_while_scanning.add(STALE)
    blocked_finish["release"].set()

    sessions._complete_a_pending_end_off_the_sweep(STALE)
    _join_completion_threads()
    sessions._complete_a_pending_end_off_the_sweep(STALE)
    _join_completion_threads()

    assert blocked_finish["calls"] == [STALE, STALE], blocked_finish["calls"]
