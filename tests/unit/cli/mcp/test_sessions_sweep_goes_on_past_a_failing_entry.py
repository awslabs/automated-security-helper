# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The TTL sweep names a workspace it could not remove and goes on to the rest.

One stale workspace whose removal raised used to end the whole pass: the
exception left the loop, every later entry stayed unread, and nothing said
which session had stopped it. A removal that failed inside its own handling
(a file another account owns, a filesystem error) returned False with no
record at all, so a workspace that kept failing was never seen by anyone. The
sweep now treats each workspace's failure as that workspace's: it logs a
warning naming the session, keeps the workspace for the next pass, and removes
the others.
"""

from __future__ import annotations

import errno
import logging
import time
from pathlib import Path
from typing import Iterator, List

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

FAILING = "failing-session"
OTHER = "other-session"


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Iterator[Path]:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()
    # The sweep warns once per session id until a pass removes it, and the
    # latch is module state: a failure this test leaves behind would silence
    # the next test's warning for the same id.
    sessions._sweep_failures_warned.clear()
    yield workspace
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()
    sessions._sweep_failures_warned.clear()


@pytest.fixture
def logged() -> Iterator[_Collect]:
    handler = _Collect()
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


def _workspace(root: Path, session_id: str) -> Path:
    sandbox = mark_session_workspace(root / session_id)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("x = 1\n", encoding="utf-8")
    return sandbox


def _warnings_naming(handler: _Collect, session_id: str) -> List[str]:
    return [
        record.getMessage()
        for record in handler.records
        if record.levelno >= logging.WARNING and repr(session_id) in record.getMessage()
    ]


def test_a_removal_that_raises_is_named_and_the_sweep_goes_on(
    root, monkeypatch, logged
) -> None:
    workspaces = {FAILING: _workspace(root, FAILING), OTHER: _workspace(root, OTHER)}
    real = sessions._remove_stale_session_state
    failed: List[str] = []

    def failing_removal(root_, session_id, sandbox, cutoff):
        # The FIRST entry the sweep visits fails, whatever its name: the sweep
        # walks the root in the filesystem's order, so a sweep that stopped at
        # the failure would pass whenever the other entry happened to come first.
        if not failed:
            failed.append(session_id)
            raise ValueError("the registry refused this name")
        return real(root_, session_id, sandbox, cutoff)

    monkeypatch.setattr(sessions, "_remove_stale_session_state", failing_removal)

    # A cutoff in the future: both workspaces are older than the TTL.
    removed = sessions.sweep_stale_workspaces(1.0, now=time.time() + 3600)

    assert failed, "no removal was attempted"
    (survivor,) = set(workspaces) - {failed[0]}
    assert removed == [survivor], "the sweep did not continue past the failing entry"
    assert not workspaces[survivor].exists()
    assert workspaces[failed[0]].is_dir(), (
        "the failing workspace was not kept for the next pass"
    )
    named = _warnings_naming(logged, failed[0])
    assert len(named) == 1, f"expected one warning naming the session; got {named}"
    assert "next pass" in named[0]


def test_a_removal_that_fails_inside_its_handling_is_named(
    root, monkeypatch, logged
) -> None:
    failing = _workspace(root, FAILING)

    # The step the sweep's handling runs under its guard for a session with a
    # workspace (the rename aside, the dropping of the session's state); a
    # session with none takes _remove_session_state, which this sweep does not.
    def refused(session_id, sandbox):
        raise OSError(errno.EACCES, "Permission denied", str(failing))

    monkeypatch.setattr(sessions, "_set_session_state_aside", refused)

    removed = sessions.sweep_stale_workspaces(1.0, now=time.time() + 3600)

    assert removed == []
    assert failing.is_dir(), "the workspace was removed although the removal failed"
    named = _warnings_naming(logged, FAILING)
    assert len(named) == 1, f"expected one warning naming the session; got {named}"
    assert "next pass" in named[0]


def test_a_clean_sweep_logs_no_removal_warning(root, logged) -> None:
    """The control: a removal that succeeds names nothing."""
    _workspace(root, OTHER)

    removed = sessions.sweep_stale_workspaces(1.0, now=time.time() + 3600)

    assert removed == [OTHER]
    assert _warnings_naming(logged, OTHER) == []
