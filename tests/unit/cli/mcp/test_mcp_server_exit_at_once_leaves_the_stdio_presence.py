# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stdio server that exits on SIGTERM, SIGHUP or Ctrl-C still leaves its entry.

Those signals end the server through exit_at_once, whose os._exit skips
run_mcp_server's finally, so StdioServerPresence.__exit__ never ran: the dead
entry stayed in the registry and the default workspace stayed on disk when this
was the last stdio server. run_mcp_server now hands its presence to
exit_at_once, which leaves it before the process ends, and releases it on the
way out so a return leaves it once.
"""

from __future__ import annotations

from typing import Any, List
from unittest.mock import patch

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp.sessions import StdioServerPresence

pytestmark = pytest.mark.unit


class _Presence:
    def __init__(self, failing: bool = False) -> None:
        self.exits: List[Any] = []
        self.failing = failing

    def __exit__(self, *exc_info: object) -> None:
        self.exits.append(exc_info)
        if self.failing:
            raise RuntimeError("the registry lock was refused")


@pytest.fixture
def exits(monkeypatch) -> List[int]:
    """exit_at_once's process end, recorded instead of taken."""
    recorded: List[int] = []
    monkeypatch.setattr(mcp_server.os, "_exit", recorded.append)
    monkeypatch.setattr(mcp_server.logging, "shutdown", lambda: None)
    monkeypatch.setattr(mcp_server, "kill_running_groups", lambda: None)
    return recorded


def test_exit_at_once_leaves_the_presence_entry(monkeypatch, exits) -> None:
    presence = _Presence()
    monkeypatch.setattr(mcp_server, "_stdio_presence", presence, raising=False)

    mcp_server.exit_at_once(0)

    # Red before the fix: nothing left the entry; the process just ended.
    assert presence.exits == [(None, None, None)], presence.exits
    assert exits == [0]


def test_leaving_the_presence_twice_leaves_the_entry_once(monkeypatch) -> None:
    """Red at the base: the entry stayed on the module after it was left, so a
    second signal in the shutdown window (SIGTERM, then SIGHUP or Ctrl-C) left
    it again, a second ``__exit__`` on a presence already gone."""
    presence = _Presence()
    monkeypatch.setattr(mcp_server, "_stdio_presence", presence, raising=False)

    mcp_server._leave_stdio_presence()
    mcp_server._leave_stdio_presence()

    assert presence.exits == [(None, None, None)], presence.exits
    assert mcp_server._stdio_presence is None


def test_exit_at_once_with_no_presence_still_exits(monkeypatch, exits) -> None:
    monkeypatch.setattr(mcp_server, "_stdio_presence", None, raising=False)

    mcp_server.exit_at_once(130)

    assert exits == [130]


def test_a_failing_presence_exit_does_not_stop_the_exit(monkeypatch, exits) -> None:
    presence = _Presence(failing=True)
    monkeypatch.setattr(mcp_server, "_stdio_presence", presence, raising=False)

    mcp_server.exit_at_once(0)

    assert presence.exits, "the entry was not even tried"
    assert exits == [0]


def test_run_mcp_server_hands_its_presence_to_exit_at_once_while_serving(
    monkeypatch,
) -> None:
    seen: List[Any] = []
    left: List[Any] = []

    def serving(fn) -> None:
        seen.append(getattr(mcp_server, "_stdio_presence", None))

    monkeypatch.setattr(mcp_server.anyio, "run", serving)
    with (
        patch.object(StdioServerPresence, "__enter__", lambda self: self),
        patch.object(
            StdioServerPresence, "__exit__", lambda self, *exc: left.append(self)
        ),
    ):
        mcp_server.run_mcp_server()

    # Red before the fix: nothing was handed over, so exit_at_once saw None.
    assert len(seen) == 1 and isinstance(seen[0], StdioServerPresence), seen
    assert left == seen, "the finally left a different presence, or none"
    assert getattr(mcp_server, "_stdio_presence", None) is None
