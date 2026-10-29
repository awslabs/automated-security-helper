#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An HTTP server whose application fails to start is a failed command.

uvicorn returns from ``Server.run()`` when the app's lifespan startup fails, having
logged the failure itself and started nothing. ``_run_uvicorn`` returned with it,
and the process exited 0 as a server that had served and been asked to stop. The
runner now raises when the server never started and no signal stopped it, which
the command reports as a failed server, exit 1.
"""

from __future__ import annotations

from typing import Any, List
from unittest.mock import patch

import pytest

from automated_security_helper.cli import mcp as mcp_cli
from automated_security_helper.core.enums import AshLogLevel

pytestmark = pytest.mark.unit


async def _no_app(scope, receive, send) -> None:
    """An ASGI app for a Config that is loaded and never served."""


class _ServerThatNeverStarts:
    """uvicorn's Server as it returns from a run whose startup failed."""

    def __init__(self, config: Any) -> None:
        self.config = config
        self.started = False
        self.should_exit = False
        self.force_exit = False

    def run(self, sockets=None) -> None:
        return None


class _ServerThatServed(_ServerThatNeverStarts):
    def run(self, sockets=None) -> None:
        self.started = True


def _run_with(server_class) -> List[str]:
    calls: List[str] = []
    with (
        patch.object(mcp_cli, "_uvicorn_server_class", return_value=server_class),
        patch.object(mcp_cli, "_note_the_signal_that_stops"),
        patch.object(
            mcp_cli, "_ask_server_to_stop_on_sighup", return_value=lambda: None
        ),
        patch("automated_security_helper.utils.log.check_commands_of_stderr"),
        patch("automated_security_helper.utils.log.check_commands_of_stdout"),
        patch(
            "automated_security_helper.utils.log.route_library_handlers_through_command_check"
        ),
        patch(
            "automated_security_helper.utils.subprocess_utils.kill_running_groups",
            side_effect=lambda: calls.append("kill_running_groups") or 0,
        ),
    ):
        mcp_cli._run_uvicorn(
            _no_app, host="127.0.0.1", port=43210, log_level=AshLogLevel.INFO
        )
    return calls


def test_a_server_that_never_started_raises():
    """Red at the base: ``_run_uvicorn`` returned and the command exited 0."""
    with pytest.raises(RuntimeError, match="did not start"):
        _run_with(_ServerThatNeverStarts)


def test_a_server_that_served_returns():
    """Control: a server that started and was stopped is the normal return."""
    calls = _run_with(_ServerThatServed)

    assert calls == ["kill_running_groups"]


def test_a_server_stopped_by_a_signal_before_starting_does_not_raise(monkeypatch):
    """Control: the signal's own exit status applies, not a startup failure."""
    import signal

    monkeypatch.setattr(mcp_cli, "_stop_signal", signal.SIGTERM)

    _run_with(_ServerThatNeverStarts)
