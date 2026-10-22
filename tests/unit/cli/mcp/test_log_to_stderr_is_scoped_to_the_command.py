# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash mcp`` sends ASH's console log to stderr while it runs, and only then.

The MCP server runs scans in-process, and ``get_logger`` reads
``ASH_LOG_TO_STDERR`` to choose where its console handler writes. On the stdio
transport stdout is the JSON-RPC stream, so the command has to set it before any
scan can start.

Set with ``set_environ`` and never put back, it would reach every later
``get_logger`` call in the same process -- another command in a long-lived host,
or the next test on an xdist worker -- and each would build a stderr console:
console tests reading captured stdout would find it empty whenever an mcp test
had run earlier in the worker (63 failures in two console modules, measured).

The variable is set for the call and put back on every way out: a normal
return, ``typer.Exit``, an exception and ``KeyboardInterrupt``. A value that was
there before comes back as it was, and one that was not is removed again.

The exit codes on these paths belong to other tests; these assert only on the
variable.
"""

import logging
import os
from unittest.mock import MagicMock, patch

import pytest
import typer

from automated_security_helper.cli.mcp import mcp_command
from automated_security_helper.utils.log import get_logger
from tests.utils.env_assertions import environ_value

_VAR = "ASH_LOG_TO_STDERR"
_DEPS = "automated_security_helper.cli.mcp.validate_mcp_dependencies"
_STDIO_SERVER = "automated_security_helper.cli.mcp_server.run_mcp_server"


@pytest.fixture(params=[None, "no"], ids=["unset", "preset"])
def before(request, monkeypatch):
    """The variable's value before the command: absent, or one it does not set."""
    if request.param is None:
        monkeypatch.delenv(_VAR, raising=False)
    else:
        monkeypatch.setenv(_VAR, request.param)
    return request.param


def _ctx():
    ctx = MagicMock(spec=typer.Context)
    ctx.resilient_parsing = False
    return ctx


def _invoke(**kwargs) -> None:
    """Run the command to whatever end it reaches; the exit is not under test."""
    try:
        mcp_command(_ctx(), **kwargs)
    except (typer.Exit, KeyboardInterrupt, Exception):
        pass


def _recording_server(seen: list, raises=None):
    def serve(*args, **kwargs):
        seen.append(os.environ.get(_VAR))
        if raises is not None:
            raise raises

    return serve


@pytest.mark.parametrize(
    "raises",
    [None, RuntimeError("server failed"), KeyboardInterrupt()],
    ids=["returns", "raises", "interrupted"],
)
def test_the_stdio_server_runs_with_the_switch_and_it_is_put_back(before, raises):
    seen: list = []
    with (
        patch(_DEPS, return_value=True),
        patch(_STDIO_SERVER, side_effect=_recording_server(seen, raises)),
    ):
        _invoke(quiet=True)

    assert seen == ["1"], "the server must run with its log on stderr"
    assert environ_value(_VAR) == before


def test_an_http_server_runs_with_the_switch_and_it_is_put_back(before):
    seen: list = []
    with (
        patch(_DEPS, return_value=True),
        patch("automated_security_helper.cli.mcp.build_streamable_http_app"),
        patch(
            "automated_security_helper.cli.mcp._run_uvicorn",
            side_effect=_recording_server(seen),
        ),
    ):
        _invoke(quiet=True, transport="streamable-http")

    assert seen == ["1"]
    assert environ_value(_VAR) == before


@pytest.mark.parametrize(
    "outcome",
    [
        {"return_value": False},
        {"side_effect": KeyboardInterrupt()},
        {"side_effect": RuntimeError("import check failed")},
    ],
    ids=["missing-dependencies", "interrupted", "raises"],
)
def test_it_is_put_back_when_the_command_stops_before_serving(before, outcome):
    with (
        patch(_DEPS, **outcome),
        patch(_STDIO_SERVER) as server,
    ):
        _invoke(quiet=True)

    server.assert_not_called()
    assert environ_value(_VAR) == before


def test_it_is_put_back_after_a_validation_error(before):
    with patch(_DEPS, return_value=True), patch(_STDIO_SERVER) as server:
        _invoke(quiet=True, transport="not-a-transport")

    server.assert_not_called()
    assert environ_value(_VAR) == before


def test_a_logger_built_after_the_command_writes_to_stdout_again(monkeypatch, capsys):
    """The symptom itself, in one process: an mcp run, then a console logger."""
    monkeypatch.delenv(_VAR, raising=False)
    with patch(_DEPS, return_value=True), patch(_STDIO_SERVER):
        _invoke(quiet=True)
    capsys.readouterr()

    logger = get_logger(
        name="ash-after-the-mcp-command", level=logging.INFO, show_progress=False
    )
    try:
        logger.info("RECORD-AFTER-MCP")
    finally:
        logger.handlers.clear()

    captured = capsys.readouterr()
    assert "RECORD-AFTER-MCP" in captured.out, (
        "a logger configured after `ash mcp` returned still writes to stderr: the "
        f"command left {_VAR} set"
    )
