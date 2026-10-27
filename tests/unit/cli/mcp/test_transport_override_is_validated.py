# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ASH_MCP_TRANSPORT`` is read case- and space-insensitively, and an unknown value fails closed.

The variable is the operator's override that makes every caller remote. A value
that names a network transport in any spelling (``Streamable-HTTP``, a stray
space) counts as one. Empty, or only whitespace, it is unset. An unknown value
such as ``http`` counts as remote for an in-process caller, and the server
refuses to start with it, exit 5 (a usage error), from ``ash mcp`` and from
``python -m automated_security_helper.cli.mcp_server`` alike.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys

import pytest
import typer
from rich.console import Console

from automated_security_helper.cli.mcp import mcp_command
from automated_security_helper.cli.mcp.sandbox import (
    caller_is_remote,
    get_server_transport,
)

UNKNOWN = ["http", "streamable_http", "stdi0", "tcp", "stream able-http", "sse,stdio"]


@pytest.mark.parametrize(
    "value", ["Streamable-HTTP", " sse ", "SSE", "STREAMABLE-HTTP\n"]
)
def test_a_network_transport_in_any_case_or_spacing_makes_callers_remote(
    monkeypatch, value
) -> None:
    monkeypatch.setenv("ASH_MCP_TRANSPORT", value)

    assert caller_is_remote(None) is True
    assert get_server_transport() == value.strip().lower()


@pytest.mark.parametrize("value", UNKNOWN)
def test_an_unknown_value_fails_closed(monkeypatch, value) -> None:
    monkeypatch.setenv("ASH_MCP_TRANSPORT", value)

    assert caller_is_remote(None) is True


@pytest.mark.parametrize("value", ["stdio", " STDIO ", "", "   ", "\n"])
def test_stdio_or_unset_keeps_the_local_default(monkeypatch, value) -> None:
    monkeypatch.setenv("ASH_MCP_TRANSPORT", value)

    assert caller_is_remote(None) is False


class _Ctx:
    resilient_parsing = False


@pytest.fixture
def stderr(monkeypatch) -> io.StringIO:
    buffer = io.StringIO()
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._stderr",
        Console(file=buffer, width=400, color_system=None),
    )
    return buffer


@pytest.fixture
def started(monkeypatch) -> dict:
    record: dict = {}
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._run_uvicorn",
        lambda *a, **k: record.update(server="http"),
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp_server.run_mcp_server",
        lambda: record.update(server="stdio"),
    )
    return record


@pytest.mark.parametrize("transport", ["stdio", "streamable-http", "sse"])
@pytest.mark.parametrize("value", UNKNOWN)
def test_the_server_refuses_to_start_with_an_unknown_value(
    monkeypatch, stderr, started, value, transport
) -> None:
    monkeypatch.setenv("ASH_MCP_TRANSPORT", value)

    with pytest.raises(typer.Exit) as excinfo:
        mcp_command(ctx=_Ctx(), transport=transport, host="127.0.0.1", quiet=True)

    assert excinfo.value.exit_code == 5
    assert started == {}, "the server started"
    message = " ".join(stderr.getvalue().split())
    assert "ASH_MCP_TRANSPORT" in message and repr(value) in message, message


def test_the_variable_is_reported_when_it_is_also_the_transport_flag(
    monkeypatch, stderr, started
) -> None:
    """The container entrypoint passes ASH_MCP_TRANSPORT as --transport as well."""
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "http")

    with pytest.raises(typer.Exit) as excinfo:
        mcp_command(ctx=_Ctx(), transport="http", host="127.0.0.1", quiet=True)

    assert excinfo.value.exit_code == 5
    assert started == {}, "the server started"
    assert "ASH_MCP_TRANSPORT" in stderr.getvalue()


@pytest.mark.parametrize(
    "value",
    [
        "stdio",
        "streamable-http",
        "sse",
        "STDIO",
        "Streamable-HTTP",
        "SSE",
        " sse\n",
        "\tstdio ",
        "",
        "   ",
    ],
)
def test_a_known_or_empty_value_starts(monkeypatch, started, value) -> None:
    monkeypatch.setenv("ASH_MCP_TRANSPORT", value)

    mcp_command(ctx=_Ctx(), transport="streamable-http", host="127.0.0.1", quiet=True)

    assert started.get("server") == "http"


@pytest.mark.parametrize("value", ["http", "Stdio-HTTP"])
def test_the_server_module_refuses_an_unknown_value_too(tmp_path, value) -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("ASH_MCP_")}
    env.pop("ASH_CONFIG", None)
    env["ASH_MCP_WORKSPACE_ROOT"] = str(tmp_path / "workspaces")
    env["ASH_MCP_TRANSPORT"] = value

    for argv in (
        [sys.executable, "-m", "automated_security_helper.cli.mcp_server"],
        [sys.executable, "-m", "automated_security_helper.cli.main", "mcp"],
    ):
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=env,
            cwd=tmp_path,
            timeout=120,
        )

        assert result.returncode == 5, (argv, result.returncode, result.stderr[-2000:])
        assert "ASH_MCP_TRANSPORT" in result.stderr, result.stderr[-2000:]
