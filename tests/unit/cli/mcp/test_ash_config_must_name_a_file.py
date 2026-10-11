# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash mcp`` refuses to start when ``ASH_CONFIG`` names no config file.

``ASH_CONFIG`` is the operator's explicit policy for every scan the server runs
without a config of its own. A value that names a missing path, or a directory,
makes the server refuse to start with exit 3 and an error naming the variable and
the path, on every transport. An unset or empty value keeps the built-in default.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
import typer
from rich.console import Console

from automated_security_helper.cli.mcp import mcp_command


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
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._run_uvicorn",
        lambda *a, **k: record.update(server="http"),
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp_server.run_mcp_server",
        lambda: record.update(server="stdio"),
    )
    return record


def _start(transport: str) -> None:
    mcp_command(ctx=_Ctx(), transport=transport, host="127.0.0.1", quiet=True)


@pytest.mark.parametrize("transport", ["stdio", "streamable-http", "sse"])
@pytest.mark.parametrize("kind", ["missing", "directory"])
def test_a_path_that_is_no_config_file_refuses_startup(
    tmp_path, monkeypatch, stderr, started, transport, kind
) -> None:
    target = tmp_path / "ash-config.yaml"
    if kind == "directory":
        target.mkdir()
    monkeypatch.setenv("ASH_CONFIG", str(target))

    with pytest.raises(typer.Exit) as excinfo:
        _start(transport)

    assert excinfo.value.exit_code == 3
    assert started == {}, "the server started"
    message = stderr.getvalue()
    assert "ASH_CONFIG" in message, message
    assert str(target) in message, message


def test_an_existing_config_file_starts(tmp_path, monkeypatch, started) -> None:
    config = tmp_path / "ash-config.yaml"
    config.write_text("project_name: operator-policy\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))

    _start("stdio")

    assert started.get("server") == "stdio"


@pytest.mark.parametrize("value", [None, ""])
def test_no_ash_config_keeps_the_built_in_default(monkeypatch, started, value) -> None:
    if value is None:
        monkeypatch.delenv("ASH_CONFIG", raising=False)
    else:
        monkeypatch.setenv("ASH_CONFIG", value)

    _start("stdio")

    assert started.get("server") == "stdio"


def test_the_ash_command_line_refuses_too(tmp_path, monkeypatch, started) -> None:
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app as ash_app

    monkeypatch.setenv("ASH_CONFIG", str(tmp_path / "missing.yaml"))

    result = CliRunner().invoke(ash_app, ["mcp"])

    assert result.exit_code == 3, result.output
    assert started == {}, "the server started"


def test_the_message_names_the_variable_and_the_path(
    tmp_path, monkeypatch, stderr, started
) -> None:
    missing: Path = tmp_path / "nowhere" / "policy.yaml"
    monkeypatch.setenv("ASH_CONFIG", str(missing))

    with pytest.raises(typer.Exit):
        _start("stdio")

    message = " ".join(stderr.getvalue().split())
    assert f"ASH_CONFIG={missing}" in message, message
