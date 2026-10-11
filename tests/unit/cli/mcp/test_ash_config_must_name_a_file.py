# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash mcp`` refuses to start when ``ASH_CONFIG`` is not a config it can load.

``ASH_CONFIG`` is the operator's explicit policy for every scan the server runs
without a config of its own. The server loads it at startup the way it loads each
``--profile``. A value that names a missing path or a directory, a file the server
can't read, or a file that fails to parse or validate makes the server refuse to
start with exit 3 and an error naming the variable and the path, on every
transport. An unset or empty value keeps the built-in default.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path

import pytest
import typer
from rich.console import Console

from automated_security_helper.cli.mcp import mcp_command

_NO_POSIX_MODES = pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX file modes that the current user can't override",
)


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


@pytest.fixture
def restore_modes():
    """Give back the modes a test took away, so tmp_path can be removed."""
    changed: list[tuple[Path, int]] = []

    def take_away(path: Path) -> None:
        changed.append((path, path.stat().st_mode))
        path.chmod(0)

    yield take_away
    for path, mode in reversed(changed):
        path.chmod(mode)


@_NO_POSIX_MODES
@pytest.mark.parametrize("transport", ["stdio", "streamable-http", "sse"])
def test_a_config_file_the_server_cannot_read_refuses_startup(
    tmp_path, monkeypatch, stderr, started, restore_modes, transport
) -> None:
    config = tmp_path / "ash-config.yaml"
    config.write_text("project_name: operator-policy\n", encoding="utf-8")
    restore_modes(config)
    monkeypatch.setenv("ASH_CONFIG", str(config))

    with pytest.raises(typer.Exit) as excinfo:
        _start(transport)

    assert excinfo.value.exit_code == 3
    assert started == {}, "the server started"
    message = " ".join(stderr.getvalue().split())
    assert f"ASH_CONFIG={config}" in message, message
    assert "names no config file" not in message, message


@_NO_POSIX_MODES
def test_a_config_file_in_a_directory_the_server_cannot_search_refuses_startup(
    tmp_path, monkeypatch, stderr, started, restore_modes
) -> None:
    # Path.is_file raises PermissionError here on some Python versions and returns
    # False on others. The exit code and the message must not depend on which.
    locked = tmp_path / "locked"
    locked.mkdir()
    config = locked / "ash-config.yaml"
    config.write_text("project_name: operator-policy\n", encoding="utf-8")
    restore_modes(locked)
    monkeypatch.setenv("ASH_CONFIG", str(config))

    with pytest.raises(typer.Exit) as excinfo:
        _start("stdio")

    assert excinfo.value.exit_code == 3
    assert started == {}, "the server started"
    message = " ".join(stderr.getvalue().split())
    assert f"ASH_CONFIG={config}" in message, message
    assert "names no config file" not in message, message


@pytest.mark.parametrize(
    "content",
    [
        pytest.param("project_name: [1, 2]\n", id="refused-by-the-schema"),
        pytest.param("project_name: x\n  : : [\n", id="not-yaml"),
    ],
)
@pytest.mark.parametrize("transport", ["stdio", "streamable-http"])
def test_a_config_file_that_does_not_load_refuses_startup(
    tmp_path, monkeypatch, stderr, started, transport, content
) -> None:
    config = tmp_path / "ash-config.yaml"
    config.write_text(content, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))

    with pytest.raises(typer.Exit) as excinfo:
        _start(transport)

    assert excinfo.value.exit_code == 3
    assert started == {}, "the server started"
    message = " ".join(stderr.getvalue().split())
    assert f"ASH_CONFIG={config}" in message, message


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


@pytest.mark.parametrize(
    "variable", ["ASH_CONFIG", "ASH_MCP_TRANSPORT"], ids=["config", "transport"]
)
def test_running_the_server_module_makes_the_same_startup_checks(
    tmp_path, variable
) -> None:
    # `python -m automated_security_helper.cli.mcp_server` starts the stdio server
    # without `ash mcp` in front of it. It must refuse the same environment.
    env = {k: v for k, v in os.environ.items() if not k.startswith("ASH_MCP_")}
    env.pop("ASH_CONFIG", None)
    env["ASH_MCP_WORKSPACE_ROOT"] = str(tmp_path / "workspaces")
    if variable == "ASH_CONFIG":
        env["ASH_CONFIG"] = str(tmp_path / "missing.yaml")
    else:
        env["ASH_MCP_TRANSPORT"] = "no-such-transport"

    result = subprocess.run(
        [sys.executable, "-m", "automated_security_helper.cli.mcp_server"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        timeout=120,
    )

    assert result.returncode == 3, (result.returncode, result.stderr[-2000:])
    assert variable in result.stderr, result.stderr[-2000:]


def test_the_message_names_the_variable_and_the_path(
    tmp_path, monkeypatch, stderr, started
) -> None:
    missing: Path = tmp_path / "nowhere" / "policy.yaml"
    monkeypatch.setenv("ASH_CONFIG", str(missing))

    with pytest.raises(typer.Exit):
        _start("stdio")

    message = " ".join(stderr.getvalue().split())
    assert f"ASH_CONFIG={missing}" in message, message
