# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every refusal of the MCP scan tools carries an exit code and its meaning.

Why this exists
---------------
A client branches on ``exit_code``, as a CI script branches on the CLI's status,
so every one of the scan tools' refusals has to carry one, not only a link in the
output tree and committed output: also a target outside the permitted
roots, a missing directory, an unusable severity, a refused or unusable config,
a refusal by the scan registry, an unexpected error. run_ash_scan must not relay
a scan_directory refusal as ``scan_start_failure``, which would drop its
``error_type`` and its code, and the workspace tools' refusals of a session or
an unexpected error need a code with a meaning.

Each refusal carries the code for what was refused: 3 for a config, 5 for
the request itself (a session header, a severity, a missing source_dir), 4 for a
target the server will not scan, 1 for anything else. Where the CLI refuses the
same thing, it exits with the same code, which the parity cells check.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest
from typer.testing import CliRunner

from automated_security_helper.core.constants import ASH_EXIT_CODES

pytestmark = pytest.mark.unit

CONFIG, TARGET, USAGE, INTERNAL = 3, 4, 5, 1
SESSION = "client-one"


@pytest.fixture
def layout(tmp_path, monkeypatch) -> Dict[str, Path]:
    from automated_security_helper.cli.mcp import source_delivery
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    # No session has delivered source here, whatever an earlier test in this
    # worker delivered: the process-wide map would otherwise answer for it.
    monkeypatch.setattr(source_delivery, "_SESSION_SOURCE_DIRS", {})
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "app.py").write_text("x = 1\n", encoding="utf-8")
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "ash.yaml").write_text("project_name: outside\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    return {"scan": scan, "outside": outside}


@pytest.fixture
def no_scan_runs(monkeypatch) -> list:
    """The scans the tools start; none runs."""
    from automated_security_helper.cli import mcp_tools

    started: list = []

    def record(scan_id, coroutine, **start_options) -> None:
        coroutine.close()
        started.append(scan_id)

    monkeypatch.setattr(mcp_tools, "_start_scan_task", record)
    return started


def _ctx(session_id: str = SESSION) -> MagicMock:
    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": session_id}
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    return ctx


def _assert_refused_with(response: Dict[str, Any], code: int) -> None:
    assert response["success"] is False, response
    assert response["exit_code"] == code, response
    assert response["exit_code_meaning"] == ASH_EXIT_CODES[code], response


def _scan_directory(**kwargs: Any) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    return asyncio.run(mcp_scan_directory(session_id=SESSION, **kwargs))


# ---------------------------------------------------------------------------
# scan_directory
# ---------------------------------------------------------------------------


def test_a_target_outside_the_roots(layout, no_scan_runs) -> None:
    _assert_refused_with(_scan_directory(directory_path=str(layout["outside"])), TARGET)


def test_a_missing_directory(layout, no_scan_runs) -> None:
    """The request named a directory that is not there: the CLI's usage error."""
    response = _scan_directory(directory_path=str(layout["scan"] / "missing"))
    _assert_refused_with(response, USAGE)


def test_a_source_that_is_not_a_directory(layout, no_scan_runs) -> None:
    response = _scan_directory(directory_path=str(layout["scan"] / "app.py"))
    _assert_refused_with(response, USAGE)


def test_an_unusable_severity(layout, no_scan_runs) -> None:
    response = _scan_directory(
        directory_path=str(layout["scan"]), severity_threshold="LOUD"
    )
    _assert_refused_with(response, USAGE)


def test_a_config_outside_the_roots(layout, no_scan_runs) -> None:
    response = _scan_directory(
        directory_path=str(layout["scan"]),
        config_path=str(layout["outside"] / "ash.yaml"),
    )
    _assert_refused_with(response, CONFIG)


def test_a_config_path_that_names_no_file(layout, no_scan_runs) -> None:
    response = _scan_directory(
        directory_path=str(layout["scan"]),
        config_path=str(layout["scan"] / "missing.yaml"),
    )
    _assert_refused_with(response, CONFIG)


def test_an_ash_config_that_names_no_file(
    layout, no_scan_runs, tmp_path, monkeypatch
) -> None:
    """The file ASH_CONFIG names gives the scan its limits and its base: one
    that does not exist refuses the scan as a config, as the CLI's scan exits 3,
    not as an unexpected error, and no scan starts or stays registered."""
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )

    monkeypatch.setenv("ASH_CONFIG", str(tmp_path / "operator-missing.yaml"))

    response = _scan_directory(directory_path=str(layout["scan"]))

    assert response.get("error_category") == "file_not_found", response
    _assert_refused_with(response, CONFIG)
    assert no_scan_runs == []
    # Refused before registration: a registered entry would hold the directory
    # against the next scan.
    assert get_scan_registry().list_scans() == []


@pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permission bits, which root reads past",
)
def test_an_ash_config_that_cannot_be_read(
    layout, no_scan_runs, tmp_path, monkeypatch
) -> None:
    """An unreadable ASH_CONFIG refuses the scan as a config, exit 3, like a
    file that does not exist: not an error that escapes the tool."""
    operator = tmp_path / "operator-unreadable.yaml"
    operator.write_text("project_name: operator\n", encoding="utf-8")
    operator.chmod(0)
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    try:
        response = _scan_directory(directory_path=str(layout["scan"]))
    finally:
        operator.chmod(0o600)

    _assert_refused_with(response, CONFIG)
    assert no_scan_runs == []


def test_a_workspace_scan_with_an_ash_config_that_names_no_file(
    layout, tmp_path, monkeypatch
) -> None:
    """The workspace scan tool answers the same refused ASH_CONFIG the same way
    scan_directory does: a config refusal with exit 3, not an unexpected error
    with exit 1."""
    import json

    from automated_security_helper.cli.mcp import workspace as workspace_module

    monkeypatch.setenv("ASH_CONFIG", str(tmp_path / "operator-missing.yaml"))
    root = layout["scan"]
    (root / "api").mkdir()
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace = root / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    executed: list = []
    monkeypatch.setattr(
        workspace_module,
        "execute_workspace",
        lambda *args, **kwargs: executed.append(args),
    )

    response = asyncio.run(
        workspace_module.mcp_scan_workspace(workspace_file=str(workspace))
    )

    _assert_refused_with(response, CONFIG)
    assert executed == []


@pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permission bits, which root reads past",
)
def test_a_workspace_scan_with_an_ash_config_that_cannot_be_read(
    layout, tmp_path, monkeypatch
) -> None:
    """The same for an ASH_CONFIG the server cannot read: a config refusal with
    exit 3 from the workspace tool too, and no error escapes it."""
    import json

    from automated_security_helper.cli.mcp import workspace as workspace_module

    operator = tmp_path / "operator-unreadable.yaml"
    operator.write_text("project_name: operator\n", encoding="utf-8")
    operator.chmod(0)
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    root = layout["scan"]
    (root / "api").mkdir()
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace = root / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    executed: list = []
    monkeypatch.setattr(
        workspace_module,
        "execute_workspace",
        lambda *args, **kwargs: executed.append(args),
    )

    try:
        response = asyncio.run(
            workspace_module.mcp_scan_workspace(workspace_file=str(workspace))
        )
    finally:
        operator.chmod(0o600)

    _assert_refused_with(response, CONFIG)
    assert executed == []


@pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permission bits, which root reads past",
)
def test_both_scan_tools_put_an_unreadable_ash_config_in_one_category(
    layout, no_scan_runs, tmp_path, monkeypatch
) -> None:
    """A client that branches on ``error_category`` reads the same category for
    the same unreadable ASH_CONFIG from either scan tool."""
    import json

    from automated_security_helper.cli.mcp import workspace as workspace_module

    operator = tmp_path / "operator-unreadable.yaml"
    operator.write_text("project_name: operator\n", encoding="utf-8")
    operator.chmod(0)
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    root = layout["scan"]
    (root / "api").mkdir()
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace = root / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    monkeypatch.setattr(
        workspace_module, "execute_workspace", lambda *args, **kwargs: None
    )

    try:
        single = _scan_directory(directory_path=str(root))
        multi = asyncio.run(
            workspace_module.mcp_scan_workspace(workspace_file=str(workspace))
        )
    finally:
        operator.chmod(0o600)

    _assert_refused_with(single, CONFIG)
    _assert_refused_with(multi, CONFIG)
    assert single["error_category"] == multi["error_category"], (single, multi)


def test_a_discovered_config_outside_the_roots(layout, no_scan_runs) -> None:
    link = layout["scan"] / ".ash" / ".ash.yaml"
    link.parent.mkdir()
    link.symlink_to(layout["outside"] / "ash.yaml")
    _assert_refused_with(_scan_directory(directory_path=str(layout["scan"])), CONFIG)


def test_a_registry_refusal(layout, no_scan_runs) -> None:
    """A directory another scan holds."""
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )

    get_scan_registry().register_scan(
        directory_path=str(layout["scan"]),
        output_directory=str(layout["scan"] / ".ash" / "ash_output"),
    )
    _assert_refused_with(_scan_directory(directory_path=str(layout["scan"])), INTERNAL)


def test_an_unexpected_error(layout, no_scan_runs, monkeypatch) -> None:
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    def broken(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("the registry broke")

    monkeypatch.setattr(scan_registry_module.ScanRegistry, "register_scan", broken)
    _assert_refused_with(_scan_directory(directory_path=str(layout["scan"])), INTERNAL)


# ---------------------------------------------------------------------------
# run_ash_scan
# ---------------------------------------------------------------------------


def _run_ash_scan(ctx: MagicMock, **kwargs: Any) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_server import run_ash_scan

    return asyncio.run(run_ash_scan(ctx=ctx, **kwargs))


def test_run_ash_scan_with_an_unusable_session_header(layout, no_scan_runs) -> None:
    response = _run_ash_scan(_ctx("../not-a-session"), source_dir=str(layout["scan"]))
    _assert_refused_with(response, USAGE)


def test_run_ash_scan_with_no_source_dir_and_nothing_delivered(
    layout, no_scan_runs
) -> None:
    _assert_refused_with(_run_ash_scan(_ctx()), USAGE)


def test_run_ash_scan_with_a_config_outside_the_roots(layout, no_scan_runs) -> None:
    response = _run_ash_scan(
        _ctx(),
        source_dir=str(layout["scan"]),
        config_path=str(layout["outside"] / "ash.yaml"),
    )
    _assert_refused_with(response, CONFIG)


def test_run_ash_scan_with_a_target_outside_the_roots(layout, no_scan_runs) -> None:
    response = _run_ash_scan(_ctx(), source_dir=str(layout["outside"]))
    _assert_refused_with(response, TARGET)


def test_run_ash_scan_passes_a_scan_directory_refusal_on_unchanged(
    layout, no_scan_runs
) -> None:
    """Relayed as it came: its error_type and its code, not scan_start_failure."""
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )

    get_scan_registry().register_scan(
        directory_path=str(layout["scan"]),
        output_directory=str(layout["scan"] / ".ash" / "ash_output"),
    )
    direct = _scan_directory(directory_path=str(layout["scan"]))
    relayed = _run_ash_scan(_ctx(), source_dir=str(layout["scan"]))

    _assert_refused_with(relayed, INTERNAL)
    assert relayed["error_type"] == direct["error_type"] != "scan_start_failure"


def test_run_ash_scan_on_an_unexpected_error(layout, no_scan_runs, monkeypatch) -> None:
    from automated_security_helper.cli import mcp_server

    monkeypatch.setattr(
        mcp_server,
        "mcp_scan_directory",
        AsyncMock(side_effect=RuntimeError("the scan tool broke")),
    )
    response = _run_ash_scan(_ctx(), source_dir=str(layout["scan"]))
    _assert_refused_with(response, INTERNAL)


# ---------------------------------------------------------------------------
# The workspace tools
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["resolve_ash_workspace", "run_ash_workspace_scan"])
def test_a_workspace_tool_with_an_unusable_session_header(layout, tool) -> None:
    from automated_security_helper.cli import mcp_server

    response = asyncio.run(
        getattr(mcp_server, tool)(
            ctx=_ctx("../not-a-session"),
            workspace_file=str(layout["scan"] / "dev.code-workspace"),
        )
    )
    _assert_refused_with(response, USAGE)


@pytest.mark.parametrize(
    "tool, inner",
    [
        ("resolve_ash_workspace", "mcp_resolve_workspace"),
        ("run_ash_workspace_scan", "mcp_scan_workspace"),
    ],
)
def test_a_workspace_tool_on_an_unexpected_error(
    layout, monkeypatch, tool, inner
) -> None:
    from automated_security_helper.cli import mcp_server

    monkeypatch.setattr(
        mcp_server, inner, AsyncMock(side_effect=RuntimeError("it broke"))
    )
    response = asyncio.run(
        getattr(mcp_server, tool)(
            ctx=_ctx(), workspace_file=str(layout["scan"] / "dev.code-workspace")
        )
    )
    _assert_refused_with(response, INTERNAL)


# ---------------------------------------------------------------------------
# get_config
# ---------------------------------------------------------------------------


def _get_config(ctx: MagicMock, **kwargs: Any) -> Dict[str, Any]:
    from automated_security_helper.cli import mcp_server

    return asyncio.run(mcp_server.get_config(ctx, **kwargs))


def test_get_config_with_a_config_outside_the_roots(layout) -> None:
    response = _get_config(_ctx(), config_path=str(layout["outside"] / "ash.yaml"))

    assert response["error_type"] == "config_input_not_permitted", response
    _assert_refused_with(response, CONFIG)


def test_get_config_with_an_operator_config_that_does_not_validate(
    layout, tmp_path, monkeypatch
) -> None:
    operator = tmp_path / "operator.yaml"
    operator.write_text("global_settings:\n  severity_threshold: LOUD\n", "utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    config = layout["scan"] / ".ash.yaml"
    config.write_text("project_name: scan\n", encoding="utf-8")

    response = _get_config(_ctx(), config_path=str(config))

    assert response["error_category"] == "invalid_format", response
    _assert_refused_with(response, CONFIG)


@pytest.mark.parametrize("named", [True, False], ids=["named", "none named"])
def test_get_config_with_an_operator_config_that_does_not_exist(
    layout, tmp_path, monkeypatch, named
) -> None:
    """ASHConfigFileNotFoundError is the "not found" core/exceptions.py makes
    it for: get_config says file_not_found, not invalid_format."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    monkeypatch.setenv("ASH_CONFIG", str(tmp_path / "operator-missing.yaml"))
    if named:
        config = layout["scan"] / ".ash.yaml"
        config.write_text("project_name: scan\n", encoding="utf-8")
        response = _get_config(_ctx(), config_path=str(config))
    else:
        response = mcp_get_config(search_dir=str(layout["scan"]), session_id=SESSION)

    assert response.get("error_category") == "file_not_found", response
    _assert_refused_with(response, CONFIG)


def test_get_config_with_an_unusable_session_header(layout) -> None:
    _assert_refused_with(_get_config(_ctx("../not-a-session")), USAGE)


def test_get_config_on_an_unexpected_error(layout, monkeypatch) -> None:
    from automated_security_helper.cli import mcp_server

    def _broken(**_kwargs: Any) -> Dict[str, Any]:
        raise RuntimeError("it broke")

    monkeypatch.setattr(mcp_server, "mcp_get_config", _broken)

    _assert_refused_with(_get_config(_ctx()), INTERNAL)


# ---------------------------------------------------------------------------
# Parity with the CLI
# ---------------------------------------------------------------------------


def test_parity_a_config_path_that_names_no_file(layout, no_scan_runs, monkeypatch):
    from automated_security_helper.cli.main import app

    monkeypatch.chdir(layout["scan"])
    cli = CliRunner().invoke(app, ["config", "validate", "--config", "missing.yaml"])
    mcp = _scan_directory(
        directory_path=str(layout["scan"]),
        config_path=str(layout["scan"] / "missing.yaml"),
    )

    assert cli.exit_code == mcp["exit_code"] == CONFIG, (cli.output, mcp)


def test_parity_an_unusable_option_value(layout, no_scan_runs, monkeypatch):
    from automated_security_helper.cli.main import app

    monkeypatch.chdir(layout["scan"])
    cli = CliRunner().invoke(app, ["scan", "--min-severity", "loud"])
    mcp = _scan_directory(directory_path=str(layout["scan"]), severity_threshold="LOUD")

    assert cli.exit_code == mcp["exit_code"] == USAGE, (cli.output, mcp)


@pytest.mark.parametrize("name", ["missing", "app.py"], ids=["missing", "a file"])
def test_parity_a_source_dir_that_is_not_a_directory(
    layout, no_scan_runs, monkeypatch, name
):
    from automated_security_helper.cli.main import app

    monkeypatch.chdir(layout["scan"])
    source = layout["scan"] / name
    cli = CliRunner().invoke(app, ["scan", "--source-dir", str(source)])
    mcp = _scan_directory(directory_path=str(source))

    assert cli.exit_code == mcp["exit_code"] == USAGE, (cli.output, mcp)
