# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""MCP scan_directory checks a named config once, and refuses one that does not validate.

Before a scan is registered, scan_directory checks the config the client named:
that it and every base it extends are inside the session's grant, and that it
loads. The two checks each parsed the file, on the event loop that every
session shares, and the load check never validated the result, so a config the
scan refuses with exit 3 (``global_settings: 7``) started a scan that then
failed, while ``get_config`` refused the same file up front. The run_ash_scan
tool ran the grant check once more before calling scan_directory.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli.mcp.sandbox import (
    ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
    ASH_MCP_ALLOWED_ROOTS_ENV,
    ASH_MCP_TRANSPORT_ENV,
)
from automated_security_helper.config import config_sources


@pytest.fixture
def target(tmp_path, monkeypatch) -> Path:
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, raising=False)
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "app.py").write_text("x = 1\n", encoding="utf-8")
    return scan


def _scan(target: Path, config: Path):
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    with patch("automated_security_helper.cli.mcp_tools._run_scan_async") as started:
        result = asyncio.run(
            mcp_scan_directory(directory_path=str(target), config_path=str(config))
        )
    return result, started.called


def test_a_config_that_does_not_validate_is_refused_before_the_scan(target):
    config = target / ".ash.yaml"
    config.write_text("global_settings: 7\n", encoding="utf-8")

    result, started = _scan(target, config)

    assert result["success"] is False, result
    assert result["error_category"] == "invalid_format"
    assert "global_settings" in result["error"]
    assert started is False


def _count_reads(monkeypatch) -> List[Path]:
    reads: List[Path] = []
    real_read = config_sources.read_config_file

    def counting_read(path, *args, **kwargs):
        reads.append(Path(path))
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(config_sources, "read_config_file", counting_read)
    return reads


def test_the_config_is_parsed_once(target, monkeypatch):
    config = target / ".ash.yaml"
    config.write_text("project_name: once\n", encoding="utf-8")
    reads = _count_reads(monkeypatch)

    result, started = _scan(target, config)

    assert result["success"] is True, result
    assert started is True
    assert reads.count(config) == 1, reads


def test_run_ash_scan_parses_the_config_once(target, monkeypatch):
    """run_ash_scan checks a named config before it acts on the target, and
    hands the result to scan_directory instead of having it read the file
    again."""
    from automated_security_helper.cli import mcp_server

    async def _no_monitor(*args, **kwargs):
        return None

    monkeypatch.setattr(mcp_server, "monitor_scan_progress", _no_monitor)
    ctx = MagicMock()
    for method in ("info", "error", "warning", "debug", "report_progress"):
        setattr(ctx, method, AsyncMock())
    config = target / ".ash.yaml"
    config.write_text("project_name: once\n", encoding="utf-8")
    reads = _count_reads(monkeypatch)

    with patch("automated_security_helper.cli.mcp_tools._run_scan_async") as started:
        result = asyncio.run(
            mcp_server.run_ash_scan(
                ctx=ctx, source_dir=str(target), config_path=str(config)
            )
        )

    assert result["success"] is True, result
    assert started.called
    assert reads.count(config) == 1, reads


def _raise(error: BaseException):
    def raiser(*args, **kwargs):
        raise error

    return raiser


def test_a_rust_panic_while_validating_is_refused_before_the_scan(target, monkeypatch):
    """pydantic-core reports a Rust panic as pyo3's PanicException, a
    BaseException; it is refused as a config that does not load, as the scan's
    own resolution refuses it, instead of reaching the event loop."""
    from automated_security_helper.config.ash_config import AshConfig

    panic = type("PanicException", (BaseException,), {"__module__": "pyo3_runtime"})
    monkeypatch.setattr(
        AshConfig, "model_validate", _raise(panic("PyObject pointer is null"))
    )
    config = target / ".ash.yaml"
    config.write_text("project_name: x\n", encoding="utf-8")

    result, started = _scan(target, config)

    assert result["success"] is False, result
    assert result["error_category"] == "invalid_format"
    assert "PanicException" in result["error"]
    assert started is False


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_control_an_interrupt_still_propagates(target, monkeypatch, error):
    from automated_security_helper.config.ash_config import AshConfig

    monkeypatch.setattr(AshConfig, "model_validate", _raise(error()))
    config = target / ".ash.yaml"
    config.write_text("project_name: x\n", encoding="utf-8")

    with pytest.raises(error):
        _scan(target, config)


def test_control_a_valid_config_starts_the_scan(target):
    config = target / ".ash.yaml"
    config.write_text("project_name: fine\n", encoding="utf-8")

    result, started = _scan(target, config)

    assert result["success"] is True, result
    assert started is True
