# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures for the MCP result snapshots. The helpers and the reasoning behind them
are in tests/snapshot/mcp/mcp_snapshot_support.py."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest

from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from tests.snapshot.mcp.mcp_snapshot_support import (
    aggregated_results,
    write_reports,
    write_results,
)


@pytest.fixture(autouse=True)
def isolated_mcp_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    """Fresh process-global MCP state, a private cwd, and confinement under tmp."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp import source_delivery
    from automated_security_helper.cli.mcp.sessions import (
        reset_default_registry_for_tests,
    )
    from automated_security_helper.core.resource_management import scan_registry

    monkeypatch.setattr(scan_registry, "_scan_registry", ScanRegistry())
    saved_sources = dict(source_delivery._SESSION_SOURCE_DIRS)
    source_delivery._SESSION_SOURCE_DIRS.clear()
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()
    reset_default_registry_for_tests()

    for name in (
        "ASH_MCP_ALLOWED_CONFIG_ROOTS",
        "ASH_MCP_TRANSPORT",
        "XDG_CACHE_HOME",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "allowed"))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    (tmp_path / "allowed").mkdir()
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)

    yield tmp_path / "allowed"

    source_delivery._SESSION_SOURCE_DIRS.clear()
    source_delivery._SESSION_SOURCE_DIRS.update(saved_sources)
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()
    reset_default_registry_for_tests()


#: Modules of the MCP server that stamp "now" into a tool result: the ``timestamp`` of
#: every response, a scan's ``start_time``/``end_time``, and the ``scan-<YYYYmmddHHMMSS>``
#: id get_scan_results mints per call. Each binds ``datetime`` at module level.
MCP_CLOCK_MODULES = (
    "automated_security_helper.cli.mcp_tools",
    "automated_security_helper.cli.mcp.sessions",
    "automated_security_helper.core.resource_management.event_manager",
    "automated_security_helper.core.resource_management.scan_management",
    "automated_security_helper.core.resource_management.scan_registry",
    "automated_security_helper.core.resource_management.scan_tracking",
)


@pytest.fixture(autouse=True)
def _pinned_mcp_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the clock every MCP payload reads, so its instants are snapshotted as-is.

    Without this the ``timestamp``, ``start_time``, ``end_time`` and ``scan_id`` of
    the lifecycle and findings payloads differed on every run (measured), and the
    only alternative was to mask them, which would hide a wrong or missing instant.
    """
    from tests.snapshot.support.fixture_model import pin_clock

    pin_clock(monkeypatch, extra_modules=MCP_CLOCK_MODULES)


@pytest.fixture
def allowed(isolated_mcp_state: Path) -> Path:
    """The one directory ASH_MCP_ALLOWED_ROOTS permits, empty."""
    return isolated_mcp_state


@pytest.fixture
def project(allowed: Path) -> Path:
    """A permitted source tree with a completed scan's output in it."""
    source = allowed / "project"
    (source / "src").mkdir(parents=True)
    (source / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    write_results(output, aggregated_results())
    write_reports(output)
    return source
