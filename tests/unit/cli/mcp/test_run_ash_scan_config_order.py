# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The config ``run_ash_scan`` uses when none is named, observed through the tool.

The tool reference says: the profile the session bound with ``select_profile``,
else the config ASH discovers in the source directory, else the file
``ASH_CONFIG`` names, else the built-in defaults. ``test_config_fallback_order.py``
pins the last three inside ``resolve_config``; this runs the MCP tool with
``ASH_CONFIG`` set, so a tool that passed ``ASH_CONFIG``'s file on as the
caller's ``config_path`` (``mcp_server.run_ash_scan`` when no profile is bound,
or ``mcp_tools._run_scan_async`` building the scan's arguments) would scan the
wrong config and fail here. The scan itself is stubbed: the stub resolves the
config from the arguments the orchestrator would get, as
``core/orchestrator.py`` does.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
)

REMOTE = "client-1"


class _Ctx:
    def __init__(self, headers: Dict[str, str]) -> None:
        self.headers = headers

    async def info(self, *a: Any, **k: Any) -> None: ...
    async def error(self, *a: Any, **k: Any) -> None: ...
    async def warning(self, *a: Any, **k: Any) -> None: ...
    async def debug(self, *a: Any, **k: Any) -> None: ...
    async def report_progress(self, *a: Any, **k: Any) -> None: ...


@pytest.fixture(autouse=True)
def _env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    operator = tmp_path / "operator"
    operator.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "scan-root"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    ash_config = operator / "ash.yaml"
    ash_config.write_text("project_name: from-ash-config\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(ash_config))
    clear_profile_registry()
    clear_session_state()
    yield {"scan_root": tmp_path / "scan-root"}
    clear_profile_registry()
    clear_session_state()


def _scanned_project_names(target: Path, monkeypatch: pytest.MonkeyPatch) -> List[str]:
    from automated_security_helper.cli import mcp_server
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.interactions import run_ash_scan as runner

    seen: List[str] = []

    def _fake_run_ash_scan(**kwargs: Any) -> None:
        config = resolve_config(
            config_path=kwargs["config"],
            source_dir=kwargs["source_dir"],
            permit_base=kwargs["config_base_gate"],
            trusted_config_path=kwargs["trusted_config_path"],
            untrusted_config=kwargs["untrusted_config"],
            client_config_policy=kwargs["client_config_policy"],
            remote_client=kwargs["remote_client"],
        )
        seen.append(config.project_name)
        return None

    async def _noop(*a: Any, **k: Any) -> None:
        return None

    monkeypatch.setattr(runner, "run_ash_scan", _fake_run_ash_scan)
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", _noop)

    async def _go() -> Dict[str, Any]:
        result = await mcp_server.run_ash_scan(
            _Ctx({"mcp-session-id": REMOTE}), source_dir=str(target)
        )
        pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        await asyncio.gather(*pending, return_exceptions=True)
        return result

    result = asyncio.run(_go())
    assert result.get("success") is not False, result
    return seen


def test_a_discovered_config_comes_before_ash_config(_env, monkeypatch) -> None:
    target = _env["scan_root"] / "repo"
    (target / ".ash").mkdir(parents=True)
    (target / ".ash" / ".ash.yaml").write_text(
        "project_name: discovered\n", encoding="utf-8"
    )

    assert _scanned_project_names(target, monkeypatch) == ["discovered"]


def test_ash_config_applies_when_nothing_is_discovered(_env, monkeypatch) -> None:
    target = _env["scan_root"] / "bare"
    target.mkdir(parents=True)

    assert _scanned_project_names(target, monkeypatch) == ["from-ash-config"]
