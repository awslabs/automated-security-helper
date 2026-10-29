# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A bound profile whose file is gone and cannot be rewritten refuses the scan as a refusal.

``resolve_session_config_path`` writes a bound profile's file again when it is
gone, and raises when it cannot (the profile is no longer registered, or the
workspace cannot be written). Every caller has to turn that raise into the
tool's own refusal:

* ``run_ash_scan`` (``cli/mcp_server.py``) answers a config refusal, exit 3,
  with a stable ``error_type``, not the catch-all's internal error.
* the scan runner (``_run_scan`` in ``cli/mcp_tools.py``) records the entry
  FAILED with the reason; the runner's own ``try`` begins later, so a raise
  there would otherwise leave the entry PENDING, which reads as running.
* the workspace tools catch ``RuntimeError`` for a bound profile whose
  registered copy is missing (``_resolve_session_config``), so the error is a
  ``RuntimeError`` as well as a ``ProfileRegistryError``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from mcp.server.mcpserver import Context

from automated_security_helper.cli.mcp.profile_registry import (
    DEFAULT_SESSION_ID,
    BoundProfileUnavailableError,
    ProfileRegistryError,
    clear_all_session_state,
    clear_profile_registry,
    register_profiles,
    resolve_session_config_path,
    set_profile_registry,
)
from automated_security_helper.cli.mcp_tools import mcp_select_profile

pytestmark = pytest.mark.unit

SESSION = "bound-then-orphaned"


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    document: Dict[str, Any] = {
        "project_name": "operator-registered",
        "global_settings": {
            "mcp": {"runtime_overrides": {"enabled": True, "allowed_paths": ["/**"]}}
        },
    }
    profile = tmp_path / "op.yaml"
    profile.write_text(yaml.safe_dump(document), encoding="utf-8")
    set_profile_registry(register_profiles([f"op={profile}"]))
    yield
    clear_profile_registry()
    clear_all_session_state()


def _bind_then_orphan(session_id: str | None) -> None:
    """Bind the profile, remove its materialized file, unregister the profile."""
    result = mcp_select_profile("op", session_id=session_id)
    assert result["success"] is True, result
    bound = resolve_session_config_path(session_id)
    assert bound is not None and Path(bound).is_file()
    Path(bound).unlink()
    clear_profile_registry()


def _project(tmp_path: Path) -> Path:
    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    return source


def test_the_refusal_is_a_registry_error_and_a_runtime_error() -> None:
    """The type the workspace tools' handler catches (RuntimeError) and the
    registry's own (ProfileRegistryError) are one error here."""
    _bind_then_orphan(SESSION)

    with pytest.raises(BoundProfileUnavailableError) as refused:
        resolve_session_config_path(SESSION)

    assert isinstance(refused.value, ProfileRegistryError)
    assert isinstance(refused.value, RuntimeError)
    assert "select_profile" in str(refused.value)


def test_the_scan_runner_records_the_refusal_instead_of_leaving_the_entry_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    _bind_then_orphan(SESSION)
    source = _project(tmp_path)
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    started: List[str] = []

    def never_runs(*args: Any, **kwargs: Any) -> Any:
        started.append("scan")
        raise RuntimeError("the scan must not start")

    monkeypatch.setattr(ras, "run_ash_scan", never_runs)
    with patch.object(mcp_tools, "get_scan_registry", return_value=registry):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(source),
                output_dir=str(output),
                severity_threshold="MEDIUM",
                config_path=None,
                session_id=SESSION,
            )
        )

    entry = registry.get_scan(scan_id)
    assert entry is not None
    assert entry.status is MCScanStatus.FAILED, entry.status
    assert "select_profile" in (entry.error_message or ""), entry.error_message
    assert started == [], "the scan started although its profile was unusable"


@pytest.mark.asyncio
async def test_run_ash_scan_answers_a_config_refusal_not_an_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.cli import mcp_server

    # The stdio session: the tool resolves the caller to the default session,
    # which is the one bound here.
    _bind_then_orphan(DEFAULT_SESSION_ID)
    source = _project(tmp_path)
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    ctx = MagicMock(spec=Context)
    ctx.headers = {}

    response = await mcp_server.run_ash_scan(ctx, source_dir=str(source))

    assert response["success"] is False, response
    assert response["error_type"] == "bound_profile_unavailable", response
    assert response["exit_code"] == 3, response
    assert "select_profile" in response["error"], response
