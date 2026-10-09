# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""MCP workspace ``config_overrides`` go through the runtime-override gate.

A workspace scan hands ``config_overrides`` to ``resolve_config`` as
``--config-overrides``, which the trust checks count as the operator's. Over MCP
they come from the client, so ``cli/mcp/workspace._gate_client_overrides`` checks
them against the session config's ``runtime_overrides`` allowlist first, the same
gate ``select_profile`` applies to ``patch_ops`` and ``override_yaml``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module


@pytest.fixture(autouse=True)
def _clear_policy_env(monkeypatch):
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    (root / "app").mkdir(parents=True)
    (root / "app" / "main.py").write_text("x = 1\n")
    path = root / "dev.code-workspace"
    path.write_text(json.dumps({"folders": [{"path": "app"}]}))
    return path


def _with_profile(monkeypatch, tmp_path: Path, allowed_paths, extra: str = "") -> None:
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        "project_name: operator\n" + extra + "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        f"      allowed_paths: {json.dumps(list(allowed_paths))}\n"
    )
    monkeypatch.setattr(
        workspace_module,
        "_resolve_session_config",
        lambda session_id, profile_name: str(profile),
    )


async def _resolve(tmp_path: Path, overrides):
    return await workspace_module.mcp_resolve_workspace(
        str(_workspace(tmp_path)), config_overrides=overrides
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "override",
    [
        "ash_plugin_modules=[standin_module]",
        "ash_plugin_modules+=[standin_module]",
        "sandbox.mode=off",
        "scanners.bandit.enabled=false",
    ],
)
async def test_without_a_profile_that_allows_overrides_none_is_accepted(
    tmp_path, override
):
    result = await _resolve(tmp_path, [override])
    assert result["success"] is False
    assert "plan" not in result


@pytest.mark.asyncio
async def test_no_overrides_still_resolve(tmp_path):
    result = await _resolve(tmp_path, None)
    assert result["success"] is True


@pytest.mark.asyncio
async def test_an_allowed_override_is_applied(tmp_path, monkeypatch):
    _with_profile(monkeypatch, tmp_path, ["/scanners/**"])
    result = await _resolve(tmp_path, ["scanners.bandit.enabled=false"])
    assert result["success"] is True, result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "override",
    [
        "ash_plugin_modules=[standin_module]",
        "ash_plugin_modules+=[standin_module]",
        "sandbox.mode=off",
        "sandbox.network_scanners=[checkov]",
    ],
)
async def test_plugin_modules_and_sandbox_are_refused_even_when_overrides_are_on(
    tmp_path, monkeypatch, override
):
    # The profile turns the sandbox on, so turning it off is a change.
    _with_profile(monkeypatch, tmp_path, ["/**"], "sandbox:\n  mode: bwrap\n")
    result = await _resolve(tmp_path, [override])
    assert result["success"] is False, result


@pytest.mark.asyncio
async def test_the_scan_tool_refuses_before_scanning(tmp_path, monkeypatch):
    from automated_security_helper.workspace import execution as execution_module

    # Recorded, not raised: the tool turns an exception into success False, which
    # would make a scan that started look the same as one refused up front.
    calls = []
    monkeypatch.setattr(
        execution_module, "execute_workspace", lambda *a, **k: calls.append(a)
    )
    if hasattr(workspace_module, "execute_workspace"):
        monkeypatch.setattr(
            workspace_module, "execute_workspace", lambda *a, **k: calls.append(a)
        )
    result = await workspace_module.mcp_scan_workspace(
        str(_workspace(tmp_path)),
        config_overrides=["ash_plugin_modules=[standin_module]"],
    )
    assert result["success"] is False
    assert calls == []


@pytest.mark.parametrize(
    "op",
    [
        {"op": "add", "path": "/ash_plugin_modules/-", "value": "standin_module"},
        {"op": "replace", "path": "/ash_plugin_modules", "value": ["standin_module"]},
    ],
)
def test_ash_plugin_modules_is_denied_by_default_even_when_everything_is_allowed(op):
    """select_profile's patch_ops and override_yaml use the same default denials."""
    from automated_security_helper.config.ash_config import (
        AshConfig,
        RuntimeOverridesConfig,
    )
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
        apply_runtime_patch,
    )

    allowlist = RuntimeOverridesConfig(enabled=True, allowed_paths=["/**"])
    with pytest.raises(RuntimePatchDeniedError):
        apply_runtime_patch(AshConfig(), [op], allowlist=allowlist)
