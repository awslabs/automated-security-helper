# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace ``config_overrides`` entry that is not ``key=value`` is an invalid config.

The MCP workspace tools report "the code the CLI would have exited with". For an
override with no ``=``, or with an empty key, the CLI's ``--config-overrides``
raises ``ASHConfigValidationError`` ("Invalid config override: ... Expected format:
key.path=value") and exits 3. The MCP gate raised a runtime-override denial instead,
as if the client had asked to change something the policy refuses, under a message
that named no expected format. It now raises the CLI's own error, whether or not
the session allows overrides; the exit code stays 3. A well-formed override the
policy refuses is still a denial, also exit 3.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit

# The last entry has no '=' and the shape of a token, which the CLI names by
# its length only; the workspace refusal has to read the same.
MALFORMED = ["project_name", "=renamed", "  =renamed", "ab12" * 10]


@pytest.fixture(autouse=True)
def _clear_policy_env(monkeypatch, tmp_path):
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_profile_registry,
        clear_all_session_state,
    )

    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    clear_profile_registry()
    clear_all_session_state()
    yield
    clear_profile_registry()
    clear_all_session_state()


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    (root / "app").mkdir(parents=True)
    (root / "app" / "main.py").write_text("x = 1\n")
    path = root / "dev.code-workspace"
    path.write_text(json.dumps({"folders": [{"path": "app"}]}))
    return path


def _allow_everything(tmp_path: Path) -> None:
    from automated_security_helper.cli.mcp.profile_registry import (
        register_profiles,
        set_profile_registry,
    )
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    profile = tmp_path / "profile.yaml"
    profile.write_text(
        "project_name: operator\nglobal_settings:\n  mcp:\n    runtime_overrides:\n"
        '      enabled: true\n      allowed_paths: ["/**"]\n'
    )
    set_profile_registry(register_profiles([f"op={profile}"]))
    assert mcp_select_profile("op")["success"] is True


def _cli_error(override: str) -> str:
    with pytest.raises(ASHConfigValidationError) as raised:
        apply_config_overrides(AshConfig(), [override])
    return str(raised.value)


async def _call(tool: str, tmp_path: Path, monkeypatch, overrides):
    if tool == "resolve":
        return await workspace_module.mcp_resolve_workspace(
            str(_workspace(tmp_path)), config_overrides=overrides
        )
    from automated_security_helper.workspace import execution as execution_module

    calls = []
    monkeypatch.setattr(
        execution_module, "execute_workspace", lambda *a, **k: calls.append(a)
    )
    if hasattr(workspace_module, "execute_workspace"):
        monkeypatch.setattr(
            workspace_module, "execute_workspace", lambda *a, **k: calls.append(a)
        )
    result = await workspace_module.mcp_scan_workspace(
        str(_workspace(tmp_path)), config_overrides=overrides
    )
    assert calls == [], "the scan started despite the refused override"
    return result


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["resolve", "scan"])
@pytest.mark.parametrize("allowed", [True, False], ids=["allowed", "not-allowed"])
@pytest.mark.parametrize("override", MALFORMED)
async def test_a_malformed_override_is_the_cli_s_invalid_config(
    tmp_path, monkeypatch, tool, allowed, override
):
    if allowed:
        _allow_everything(tmp_path)

    result = await _call(tool, tmp_path, monkeypatch, [override])

    assert result["success"] is False, result
    assert result["exit_code"] == 3, result
    assert result["error_type"] == "ASHConfigValidationError", result
    assert _cli_error(override) in result["error"], result["error"]


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["resolve", "scan"])
async def test_control_a_well_formed_refused_override_is_still_a_denial(
    tmp_path, monkeypatch, tool
):
    _allow_everything(tmp_path)

    result = await _call(tool, tmp_path, monkeypatch, ["sandbox.mode=off"])

    assert result["success"] is False, result
    assert result["exit_code"] == 3, result
    assert result["error_type"] == "RuntimePatchDeniedError", result


@pytest.mark.asyncio
async def test_control_a_well_formed_allowed_override_still_resolves(
    tmp_path, monkeypatch
):
    _allow_everything(tmp_path)

    result = await _call("resolve", tmp_path, monkeypatch, ["project_name=renamed"])

    assert result["success"] is True, result
