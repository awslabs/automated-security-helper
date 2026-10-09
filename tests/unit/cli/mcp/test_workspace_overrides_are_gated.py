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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "override",
    [
        "fail_on_findings=false",
        "sandbox.mode=off",
        "ash_plugin_modules=[]",
        "global_settings.suppressions=[]",
        "fail-on-findings=false",
    ],
)
async def test_an_override_equal_to_the_profile_is_still_checked_by_its_key(
    tmp_path, monkeypatch, override
):
    """It changes nothing in the profile but would still overwrite each project's value."""
    _with_profile(
        monkeypatch,
        tmp_path,
        ["/project_name"],
        "fail_on_findings: false\n",
    )
    result = await _resolve(tmp_path, [override])
    assert result["success"] is False, result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "override",
    ["ash_plugin_modules=[]", "ash-plugin-modules=[]", "sandbox.mode=bwrap"],
)
async def test_a_denied_key_is_refused_when_the_value_is_unchanged(
    tmp_path, monkeypatch, override
):
    _with_profile(monkeypatch, tmp_path, ["/**"], "sandbox:\n  mode: bwrap\n")
    result = await _resolve(tmp_path, [override])
    assert result["success"] is False, result


@pytest.mark.asyncio
@pytest.mark.parametrize("override", ["project_name=renamed", "project-name=renamed"])
async def test_an_override_on_an_allowed_key_is_accepted(
    tmp_path, monkeypatch, override
):
    _with_profile(monkeypatch, tmp_path, ["/project_name"])
    result = await _resolve(tmp_path, [override])
    assert result["success"] is True, result


_POLICY = "workspace:\n  ignore_paths:\n    - path: app\n      reason: stand-in\n"


def _delivered_workspace(tmp_path: Path, monkeypatch, with_policy: bool) -> Path:
    root = tmp_path / "ash-mcp"
    tree = root / "session-a" / "source"
    (tree / "app").mkdir(parents=True)
    (tree / "app" / "main.py").write_text("x = 1\n")
    definition = tree / "dev.code-workspace"
    definition.write_text(json.dumps({"folders": [{"path": "app"}]}))
    if with_policy:
        (tree / ".ash-workspace.yaml").write_text(_POLICY)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    return definition


@pytest.mark.asyncio
async def test_a_policy_found_beside_a_delivered_definition_is_refused(
    tmp_path, monkeypatch
):
    definition = _delivered_workspace(tmp_path, monkeypatch, with_policy=True)
    result = await workspace_module.mcp_resolve_workspace(
        str(definition), session_id="session-a"
    )
    assert result["success"] is False
    assert "delivered by an MCP client" in result["error"]


@pytest.mark.asyncio
async def test_a_named_client_policy_is_refused_and_an_operator_policy_kept(
    tmp_path, monkeypatch
):
    definition = _delivered_workspace(tmp_path, monkeypatch, with_policy=False)
    delivered = definition.parent / "policy.yaml"
    delivered.write_text(_POLICY)
    refused = await workspace_module.mcp_resolve_workspace(
        str(definition), workspace_config=str(delivered), session_id="session-a"
    )
    assert refused["success"] is False
    assert "delivered by an MCP client" in refused["error"]

    # A session's config inputs are confined, so the operator grants its own
    # policy directory, as a network deployment does.
    operator = tmp_path / "operator" / "policy.yaml"
    operator.parent.mkdir()
    operator.write_text(_POLICY)
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator.parent))
    kept = await workspace_module.mcp_resolve_workspace(
        str(definition), workspace_config=str(operator), session_id="session-a"
    )
    assert kept["success"] is True, kept


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "override",
    [
        "reporters.bedrock_summary_reporter.options.aws_region=us-east-1",
        "reporters.BedrockSummary.options.aws_region=us-east-1",
        "reporters.bedrocksummaryreporter.options.aws_region=us-east-1",
    ],
)
async def test_a_default_denial_holds_for_every_spelling_of_the_plugin(
    tmp_path, monkeypatch, override
):
    _with_profile(monkeypatch, tmp_path, ["/**"])
    result = await _resolve(tmp_path, [override])
    assert result["success"] is False, result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "override",
    [
        "scanners.trivy_repo.options.ignore_file=standin.txt",
        "scanners.trivy-repo.options.ignore-file=standin.txt",
        "scanners.TrivyRepo.options.ignore_file=standin.txt",
    ],
)
async def test_an_operator_denial_holds_for_every_mix_of_separators(
    tmp_path, monkeypatch, override
):
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        "project_name: operator\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        '      allowed_paths: ["/**"]\n'
        '      denied_paths: ["/scanners/trivy-repo/options/ignore_file"]\n'
    )
    monkeypatch.setattr(
        workspace_module,
        "_resolve_session_config",
        lambda session_id, profile_name: str(profile),
    )
    result = await _resolve(tmp_path, [override])
    assert result["success"] is False, result


@pytest.mark.asyncio
async def test_a_policy_beside_a_symlinked_definitions_target_is_refused(
    tmp_path, monkeypatch
):
    """The resolver looks for a policy beside the file a symlink points to."""
    definition = _delivered_workspace(tmp_path, monkeypatch, with_policy=False)
    target_dir = definition.parent / "sub"
    (target_dir / "app").mkdir(parents=True)
    (target_dir / "app" / "main.py").write_text("x = 1\n")
    target = target_dir / "real.code-workspace"
    target.write_text(json.dumps({"folders": [{"path": "app"}]}))
    (target_dir / ".ash-workspace.yaml").write_text(_POLICY)
    link = definition.parent / "link.code-workspace"
    link.symlink_to(Path("sub") / "real.code-workspace")

    result = await workspace_module.mcp_resolve_workspace(
        str(link), session_id="session-a"
    )
    assert result["success"] is False, result
    assert "delivered by an MCP client" in result["error"]
