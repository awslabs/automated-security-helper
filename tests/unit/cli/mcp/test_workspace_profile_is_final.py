# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP workspace tools: a field the session's profile sets is final for every project.

The profile is the operator's config here, as ``--config`` is on the CLI. A
project's own config fills only the fields the profile leaves unset, which needs
the session's copy of the profile to hold only the fields the profile sets: a
copy that wrote out every default would set every field and leave the project's
config nothing to fill.

A client's patched copy of the profile is the client's: it is not layered over
a project's own config, and it is still a project's config only when the project
has none, as before.
"""

from __future__ import annotations

import asyncio
import importlib
import json
from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

MODULE_UNDER_TEST = "automated_security_helper.cli.mcp.workspace"
SESSION = "session-a"


def _tool(name: str):
    return getattr(importlib.import_module(MODULE_UNDER_TEST), name)


@pytest.fixture(autouse=True)
def _server(monkeypatch, tmp_path):
    from automated_security_helper.cli.mcp import profile_registry

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "work"))
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    yield
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()


def _register(tmp_path: Path, document: Dict[str, Any]) -> Path:
    from automated_security_helper.cli.mcp.profile_registry import (
        register_profiles,
        set_profile_registry,
    )

    path = tmp_path / "operator" / "profile.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    set_profile_registry(register_profiles([f"op={path}"]))
    return path


def _bind(**kwargs: Any) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    result = mcp_select_profile("op", session_id=SESSION, **kwargs)
    assert result["success"] is True, result
    return result


def _operator_copy() -> Path:
    from automated_security_helper.cli.mcp.sandbox import session_sandbox

    return session_sandbox(SESSION).config_dir / "ash.yaml"


def _workspace(tmp_path: Path, projects: Dict[str, Any]) -> Path:
    root = tmp_path / "work"
    for name, config in projects.items():
        project = root / name
        project.mkdir(parents=True, exist_ok=True)
        if config is not None:
            (project / ".ash.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    path = root / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": name} for name in projects]}),
        encoding="utf-8",
    )
    return path


async def _resolve(workspace: Path) -> Dict[str, Dict[str, Any]]:
    response = await _tool("mcp_resolve_workspace")(
        workspace_file=str(workspace), session_id=SESSION
    )
    assert response["success"] is True, response.get("error")
    return {project["project"]: project for project in response["projects"]}


def test_the_sessions_copy_of_a_profile_holds_only_what_the_profile_sets(tmp_path):
    document = {
        "fail_on_findings": True,
        "global_settings": {"severity_threshold": "CRITICAL"},
    }
    _register(tmp_path, document)

    _bind()

    assert yaml.safe_load(_operator_copy().read_text("utf-8")) == document


@pytest.mark.asyncio
async def test_a_field_the_profile_sets_is_final_and_the_project_fills_the_rest(
    tmp_path,
):
    _register(tmp_path, {"global_settings": {"severity_threshold": "CRITICAL"}})
    _bind()
    workspace = _workspace(
        tmp_path,
        {
            "api": {
                "global_settings": {"severity_threshold": "LOW"},
                "scanners": {"bandit": {"enabled": False}},
            }
        },
    )

    projects = await _resolve(workspace)

    assert projects["api"]["severity_threshold"] == "CRITICAL"
    assert "bandit" not in projects["api"]["scanners"]
    assert projects["api"]["operator_config"] == _operator_copy().as_posix()


@pytest.mark.asyncio
async def test_a_clients_patch_is_not_layered_over_a_projects_own_config(tmp_path):
    _register(
        tmp_path,
        {
            "project_name": "operator",
            "global_settings": {
                "mcp": {
                    "runtime_overrides": {
                        "enabled": True,
                        "allowed_paths": ["/project_name"],
                    }
                }
            },
        },
    )
    _bind(patch_ops=[{"op": "replace", "path": "/project_name", "value": "client"}])
    workspace = _workspace(tmp_path, {"api": {"project_name": "the-api"}, "web": None})

    projects = await _resolve(workspace)

    # The registered profile is final over the project's own config ...
    assert projects["api"]["display_label"] == "operator"
    assert projects["api"]["operator_config"] == _operator_copy().as_posix()
    # ... and the client's copy is still the config of a project that has none.
    assert projects["web"]["display_label"] == "client"
    assert projects["web"]["operator_config"] is None


_PATCHABLE_PROFILE = {
    "project_name": "operator",
    "global_settings": {
        "mcp": {
            "runtime_overrides": {"enabled": True, "allowed_paths": ["/project_name"]}
        }
    },
}


class _Orchestrator:
    """Hands back results carrying the config it was given, as the real one does."""

    def __init__(self, built, **kwargs):
        self.kwargs = kwargs
        built.append(self)

    def execute_scan(self, phases=None):
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
            ScannerTargetStatusInfo,
        )
        from automated_security_helper.schemas.sarif_schema_model import SarifReport

        model = AshAggregatedResults()
        model.ash_config = self.kwargs["resolved_config"]
        model.sarif = SarifReport.model_validate(
            {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ASH"}}}]}
        )
        model.scanner_results["bandit"] = ScannerTargetStatusInfo(
            status="PASSED", excluded=False, dependencies_satisfied=True
        )
        return model


@pytest.mark.asyncio
async def test_the_scan_layers_the_profile_never_the_clients_copy(
    tmp_path, monkeypatch
):
    """The scan side of the test above: what each project is scanned with."""
    from automated_security_helper.workspace import execution as execution_module

    _register(tmp_path, _PATCHABLE_PROFILE)
    _bind(patch_ops=[{"op": "replace", "path": "/project_name", "value": "client"}])
    workspace = _workspace(tmp_path, {"api": {"project_name": "the-api"}, "web": None})
    built: list = []
    real = execution_module.execute_workspace

    def run(plan, settings, **kwargs):
        kwargs["orchestrator_factory"] = lambda **kw: _Orchestrator(built, **kw)
        return real(plan, settings, **kwargs)

    module = importlib.import_module(MODULE_UNDER_TEST)
    monkeypatch.setattr(execution_module, "execute_workspace", run)
    if hasattr(module, "execute_workspace"):
        monkeypatch.setattr(module, "execute_workspace", run)

    response = await module.mcp_scan_workspace(
        workspace_file=str(workspace), session_id=SESSION
    )

    assert response["success"] is True, response.get("error")
    names = {
        Path(o.kwargs["source_dir"]).name: o.kwargs["resolved_config"].project_name
        for o in built
    }
    assert names == {"api": "operator", "web": "client"}


@pytest.mark.asyncio
async def test_a_patched_binding_that_lost_its_registered_copy_is_refused(tmp_path):
    """The client's copy is never layered, so with the registered copy gone there
    is nothing that can be: the call is refused rather than layering the copy."""
    _register(tmp_path, _PATCHABLE_PROFILE)
    _bind(patch_ops=[{"op": "replace", "path": "/project_name", "value": "client"}])
    _operator_copy().unlink()
    workspace = _workspace(tmp_path, {"api": {"project_name": "the-api"}})

    response = await _tool("mcp_resolve_workspace")(
        workspace_file=str(workspace), session_id=SESSION
    )

    assert response["success"] is False
    assert response["exit_code"] == 3
    assert "registered" in response["error"]


@pytest.mark.asyncio
async def test_an_unbound_session_layers_the_servers_ash_config(tmp_path, monkeypatch):
    server_config = tmp_path / "server" / "ash.yaml"
    server_config.parent.mkdir(parents=True)
    server_config.write_text(
        yaml.safe_dump({"global_settings": {"severity_threshold": "CRITICAL"}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(server_config))
    workspace = _workspace(
        tmp_path,
        {"api": {"global_settings": {"severity_threshold": "LOW"}}, "web": None},
    )

    projects = await _resolve(workspace)

    assert projects["api"]["severity_threshold"] == "CRITICAL"
    assert projects["api"]["operator_config"] == server_config.resolve().as_posix()
    assert projects["web"]["severity_threshold"] == "CRITICAL"


@pytest.mark.asyncio
async def test_an_unbound_session_does_not_layer_a_client_file_named_by_ash_config(
    tmp_path, monkeypatch
):
    client_file = tmp_path / "mcp-workspaces" / "other" / "source" / "ash.yaml"
    client_file.parent.mkdir(parents=True)
    client_file.write_text(
        yaml.safe_dump({"global_settings": {"severity_threshold": "CRITICAL"}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(client_file))
    workspace = _workspace(
        tmp_path, {"api": {"global_settings": {"severity_threshold": "LOW"}}}
    )

    projects = await _resolve(workspace)

    assert projects["api"]["operator_config"] is None
    assert projects["api"]["severity_threshold"] == "LOW"


@pytest.mark.asyncio
async def test_calls_naming_different_profiles_do_not_share_a_file(tmp_path):
    """A call's plan names the file its scan layers. A second call in the same
    session naming another profile must not rewrite that file in between."""
    from automated_security_helper.cli.mcp.profile_registry import (
        register_profiles,
        set_profile_registry,
    )

    profiles = {}
    for name, threshold in (("strict", "CRITICAL"), ("lax", "MEDIUM")):
        path = tmp_path / "operator" / f"{name}.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.safe_dump({"global_settings": {"severity_threshold": threshold}}),
            encoding="utf-8",
        )
        profiles[name] = path
    set_profile_registry(
        register_profiles([f"{name}={path}" for name, path in profiles.items()])
    )
    workspace = _workspace(
        tmp_path, {"api": {"global_settings": {"severity_threshold": "LOW"}}}
    )

    async def plan_for(profile: str) -> Dict[str, Any]:
        response = await _tool("mcp_resolve_workspace")(
            workspace_file=str(workspace), session_id=SESSION, profile=profile
        )
        assert response["success"] is True, response.get("error")
        return response["projects"][0]

    strict = await plan_for("strict")
    lax = await plan_for("lax")

    assert strict["operator_config"] != lax["operator_config"]
    text = await asyncio.to_thread(Path(strict["operator_config"]).read_text, "utf-8")
    layered = yaml.safe_load(text)
    assert layered["global_settings"]["severity_threshold"] == "CRITICAL"
