# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A project with no config of its own runs under the operator's config.

Under an MCP session the caller's gate (``config_base_gate``) covers the config
a project discovers and every base a chain names. The operator's own file,
which the plan took for a project that discovered none, is authorized by
``check_operator_config`` and the plan's digest check, not by the caller's
gate: the plan and the scan judge it alike, and the selection pre-check that
resolves the first project does too. A config the project itself discovers, or
a client's copy standing in for the operator's file, is still held to the gate,
whatever file it reaches.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_all_session_state,
    clear_profile_registry,
)
from automated_security_helper.cli.mcp.sandbox import config_base_gate
from automated_security_helper.core.exceptions import (
    ASHConfigInputNotPermittedError,
    ASHConfigValidationError,
)
from automated_security_helper.core.scanner_selection import SelectionLayers
from automated_security_helper.workspace import execution
from automated_security_helper.workspace.resolver import resolve_workspace

pytestmark = pytest.mark.unit

SESSION = "session-a"

needs_links = pytest.mark.skipif(
    sys.platform == "win32", reason="symbolic links are not measured on Windows here"
)


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    granted = tmp_path / "granted"
    for name in ("api", "web"):
        (granted / name).mkdir(parents=True)
        (granted / name / "app.py").write_text("x = 1\n", encoding="utf-8")
    (granted / "dev.code-workspace").write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), encoding="utf-8"
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text("project_name: operator\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(granted))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    clear_profile_registry()
    clear_all_session_state()
    yield {"granted": granted, "operator": operator, "tmp": tmp_path}
    clear_profile_registry()
    clear_all_session_state()


def _plan(layout, default_config: Path, trusted_config: Path):
    return resolve_workspace(
        layout["granted"] / "dev.code-workspace",
        default_config=str(default_config),
        trusted_config=str(trusted_config),
        permit_base=config_base_gate(SESSION),
        session_id=SESSION,
    )


def _settings(layout, default_config: Path, trusted_config: Path, **fields):
    return execution.ProjectScanSettings(
        output_dir=layout["tmp"] / "out",
        default_config_path=str(default_config),
        trusted_config_path=str(trusted_config),
        config_base_gate=config_base_gate(SESSION),
        selection_layers=SelectionLayers(),
        **fields,
    )


def test_the_gate_does_not_permit_the_operators_file(layout) -> None:
    assert config_base_gate(SESSION)(layout["operator"]) is False


def test_a_project_without_a_config_resolves_under_the_operators_file(layout) -> None:
    operator = layout["operator"]
    plan = _plan(layout, operator, operator)
    settings = _settings(layout, operator, operator)

    execution.refuse_unresolvable_scanner_selection(plan, settings)
    configs = [
        execution._project_config_with_policy(project, settings)
        for project in plan.active_projects
    ]

    assert [c.project_name for c in configs] == ["operator", "operator"]
    assert config_base_gate(SESSION)(operator) is False


def test_the_operators_selection_settles_for_the_preflight(layout) -> None:
    operator = layout["operator"]
    operator.write_text(
        "project_name: operator\ndefault_scanners:\n  only: [bandit]\n",
        encoding="utf-8",
    )
    plan = _plan(layout, operator, operator)

    settled = execution.settled_scanner_selection(
        plan, _settings(layout, operator, operator)
    )

    assert settled.enabled_scanners == ("bandit",)


def test_an_explicit_mcp_selection_stays_a_limit(layout) -> None:
    operator = layout["operator"]
    operator.write_text(
        "project_name: operator\ndefault_scanners:\n  only: [bandit]\n",
        encoding="utf-8",
    )
    plan = _plan(layout, operator, operator)
    settings = execution.ProjectScanSettings(
        output_dir=layout["tmp"] / "out",
        default_config_path=str(operator),
        trusted_config_path=str(operator),
        config_base_gate=config_base_gate(SESSION),
        selection_layers=SelectionLayers(cli_only=["checkov"]),
        selection_origin="mcp",
    )

    settled = execution.settled_scanner_selection(plan, settings)

    assert settled.enabled_scanners == ("checkov",)


@needs_links
def test_a_project_config_linking_to_the_operators_file_is_still_refused(
    layout,
) -> None:
    operator = layout["operator"]
    own = layout["granted"] / "api" / "conf" / "own.yaml"
    own.parent.mkdir()
    own.write_text("project_name: api\n", encoding="utf-8")
    link = layout["granted"] / "api" / ".ash.yaml"
    os.symlink(Path("conf/own.yaml"), link)
    plan = _plan(layout, operator, operator)
    (project,) = [p for p in plan.active_projects if p.key == "api"]
    link.unlink()
    os.symlink(operator, link)

    with pytest.raises(ASHConfigValidationError):
        execution._project_config_with_policy(
            project, _settings(layout, operator, operator)
        )


@needs_links
def test_a_project_config_linking_to_the_operators_file_is_refused_at_plan_time(
    layout,
) -> None:
    operator = layout["operator"]
    link = layout["granted"] / "api" / ".ash.yaml"
    os.symlink(operator, link)

    with pytest.raises(Exception) as refused:
        _plan(layout, operator, operator)

    assert isinstance(refused.value, ASHConfigInputNotPermittedError) or isinstance(
        refused.value.__cause__, ASHConfigInputNotPermittedError
    ), repr(refused.value)


def test_a_clients_copy_standing_in_for_the_operators_file_is_still_gated(
    layout,
) -> None:
    operator = layout["operator"]
    copy = layout["tmp"] / "elsewhere" / "ash.yaml"
    copy.parent.mkdir()
    copy.write_text("project_name: copy\n", encoding="utf-8")
    plan = _plan(layout, copy, operator)
    settings = _settings(layout, copy, operator)

    with pytest.raises(ASHConfigInputNotPermittedError):
        execution._project_config_with_policy(plan.active_projects[0], settings)
