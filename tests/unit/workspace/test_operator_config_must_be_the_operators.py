# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Workspace mode refuses an operator config that is not entirely the operator's.

The operator's ``--config`` is final over every project, so a file it is built
from that the workspace wrote (one inside the workspace) or an MCP client
delivered (one under the MCP workspace root) would make that file's settings
final too. Such a config is refused, as a config error (exit 3), whether or not
a project has a config of its own.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.workspace.resolver import resolve_workspace

_NOT_THE_OPERATORS = "must be the operator's"


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    for name in ("ASH_CONFIG", "ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))


def _write(path: Path, document: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _workspace(root: Path, projects: Dict[str, Optional[Dict[str, Any]]]) -> Path:
    for name, config in projects.items():
        (root / name).mkdir(parents=True, exist_ok=True)
        if config is not None:
            _write(root / name / ".ash.yaml", config)
    path = root / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": name} for name in projects]}),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    "projects",
    [{"api": {"fail_on_findings": True}}, {"api": None}],
    ids=["project with its own config", "project without one"],
)
def test_an_operator_config_inside_the_workspace_is_refused(tmp_path, projects):
    root = tmp_path / "work"
    workspace = _workspace(root, projects)
    inside = _write(root / "ops.yaml", {"fail_on_findings": False})

    with pytest.raises(ASHConfigValidationError, match=_NOT_THE_OPERATORS) as raised:
        resolve_workspace(workspace, default_config=inside)

    assert "ops.yaml" in str(raised.value)


def test_an_operator_config_extending_a_base_inside_the_workspace_is_refused(
    tmp_path,
):
    """The base passes the extends confinement: the workspace is inside the
    operator file's own directory. Only the check that it is the operator's
    refuses it."""
    ops = tmp_path / "ops"
    root = ops / "work"
    workspace = _workspace(root, {"api": {"fail_on_findings": True}})
    _write(root / "shared" / "base.yaml", {"fail_on_findings": False})
    operator = _write(ops / "ash.yaml", {"extends": "work/shared/base.yaml"})

    with pytest.raises(ASHConfigValidationError, match=_NOT_THE_OPERATORS) as raised:
        resolve_workspace(workspace, default_config=operator)

    assert "base.yaml" in str(raised.value)


def test_an_operator_config_an_mcp_client_delivered_is_refused(tmp_path):
    workspace = _workspace(tmp_path / "work", {"api": None})
    delivered = _write(
        tmp_path / "mcp-workspaces" / "sess" / "upload" / "ash.yaml",
        {"fail_on_findings": False},
    )

    with pytest.raises(ASHConfigValidationError, match=_NOT_THE_OPERATORS):
        resolve_workspace(workspace, default_config=delivered)


def test_a_client_copy_with_no_trusted_copy_is_not_layered(tmp_path):
    """With no trusted config, the default config is the operator's only when it
    is not a client's file: a session's patched copy is refused, not layered."""
    workspace = _workspace(tmp_path / "work", {"api": {"project_name": "api"}})
    client_copy = _write(
        tmp_path / "mcp-workspaces" / "sess" / "client-config" / "ash.yaml",
        {"project_name": "client"},
    )

    with pytest.raises(ASHConfigValidationError, match=_NOT_THE_OPERATORS):
        resolve_workspace(workspace, default_config=client_copy, trusted_config=None)


def test_an_operator_config_outside_the_workspace_is_layered(tmp_path):
    """Control for the refusals above."""
    workspace = _workspace(tmp_path / "work", {"api": {"fail_on_findings": False}})
    operator = _write(tmp_path / "ops" / "ash.yaml", {"fail_on_findings": True})

    plan = resolve_workspace(workspace, default_config=operator)

    assert plan.active_projects[0].operator_config == operator.resolve().as_posix()


def test_the_cli_refuses_an_operator_config_inside_the_workspace_with_exit_3(
    tmp_path, monkeypatch
):
    calls: List[Dict[str, Any]] = []
    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan",
        lambda **kwargs: calls.append(kwargs),
        raising=True,
    )
    root = tmp_path / "work"
    workspace = _workspace(root, {"api": None})
    inside = _write(root / "ops.yaml", {"fail_on_findings": False})

    result = CliRunner().invoke(
        app,
        ["scan", "--workspace", str(workspace), "--config", str(inside), "--dry-run"],
    )

    assert result.exit_code == WorkspaceExitCode.INVALID_PROJECT_CONFIG, result.output
    assert result.exit_code == 3
    assert calls == []
