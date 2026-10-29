# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash --workspace ... --config <file>``: the plan is resolved with the operator's file.

``--dry-run`` prints the plan the scan runs, so ``--config`` has to reach
resolution as well as the scan: a field it sets is final for every project, and
a project without a config of its own uses it alone.
"""

import json

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.models.workspace import WorkspaceExitCode

pytestmark = pytest.mark.unit

runner = CliRunner()


@pytest.fixture(autouse=True)
def _clear_ash_env(monkeypatch):
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def no_scan(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan",
        lambda **kwargs: calls.append(kwargs),
        raising=True,
    )
    return calls


def _layout(tmp_path):
    root = tmp_path / "work"
    (root / "api" / ".ash").mkdir(parents=True)
    (root / "api" / ".ash" / "ash.yaml").write_text(
        yaml.safe_dump({"global_settings": {"severity_threshold": "LOW"}}),
        encoding="utf-8",
    )
    (root / "web").mkdir(parents=True)
    workspace = root / "dev.code-workspace"
    workspace.write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), encoding="utf-8"
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        yaml.safe_dump({"global_settings": {"severity_threshold": "CRITICAL"}}),
        encoding="utf-8",
    )
    return workspace, operator


def test_the_plan_handed_to_the_scan_was_resolved_with_the_config(tmp_path, no_scan):
    workspace, operator = _layout(tmp_path)

    result = runner.invoke(
        app, ["scan", "--workspace", str(workspace), "--config", str(operator)]
    )

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    plan = no_scan[0]["workspace_plan"]
    by_key = {project.key: project for project in plan.projects}
    assert by_key["api"].severity_threshold == "CRITICAL"
    assert by_key["api"].operator_config == operator.resolve().as_posix()
    assert by_key["web"].config_source == operator.resolve().as_posix()
    assert by_key["web"].severity_threshold == "CRITICAL"


def test_the_dry_run_prints_the_operators_threshold(tmp_path, no_scan):
    workspace, operator = _layout(tmp_path)

    result = runner.invoke(
        app,
        ["scan", "--workspace", str(workspace), "--config", str(operator), "--dry-run"],
    )

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    assert "LOW" not in result.output
    assert "CRITICAL" in result.output
    assert no_scan == []
