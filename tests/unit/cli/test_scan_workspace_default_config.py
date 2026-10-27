# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""In ``ash scan --workspace``, ``--config`` is the operator's config, layered over every project's.

That is the design (``ProjectScanSettings.default_config_path``,
``resolver._resolve_project_config``): every field the operator's file sets is
final for every project, a project's own config fills only the fields it leaves
unset, and a project without one uses the operator's file alone in place of ASH's
built-in defaults. Every file the operator's config is built from must be the
operator's, so it sits outside the workspace root (``check_operator_config``).
``ash scan`` resolves the plan with ``--config``, so the plan and the scan side
honor it alike: a project's verdict is taken from the plan, and it is judged at
the same threshold its scanners run under. The MCP workspace tools already pass
the value to both sides.
"""

import json

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _clear_ash_env(monkeypatch):
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def scan_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan",
        lambda **kwargs: calls.append(kwargs),
        raising=True,
    )
    return calls


def _workspace(tmp_path):
    # The workspace root is the .code-workspace file's directory, and the
    # operator's --config is refused when a file it is built from is inside it
    # (resolve_config.check_operator_config), so the operator's file sits
    # beside the root, never under it.
    root = tmp_path / "workspace"
    root.mkdir()
    for project in ("api", "web"):
        (root / project).mkdir()
    (root / "web" / ".ash").mkdir()
    (root / "web" / ".ash" / "ash.yaml").write_text(
        "project_name: web\nglobal_settings:\n  severity_threshold: LOW\n",
        encoding="utf-8",
    )
    workspace = root / "dev.code-workspace"
    workspace.write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), encoding="utf-8"
    )
    operator_config = tmp_path / "operator" / "strict.yaml"
    operator_config.parent.mkdir()
    operator_config.write_text(
        "project_name: operator\nglobal_settings:\n  severity_threshold: CRITICAL\n",
        encoding="utf-8",
    )
    return workspace, operator_config


def test_a_project_without_a_config_is_planned_under_the_named_config(
    tmp_path, scan_calls
):
    workspace, operator_config = _workspace(tmp_path)

    result = runner.invoke(
        app, ["scan", "--workspace", str(workspace), "--config", str(operator_config)]
    )

    assert result.exit_code == 0, result.output
    plan = scan_calls[0]["workspace_plan"]
    api = next(p for p in plan.projects if p.key == "api")
    assert api.severity_threshold == "CRITICAL"
    assert api.gate_threshold == "CRITICAL"
    assert api.config_source == operator_config.resolve().as_posix()


def test_a_project_with_its_own_config_keeps_it(tmp_path, scan_calls):
    """The project's own file stays its config, with the operator's layered over
    it: the fields the operator sets are final (the CRITICAL threshold here),
    and the project's file fills only the rest."""
    workspace, operator_config = _workspace(tmp_path)

    runner.invoke(
        app, ["scan", "--workspace", str(workspace), "--config", str(operator_config)]
    )

    web = next(p for p in scan_calls[0]["workspace_plan"].projects if p.key == "web")
    assert web.config_source is not None
    assert web.config_source.endswith("web/.ash/ash.yaml"), web.config_source
    assert web.operator_config is not None
    assert web.operator_config.endswith("strict.yaml"), web.operator_config
    assert web.severity_threshold == "CRITICAL"


def test_dry_run_prints_the_threshold_the_scan_applies(tmp_path, scan_calls):
    workspace, operator_config = _workspace(tmp_path)

    result = runner.invoke(
        app,
        [
            "scan",
            "--workspace",
            str(workspace),
            "--config",
            str(operator_config),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    api_section = result.output.split("1. api", 1)[1].split("2. web", 1)[0]
    assert "threshold:  CRITICAL" in api_section, api_section
    assert "ASH default config" not in api_section, api_section
