# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace run's crash text is redacted with every value its configs read
from the environment, not only the plugin module names.

The prewarm imports the workspace's plugin modules before any project starts,
and a module that crashes there can quote anything in its error: here, a value
the project's config also read from the environment, for a field that is not a
plugin module. The run's failure handlers hold no project config, so the
resolver records each project's environment values on its plan entry, as a
private attribute that no dump of the plan shows, and the prewarm carries the
union of them on the error. Every surface is checked: the real run's console,
log records and ash.log, the dry run's console, and the MCP workspace tool's
answer. The MCP resolve tool, which dumps every plan entry, shows none of it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.utils.log import ASH_LOGGER

#: The value of a variable the project's config reads for an ignore path's
#: reason, a field no plan entry shows; the crashing module quotes it.
OTHER = "zzother-secret-9137"
#: A namespace package whose import raises, quoting OTHER. Named literally in
#: the config, so no plugin-module masking is involved.
CRASHING = "othercrash_ash_plugins"


class _Sink(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.messages: list = []

    def emit(self, record):
        self.messages.append(self.format(record))


@pytest.fixture
def log_records():
    """Every ash log record's message and traceback, whatever the level."""
    sink = _Sink()
    level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(sink)
    ASH_LOGGER.setLevel(1)
    yield sink.messages
    ASH_LOGGER.removeHandler(sink)
    ASH_LOGGER.setLevel(level)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A one-project workspace (the cwd) whose project config reads OTHER from
    the environment and names the crashing module, which lives outside it."""
    site = tmp_path / "site"
    (site / CRASHING).mkdir(parents=True)
    (site / CRASHING / "__init__.py").write_text(
        "import os\n"
        "raise ValueError(f\"cannot use {os.environ['ASH_OTHERCANARY']}\")\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.delitem(sys.modules, CRASHING, raising=False)
    monkeypatch.setenv("ASH_OTHERCANARY", OTHER)

    root = tmp_path / "ws"
    config_dir = root / "api" / ".ash"
    config_dir.mkdir(parents=True)
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (config_dir / ".ash.yaml").write_text(
        "project_name: api\n"
        "global_settings:\n"
        "  ignore_paths:\n"
        "    - path: vendor/**\n"
        "      reason: !ENV ${ASH_OTHERCANARY}\n"
        f"ash_plugin_modules:\n  - {CRASHING}\n",
        encoding="utf-8",
    )
    (root / "dev.code-workspace").write_text(
        '{"folders": [{"path": "api"}]}', encoding="utf-8"
    )
    monkeypatch.chdir(root)
    yield root
    sys.modules.pop(CRASHING, None)


def _crash_redacted(result, log_records) -> None:
    """The import failure refuses the run (exit 3, like every import failure
    of a configured module); the literally named module keeps its error text,
    with the env-read value redacted from it everywhere."""
    assert result.exit_code == 3, (result.exception, result.output)
    assert "which failed to import" in result.output, result.output
    assert "cannot use" in result.output, result.output
    assert OTHER not in result.output, result.output
    leaked = [message for message in log_records if OTHER in message]
    assert leaked == [], leaked


def test_the_resolver_records_each_projects_environment_values(workspace):
    from automated_security_helper.workspace.resolver import resolve_workspace

    plan = resolve_workspace(workspace / "dev.code-workspace")

    (project,) = plan.active_projects
    assert OTHER in project._environment_values


def test_no_dump_of_a_plan_entry_shows_its_environment_values(workspace):
    """The values are a private attribute: absent from model_dump,
    model_dump_json and repr, and kept by model_copy, so the plan can be
    copied and dumped without either losing or showing them."""
    from automated_security_helper.workspace.resolver import resolve_workspace

    plan = resolve_workspace(workspace / "dev.code-workspace")
    (project,) = plan.active_projects

    for shown in (
        json.dumps(project.model_dump(mode="json")),
        project.model_dump_json(),
        repr(project),
        plan.model_dump_json(),
    ):
        assert OTHER not in shown, shown
        assert "_environment_values" not in shown, shown
    assert OTHER in project.model_copy()._environment_values


def test_a_workspace_runs_crash_is_redacted_on_every_surface(workspace, log_records):
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--no-progress",
            "--workspace",
            "dev.code-workspace",
            "--output-dir",
            "out",
        ],
    )

    _crash_redacted(result, log_records)
    ash_log = workspace / "out" / "ash.log"
    assert ash_log.is_file(), sorted(p.name for p in (workspace / "out").iterdir())
    logged = ash_log.read_text(encoding="utf-8")
    assert "cannot use" in logged, logged
    assert OTHER not in logged, logged


def test_a_workspace_dry_runs_crash_is_redacted(workspace, log_records):
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--no-progress",
            "--workspace",
            "dev.code-workspace",
            "--output-dir",
            "out",
            "--dry-run",
        ],
    )

    _crash_redacted(result, log_records)


@pytest.fixture
def mcp_env(workspace, tmp_path, monkeypatch):
    from automated_security_helper.cli.mcp import source_delivery
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    monkeypatch.setattr(source_delivery, "_SESSION_SOURCE_DIRS", {})
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(workspace))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    return workspace


def test_the_mcp_workspace_tools_crash_answer_is_redacted(mcp_env, log_records):
    from automated_security_helper.cli.mcp import workspace as workspace_module

    response = asyncio.run(
        workspace_module.mcp_scan_workspace(
            workspace_file=str(mcp_env / "dev.code-workspace"),
            output_dir=str(mcp_env / "out"),
        )
    )

    assert response["success"] is False, response
    assert response["exit_code"] == 3, response
    assert "cannot use" in response["error"], response
    assert OTHER not in json.dumps(response), response
    leaked = [message for message in log_records if OTHER in message]
    assert leaked == [], leaked


def test_the_mcp_resolve_tool_shows_no_environment_value(mcp_env):
    from automated_security_helper.cli.mcp import workspace as workspace_module

    response = asyncio.run(
        workspace_module.mcp_resolve_workspace(
            workspace_file=str(mcp_env / "dev.code-workspace")
        )
    )

    assert response["success"] is True, response
    shown = json.dumps(response)
    assert OTHER not in shown, shown
    assert "_environment_values" not in shown, shown
