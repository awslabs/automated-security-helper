# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The import log lines name an env-read plugin module masked, on every surface.

``load_additional_plugin_modules`` logs each module it imports (``Importing
additional plugin module: ...``) and names an env-read entry by its label. For
an ``ash_plugin_modules`` entry the config read from the environment, the label
keeps the variable's value off the console and out of ash.log of ``ash
report``, ``ash dependencies install`` and ``ash merge`` -- the leak class the
engine's INFO line already masks. ``load_plugins`` already builds the shown map
for its
refusal; these cells pin that the import lines read it too.

The canary module is importable and inside the plugin namespace, so the run
gets past the refusal and the import line fires.
"""

from __future__ import annotations

import logging
import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.utils.log import ASH_LOGGER

#: The variable's value: an importable namespace module whose name nothing
#: else in these runs would log, so finding it in a record is the leak.
CANARY = "logcanary_ash_plugins"
MASKED_IMPORT = "Importing additional plugin module: <value>"


class _Sink(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.messages: list = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@pytest.fixture
def log_records(monkeypatch):
    """Every ash log record's message, whatever the logger's level was."""
    sink = _Sink()
    level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(sink)
    # The logger's own level gates records before any handler sees them.
    ASH_LOGGER.setLevel(1)
    yield sink.messages
    ASH_LOGGER.removeHandler(sink)
    ASH_LOGGER.setLevel(level)


@pytest.fixture
def env_read_importable_config(tmp_path, monkeypatch):
    """A resolved config whose one entry reads the canary from the environment.

    The canary is planted importable, and the config file sits outside the
    scanned tree (the cwd), so the entry is kept as the operator's.
    """
    modules = tmp_path / "modules"
    (modules / CANARY).mkdir(parents=True)
    (modules / CANARY / "__init__.py").write_text(
        "ASH_REPORTERS = []\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(modules))
    monkeypatch.delitem(sys.modules, CANARY, raising=False)
    monkeypatch.setenv("ASH_LOGCANARY", CANARY)
    source = tmp_path / "src"
    source.mkdir()
    monkeypatch.chdir(source)
    config_file = tmp_path / "cfg" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        "project_name: probe\nash_plugin_modules:\n  - !ENV ${ASH_LOGCANARY}\n",
        encoding="utf-8",
    )
    yield config_file
    sys.modules.pop(CANARY, None)


def _masked(messages: list) -> None:
    joined = " ".join(messages)
    assert CANARY not in joined, joined
    assert any(MASKED_IMPORT in message for message in messages), messages


def test_load_plugins_import_log_names_the_entry_masked(
    tmp_path, env_read_importable_config, log_records
):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugins.loader import load_plugins

    config = resolve_config(config_path=str(env_read_importable_config))
    load_plugins(
        plugin_context=PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "work",
            config=config,
        )
    )

    _masked(log_records)


def test_the_warn_skip_line_names_an_env_read_entry_masked(log_records):
    """The defense-in-depth skip in load_additional_plugin_modules: callers
    refuse out-of-namespace entries first, so this line is reachable only
    through a direct call, and it names an env-read entry by its label too."""
    from automated_security_helper.plugins.loader import (
        load_additional_plugin_modules,
    )

    load_additional_plugin_modules(
        ["env_named_module"], shown={"env_named_module": "<value>"}
    )

    joined = " ".join(log_records)
    assert "env_named_module" not in joined, joined
    assert any(
        "Skipping module with unexpected namespace: <value>" in message
        for message in log_records
    ), log_records


def test_the_engines_import_and_discovery_logs_name_the_entry_masked(
    tmp_path, env_read_importable_config, log_records
):
    """The engine's own path: it imports and discovers the modules itself
    (load_additional_plugin_modules and discover_plugins), so a scan's log
    carries those lines too, beside the already-masked "Loading plugin
    modules" line."""
    from unittest.mock import patch

    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.execution_engine import ScanExecutionEngine

    config = resolve_config(config_path=str(env_read_importable_config))
    with patch("automated_security_helper.plugins.loader.load_internal_plugins"):
        ScanExecutionEngine(
            context=PluginContext(
                source_dir=tmp_path,
                output_dir=tmp_path / "out",
                work_dir=tmp_path / "out" / "work",
                config=config,
            ),
            show_progress=False,
        )

    _masked(log_records)


def test_dependencies_install_import_log_names_the_entry_masked(
    tmp_path, env_read_importable_config, log_records, monkeypatch
):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))

    # --tool nonexistent: the unknown name is rejected right after the plugins
    # load (the selection resolves against them), so the import line fires and
    # nothing is installed.
    result = CliRunner().invoke(
        app,
        [
            "dependencies",
            "install",
            "--config",
            str(env_read_importable_config),
            "--bin-path",
            str(tmp_path / "bin"),
            "--tool",
            "nonexistent",
        ],
    )

    assert result.exception is None or isinstance(result.exception, SystemExit), repr(
        result.exception
    )
    _masked(log_records)


def _engine(tmp_path, config):
    from unittest.mock import MagicMock

    from automated_security_helper.core.execution_engine import ScanExecutionEngine

    context = MagicMock()
    context.config = config
    context.source_dir = tmp_path / "src"
    context.output_dir = tmp_path / "out"
    context.work_dir = tmp_path / "out" / "work"
    ScanExecutionEngine(
        context=context, ash_plugin_modules=[], asharp_model=MagicMock()
    )


def test_a_single_scans_engine_names_the_entry_masked_in_every_line(
    tmp_path, env_read_importable_config, log_records
):
    """The engine's own "Loading plugin modules" line is already masked; the
    import and discovery lines it causes must be too, in a single scan."""
    from automated_security_helper.config.resolve_config import resolve_config

    config = resolve_config(config_path=str(env_read_importable_config))

    _engine(tmp_path, config)

    _masked(log_records)
    joined = " ".join(log_records)
    assert "Discovered plugin package: <value>" in joined, log_records


def test_a_toml_configs_env_reference_is_masked_the_same_way(
    tmp_path, env_read_importable_config, log_records, monkeypatch
):
    """The ``${VAR}`` spelling in TOML: a TOML config resolves a value that
    starts with ``${`` from the environment, as a YAML config resolves both
    ``${VAR}`` and ``!ENV``, and the engine's import line names that entry
    masked too."""
    from automated_security_helper.config.resolve_config import resolve_config

    toml_config = tmp_path / "cfg" / ".ash.toml"
    toml_config.write_text(
        'project_name = "probe"\nash_plugin_modules = ["${ASH_LOGCANARY}"]\n',
        encoding="utf-8",
    )
    monkeypatch.delitem(sys.modules, CANARY, raising=False)
    config = resolve_config(config_path=str(toml_config))

    _engine(tmp_path, config)

    _masked(log_records)


def test_report_import_log_names_the_entry_masked(
    tmp_path, env_read_importable_config, log_records
):
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    # A minimal results file where the report looks for one, so the render
    # reaches load_plugins whatever order it reads them in.
    results_dir = tmp_path / "src" / ".ash" / "ash_output"
    results_dir.mkdir(parents=True)
    (results_dir / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(), encoding="utf-8"
    )

    result = CliRunner().invoke(
        app, ["report", "--config", str(env_read_importable_config)]
    )

    assert result.exception is None or isinstance(result.exception, SystemExit), repr(
        result.exception
    )
    _masked(log_records)


# ---------------------------------------------------------------------------
# A plugin that crashes at import, naming its own module in the crash
# ---------------------------------------------------------------------------

#: The variable's value for these cells: a namespace package whose top-level
#: code raises with its own name in the message, as a plugin's own error text
#: can. Nothing else in these runs would print it.
CRASHING = "crashcanary_ash_plugins"


@pytest.fixture
def crashing_module(tmp_path, monkeypatch):
    """The crashing package, importable from a directory outside every
    scanned tree, named by the environment variable the configs read."""
    site = tmp_path / "site"
    (site / CRASHING).mkdir(parents=True)
    (site / CRASHING / "__init__.py").write_text(
        'raise ValueError(f"{__name__} cannot initialise")\n', encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.delitem(sys.modules, CRASHING, raising=False)
    monkeypatch.setenv("ASH_CRASHCANARY", CRASHING)
    yield CRASHING
    sys.modules.pop(CRASHING, None)


def _crash_named_masked(result, log_records) -> None:
    """The run was refused on the import failure (exit 3, like every import
    failure of a configured module), the refusal said only the error's kind --
    the crash's own text quotes the module's name -- and nowhere printed the
    value."""
    assert result.exit_code == 3, (result.exception, result.output)
    assert "ValueError, whose text is not shown" in result.output, result.output
    assert "cannot initialise" not in result.output, result.output
    assert CRASHING not in result.output, result.output
    leaked = [message for message in log_records if CRASHING in message]
    assert leaked == [], leaked


def _workspace_reading_the_crash(tmp_path, monkeypatch):
    """A one-project workspace whose project config reads the crashing module
    from the environment; the workspace root is the cwd."""
    root = tmp_path / "ws"
    config_dir = root / "api" / ".ash"
    config_dir.mkdir(parents=True)
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (config_dir / ".ash.yaml").write_text(
        "project_name: api\nash_plugin_modules:\n  - !ENV ${ASH_CRASHCANARY}\n",
        encoding="utf-8",
    )
    (root / "dev.code-workspace").write_text(
        '{"folders": [{"path": "api"}]}', encoding="utf-8"
    )
    monkeypatch.chdir(root)
    return "dev.code-workspace"


def test_a_single_scans_crash_line_names_the_module_masked(
    tmp_path, crashing_module, log_records, monkeypatch
):
    """Local mode: the engine imports the crashing module while the orchestrator
    is being built, and the failure handler prints the crash's own text."""
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    config_file = tmp_path / "cfg" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        "project_name: probe\nash_plugin_modules:\n  - !ENV ${ASH_CRASHCANARY}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(source)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--no-progress",
            "--source-dir",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            str(config_file),
        ],
    )

    _crash_named_masked(result, log_records)


def test_a_workspace_runs_crash_line_names_the_module_masked(
    tmp_path, crashing_module, log_records, monkeypatch
):
    """Workspace mode: the prewarm imports the crashing module before any
    project starts, and the run's failure handler prints the crash's text."""
    workspace = _workspace_reading_the_crash(tmp_path, monkeypatch)

    result = CliRunner().invoke(
        app,
        ["scan", "--no-progress", "--workspace", workspace, "--output-dir", "out"],
    )

    _crash_named_masked(result, log_records)


def test_the_mcp_workspace_tools_crash_answer_names_the_module_masked(
    tmp_path, crashing_module, log_records, monkeypatch
):
    """The MCP workspace tool imports the same modules in its selection
    pre-check and answers the crash with the error's text, which names the
    module: the answer and every log line show it masked, as the CLI does."""
    import asyncio
    import json

    from automated_security_helper.cli.mcp import source_delivery
    from automated_security_helper.cli.mcp import workspace as workspace_module
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    workspace = _workspace_reading_the_crash(tmp_path, monkeypatch)
    monkeypatch.setattr(source_delivery, "_SESSION_SOURCE_DIRS", {})
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "ws"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )

    response = asyncio.run(
        workspace_module.mcp_scan_workspace(
            workspace_file=str(tmp_path / "ws" / workspace),
            output_dir=str(tmp_path / "ws" / "out"),
        )
    )

    assert response["success"] is False, response
    assert response["exit_code"] == 3, response
    assert "ValueError, whose text is not shown" in response["error"], response
    assert "cannot initialise" not in response["error"], response
    assert CRASHING not in json.dumps(response), response
    leaked = [message for message in log_records if CRASHING in message]
    assert leaked == [], leaked


def test_a_workspace_dry_runs_crash_line_names_the_module_masked(
    tmp_path, crashing_module, log_records, monkeypatch
):
    """The dry run imports the same modules for its selection pre-check and
    names the crash with the real run's sentence, masked the same way."""
    workspace = _workspace_reading_the_crash(tmp_path, monkeypatch)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--no-progress",
            "--workspace",
            workspace,
            "--output-dir",
            "out",
            "--dry-run",
        ],
    )

    _crash_named_masked(result, log_records)
