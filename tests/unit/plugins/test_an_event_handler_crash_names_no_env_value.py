# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An event handler's failure text is redacted with the run's config values.

A plugin module subscribes event handlers through ``ASH_EVENT_HANDLERS``, and
a handler is plugin code: its exception can quote anything, here a value the
project's config also read from the environment. One module's handler fails
at every event the engine notifies around a run. The engine logs the
EXECUTION_START, ERROR and EXECUTION_COMPLETE failures and moves past them;
the CONVERT_PHASE_START failure ends the scan before any tool starts. The
engine's log lines and the orchestrator's error carry the config's
environment values, so every surface shows the redacted text: the console,
the log records, the files in the output directory and the MCP workspace
tool's answer.

The engine carries the values onto what it raises, so those runs cannot tell
whether the orchestrator's own lines and errors are redacted as well. The
cells at the end drive the orchestrator with an engine that carries nothing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.utils.log import ASH_LOGGER

#: A value the config reads from the environment for an ignore path's reason,
#: which the handlers quote. Nothing else in these runs prints it.
QUOTED = "zzhandler-secret-6604"
#: The handler module, named literally in the config.
HANDLERS = "k1handlers_ash_plugins"


class _Sink(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.messages: list = []

    def emit(self, record):
        self.messages.append(self.format(record))


@pytest.fixture
def log_records():
    sink = _Sink()
    level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(sink)
    ASH_LOGGER.setLevel(1)
    yield sink.messages
    ASH_LOGGER.removeHandler(sink)
    ASH_LOGGER.setLevel(level)


@pytest.fixture
def handler_module(tmp_path, monkeypatch):
    """The handler package, importable from outside every scanned tree.

    Its handlers stay subscribed once a run has loaded it: the manager has no
    way to take a subscription back, and nothing outside it touches its
    registry. They act in no other test. A run notifies only the handlers of
    the modules it loaded, no other test loads this one, and a handler does
    nothing once the variable it quotes is unset, which monkeypatch does when
    the test ends.
    """
    site = tmp_path / "site"
    (site / HANDLERS).mkdir(parents=True)
    (site / HANDLERS / "__init__.py").write_text(
        "import os\n"
        "from automated_security_helper.plugins.events import AshEventType\n"
        "\n"
        "\n"
        "def _quote(*args, **kwargs):\n"
        '    value = os.environ.get("ASH_K1CANARY")\n'
        "    if value:\n"
        '        raise ValueError(f"phase handler cannot use {value}")\n'
        "\n"
        "\n"
        "ASH_EVENT_HANDLERS = {\n"
        "    AshEventType.EXECUTION_START: [_quote],\n"
        "    AshEventType.CONVERT_PHASE_START: [_quote],\n"
        "    AshEventType.ERROR: [_quote],\n"
        "    AshEventType.EXECUTION_COMPLETE: [_quote],\n"
        "}\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.delitem(sys.modules, HANDLERS, raising=False)
    monkeypatch.setenv("ASH_K1CANARY", QUOTED)
    yield HANDLERS
    sys.modules.pop(HANDLERS, None)


_CONFIG = (
    "project_name: {name}\n"
    "global_settings:\n"
    "  ignore_paths:\n"
    "    - path: vendor/**\n"
    "      reason: !ENV ${{ASH_K1CANARY}}\n"
    f"ash_plugin_modules:\n  - {HANDLERS}\n"
)


def _files_quoting(directory) -> list:
    """Every file under *directory* (the test's own output tree) that holds
    the quoted value."""
    if not directory.exists():
        return []
    return [
        str(path)
        for path in directory.rglob("*")
        if path.is_file()
        and QUOTED in path.read_text(encoding="utf-8", errors="replace")
    ]


def _redacted(output: str, log_records: list, out_dir) -> None:
    assert "phase handler cannot use" in output, output
    assert QUOTED not in output, output
    leaked = [message for message in log_records if QUOTED in message]
    assert leaked == [], leaked
    assert _files_quoting(out_dir) == []


def test_a_single_scans_handler_failure_is_redacted_on_every_surface(
    tmp_path, handler_module, log_records, monkeypatch
):
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    config_file = tmp_path / "cfg" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(_CONFIG.format(name="probe"), encoding="utf-8")
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

    assert result.exit_code == 1, (result.exception, result.output)
    _redacted(result.output, log_records, tmp_path / "out")
    for event in ("execution start", "execution error", "execution complete"):
        logged = any(
            f"Failed to notify {event} event: phase handler cannot use" in message
            for message in log_records
        )
        assert logged, f"no record of the {event} handler's failure"


@pytest.fixture
def workspace(tmp_path, handler_module, monkeypatch):
    root = tmp_path / "ws"
    config_dir = root / "api" / ".ash"
    config_dir.mkdir(parents=True)
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (config_dir / ".ash.yaml").write_text(_CONFIG.format(name="api"), encoding="utf-8")
    (root / "dev.code-workspace").write_text(
        '{"folders": [{"path": "api"}]}', encoding="utf-8"
    )
    monkeypatch.chdir(root)
    return root


def test_a_workspace_runs_handler_failure_is_redacted_on_every_surface(
    workspace, log_records
):
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

    assert result.exit_code != 0, (result.exception, result.output)
    _redacted(result.output, log_records, workspace / "out")


def test_the_mcp_workspace_tools_handler_failure_is_redacted(
    workspace, tmp_path, log_records, monkeypatch
):
    from automated_security_helper.cli.mcp import source_delivery
    from automated_security_helper.cli.mcp import workspace as workspace_module
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

    response = asyncio.run(
        workspace_module.mcp_scan_workspace(
            workspace_file=str(workspace / "dev.code-workspace"),
            output_dir=str(workspace / "out"),
        )
    )

    assert QUOTED not in json.dumps(response), response
    leaked = [message for message in log_records if QUOTED in message]
    assert leaked == [], leaked
    assert _files_quoting(workspace / "out") == []


#: The value the completion handler quotes, and its package. Apart from the
#: package above, because that one fails the run at CONVERT_PHASE_START, and a
#: completion handler that fails while a run's error propagates is chained to
#: that error, whose values redact it. A run that succeeds has no such error.
COMPLETE_QUOTED = "zzcomplete-secret-7713"
COMPLETE_HANDLERS = "k1complete_ash_plugins"


@pytest.fixture
def complete_handler_module(tmp_path, monkeypatch):
    """A package whose only handler fails at EXECUTION_COMPLETE, quoting the
    value, and does nothing once the variable is unset (as handler_module)."""
    site = tmp_path / "complete-site"
    (site / COMPLETE_HANDLERS).mkdir(parents=True)
    (site / COMPLETE_HANDLERS / "__init__.py").write_text(
        "import os\n"
        "from automated_security_helper.plugins.events import AshEventType\n"
        "\n"
        "\n"
        "def _quote(*args, **kwargs):\n"
        '    value = os.environ.get("ASH_K1CCANARY")\n'
        "    if value:\n"
        '        raise ValueError(f"complete handler cannot use {value}")\n'
        "\n"
        "\n"
        "ASH_EVENT_HANDLERS = {AshEventType.EXECUTION_COMPLETE: [_quote]}\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.delitem(sys.modules, COMPLETE_HANDLERS, raising=False)
    monkeypatch.setenv("ASH_K1CCANARY", COMPLETE_QUOTED)
    yield COMPLETE_HANDLERS
    sys.modules.pop(COMPLETE_HANDLERS, None)


def test_a_completion_handler_failing_after_a_run_that_succeeded_is_redacted(
    tmp_path, complete_handler_module, log_records, monkeypatch
):
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    config_file = tmp_path / "cfg" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        "project_name: probe\n"
        "global_settings:\n"
        "  ignore_paths:\n"
        "    - path: vendor/**\n"
        "      reason: !ENV ${ASH_K1CCANARY}\n"
        f"ash_plugin_modules:\n  - {COMPLETE_HANDLERS}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(source)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--no-progress",
            "--phases",
            "convert",
            "--source-dir",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            str(config_file),
        ],
    )

    assert result.exit_code == 0, (result.exception, result.output)
    logged = any(
        "Failed to notify execution complete event: complete handler cannot use"
        in message
        for message in log_records
    )
    assert logged, "no record of the completion handler's failure"
    assert COMPLETE_QUOTED not in result.output, result.output
    leaked = [message for message in log_records if COMPLETE_QUOTED in message]
    assert leaked == [], leaked
    out = tmp_path / "out"
    in_files = [
        str(path)
        for path in out.rglob("*")
        if path.is_file()
        and COMPLETE_QUOTED in path.read_text(encoding="utf-8", errors="replace")
    ]
    assert in_files == []


class _EngineCarryingNothing:
    """Stands in for the execution engine. ``execute_phases`` raises *error*
    as it was built, with no values on it, unlike the real engine."""

    def __init__(self, error: BaseException):
        self._asharp_model = None
        self._error = error

    def execute_phases(self, phases=None):
        raise self._error


def _orchestrator(tmp_path, monkeypatch, engine, **overrides):
    """An initialized orchestrator whose config read QUOTED from the
    environment, loaded the way a run loads it, with *engine* as its engine."""
    from automated_security_helper.config import resolve_config as resolve_module
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils.error_text import config_environment_values

    AshConfig.model_rebuild()
    AshAggregatedResults.model_rebuild()
    monkeypatch.setenv("ASH_K1CANARY", QUOTED)
    config_file = tmp_path / "cfg" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        "project_name: probe\n"
        "global_settings:\n"
        "  ignore_paths:\n"
        "    - path: vendor/**\n"
        "      reason: !ENV ${ASH_K1CANARY}\n",
        encoding="utf-8",
    )
    _, config = resolve_module.load_config_file_for_run(config_file)
    known = QUOTED in config_environment_values(config)
    assert known, "the config does not know the value it read"
    source = tmp_path / "src"
    source.mkdir()
    orchestrator = ASHScanOrchestrator(
        source_dir=source,
        output_dir=tmp_path / "out",
        config_path=None,
        config_overrides=None,
        no_cleanup=False,
        metadata=None,
        ash_plugin_modules=[],
        **overrides,
    )
    with (
        patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=config,
        ),
        patch(
            "automated_security_helper.core.orchestrator.ScanExecutionEngine",
            return_value=engine,
        ),
    ):
        orchestrator.initialize()
    return orchestrator


def _printed_redacted(error: BaseException) -> None:
    """What the run's handlers print for *error*: they hold no config, so they
    pass no values, and only what the error carries can redact it."""
    from automated_security_helper.utils.error_text import error_text, traceback_text

    assert QUOTED not in error_text(error)
    assert QUOTED not in traceback_text(error)


def _lines_redacted(log_records: list, expected: str) -> None:
    assert any(expected in message for message in log_records), log_records
    leaked = [message for message in log_records if QUOTED in message]
    assert leaked == [], leaked


def test_the_orchestrators_lines_about_an_engine_failure_are_redacted(
    tmp_path, monkeypatch, log_records
):
    from automated_security_helper.core.exceptions import ASHValidationError

    engine = _EngineCarryingNothing(ValueError(f"engine cannot use {QUOTED}"))
    orchestrator = _orchestrator(tmp_path, monkeypatch, engine)

    with patch("automated_security_helper.core.orchestrator.scan_set", return_value=[]):
        with pytest.raises(ASHValidationError) as raised:
            orchestrator.execute_scan()

    assert "Scan execution failed: engine cannot use" in str(raised.value)
    assert QUOTED not in str(raised.value)
    _printed_redacted(raised.value)
    _lines_redacted(log_records, "Execution failed: engine cannot use")
    _lines_redacted(
        log_records, "Unexpected error during scan execution: engine cannot use"
    )


def test_a_validation_error_from_the_engine_leaves_carrying_the_values(
    tmp_path, monkeypatch, log_records
):
    from automated_security_helper.core.exceptions import ASHValidationError

    refused = ASHValidationError(f"engine refused {QUOTED}")
    engine = _EngineCarryingNothing(refused)
    orchestrator = _orchestrator(tmp_path, monkeypatch, engine)

    with patch("automated_security_helper.core.orchestrator.scan_set", return_value=[]):
        with pytest.raises(ASHValidationError) as raised:
            orchestrator.execute_scan()

    assert raised.value is refused
    _printed_redacted(raised.value)
    _lines_redacted(log_records, "Execution failed: engine refused")


def test_a_failed_reload_of_the_existing_results_is_redacted(
    tmp_path, monkeypatch, log_records
):
    from automated_security_helper.core.exceptions import ASHValidationError
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    existing = tmp_path / "existing.json"
    existing.write_text(AshAggregatedResults().model_dump_json(), encoding="utf-8")
    engine = _EngineCarryingNothing(AssertionError("the engine never runs"))
    orchestrator = _orchestrator(
        tmp_path, monkeypatch, engine, existing_results_path=existing
    )

    with patch.object(
        AshAggregatedResults,
        "from_json",
        side_effect=ValueError(f"results cannot use {QUOTED}"),
    ):
        with pytest.raises(ASHValidationError) as raised:
            orchestrator.execute_scan(phases=["report"])

    assert "Failed to load existing results: results cannot use" in str(raised.value)
    assert QUOTED not in str(raised.value)
    _printed_redacted(raised.value)
    _lines_redacted(log_records, "Failed to load existing results: results cannot use")
