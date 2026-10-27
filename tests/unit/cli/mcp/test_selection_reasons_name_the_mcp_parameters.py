# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan an MCP client starts names the client's parameters, not the CLI's flags.

The MCP workspace tool takes ``scanners`` and ``excluded_scanners``. A SKIPPED row for
a scanner they leave out, and the workspace's refusal of a selection no project could
run, name those parameters; a scan started from the CLI names ``--scanners`` and
``--exclude-scanners``. The scan phase and the workspace tell the two apart by
``selection_origin``, which only the MCP tool sets.

Three groups of cells:

* the row texts, from the scan phase itself, for each origin;
* the hops, driving the real chain -- ``mcp_scan_workspace`` ->
  ``build_project_scan_settings`` -> ``execute_workspace`` -> ``ASHScanOrchestrator``
  -> ``ScanExecutionEngine`` -> ``ScanPhase`` -- with only
  ``ScanPhase._execute_phase`` replaced, reading what it was called with. A mock of
  any layer between would agree with a chain that dropped the origin below it;
* the workspace's refusals of a selection, over MCP and from the CLI.

Self-contained: the stub scanner and the log capture are defined here.
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ExecutionPhase, ScannerStatus
from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


# ---------------------------------------------------------------------------
# The row texts
# ---------------------------------------------------------------------------


def _scanner_class(name: str):
    """A scanner whose tool is present and whose scan finds nothing."""

    class _Config(ScannerPluginConfigBase):
        pass

    class _Scanner(ScannerPluginBase):
        def model_post_init(self, context):
            if self.config is None:
                self.config = _Config(name=name)
            self.command = f"{name}-tool"
            super().model_post_init(context)

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            return SarifReport(
                version="2.1.0",
                runs=[Run(tool=Tool(driver=ToolComponent(name=name)), results=[])],
            )

    _Scanner.__name__ = f"{name.replace('-', '_')}_scanner"
    return _Scanner


@pytest.fixture
def context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
    )


def _scan(context, **phase_kwargs) -> AshAggregatedResults:
    """tool-a and tool-b through the scan phase, then the engine's metrics rebuild."""
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[_scanner_class("tool-a"), _scanner_class("tool-b")],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    results = phase._execute_phase(
        aggregated_results=aggregated, parallel=False, **phase_kwargs
    )
    return populate_metrics_from_unified_source(aggregated_results=results)


class _Records(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.INFO)
        self.messages: List[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@contextmanager
def _ash_log():
    from automated_security_helper.utils.log import ASH_LOGGER

    handler = _Records()
    saved_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.INFO)
    try:
        yield handler.messages
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(saved_level)


CLI_TEXTS = [
    pytest.param(
        {"excluded_scanners": ["tool-b"]},
        "excluded from this run (--exclude-scanners)",
        id="exclusion",
    ),
    pytest.param(
        {"enabled_scanners": ["tool-a"]}, "not named by --scanners", id="allowlist"
    ),
]


def _assert_names_no_flag(text: str) -> None:
    for flag in ("--scanners", "--exclude-scanners"):
        assert flag not in text, text


MCP_TEXTS = [
    pytest.param(
        {"excluded_scanners": ["tool-b"]},
        "excluded from this run (the excluded_scanners parameter)",
        id="exclusion",
    ),
    pytest.param(
        {"enabled_scanners": ["tool-a"]},
        "not named by the scanners parameter",
        id="allowlist",
    ),
]


@pytest.mark.parametrize("selection, expected", CLI_TEXTS)
def test_a_cli_selection_names_the_flags(context, selection, expected):
    """Control: with no origin given, the CLI's wording."""
    row = _scan(context, **selection).scanner_results["tool-b"]

    assert row.status == ScannerStatus.SKIPPED, row
    assert row.skipped_reason == expected, row.skipped_reason


@pytest.mark.parametrize("selection, expected", CLI_TEXTS)
def test_the_cli_origin_names_the_flags(context, selection, expected):
    row = _scan(context, selection_origin="cli", **selection).scanner_results["tool-b"]

    assert row.skipped_reason == expected, row.skipped_reason


@pytest.mark.parametrize("selection, expected", MCP_TEXTS)
def test_an_mcp_selection_names_the_parameters(context, selection, expected):
    with _ash_log() as messages:
        results = _scan(context, selection_origin="mcp", **selection)

    reloaded = populate_metrics_from_unified_source(
        aggregated_results=AshAggregatedResults.model_validate_json(
            results.model_dump_json()
        )
    )
    for when, model in [("as written", results), ("reloaded", reloaded)]:
        row = model.scanner_results["tool-b"]
        assert row.status == ScannerStatus.SKIPPED, f"{when}: {row!r}"
        assert row.skipped_reason == expected, f"{when}: {row.skipped_reason!r}"
        _assert_names_no_flag(row.skipped_reason)
    logged = [text for text in messages if "tool-b" in text and expected in text]
    assert logged, [text for text in messages if "tool-b" in text]


# ---------------------------------------------------------------------------
# The hops
# ---------------------------------------------------------------------------


class _PhaseSpy:
    """Records the keyword arguments ``_execute_phase`` receives.

    The replacement returns ``aggregated_results`` unchanged and sets
    ``_completed_scanners``, which the engine reads straight after the phase.
    """

    def __init__(self):
        self.calls: List[dict] = []

    def as_method(self):
        spy = self

        def _execute_phase(phase_self, aggregated_results, **kwargs):
            spy.calls.append(kwargs)
            phase_self._completed_scanners = []
            return aggregated_results

        return _execute_phase


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A one-project workspace, and a scan registry of this test's own."""
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    root = tmp_path / "work"
    (root / "api").mkdir(parents=True)
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8"
    )
    return workspace_file, tmp_path / "out"


async def _mcp_scan(workspace, **selection):
    from automated_security_helper.cli.mcp import workspace as workspace_module

    workspace_file, out = workspace
    return await workspace_module.mcp_scan_workspace(
        workspace_file=str(workspace_file), output_dir=str(out), **selection
    )


@pytest.mark.asyncio
async def test_an_mcp_workspace_scan_reaches_the_scan_phase_as_mcp(workspace):
    spy = _PhaseSpy()
    with patch.object(ScanPhase, "_execute_phase", spy.as_method()):
        response = await _mcp_scan(
            workspace, scanners=["bandit", "semgrep"], excluded_scanners=["semgrep"]
        )

    assert spy.calls, f"the scan phase never ran: {response}"
    assert [call.get("selection_origin") for call in spy.calls] == ["mcp"], spy.calls


def test_a_cli_scan_reaches_the_scan_phase_as_cli(tmp_path):
    """Control for the hop above: the CLI's own chain gives the origin "cli"."""
    from automated_security_helper.cli.scan import run_ash_scan_cli_command

    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    ctx = MagicMock()
    ctx.resilient_parsing = False
    ctx.invoked_subcommand = None
    ctx.args = []
    spy = _PhaseSpy()
    with patch.object(ScanPhase, "_execute_phase", spy.as_method()):
        run_ash_scan_cli_command(
            ctx,
            source_dir=str(source),
            output_dir=str(tmp_path / "out"),
            phases=[ExecutionPhase.SCAN],
            exclude_scanners=["semgrep"],
            progress=False,
            show_summary=False,
            quiet=True,
        )

    assert [call.get("selection_origin") for call in spy.calls] == ["cli"], spy.calls


# ---------------------------------------------------------------------------
# The workspace's refusals of a selection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_mcp_selection_that_cancels_itself_names_the_parameters(workspace):
    response = await _mcp_scan(
        workspace, scanners=["bandit"], excluded_scanners=["bandit"]
    )

    assert response["success"] is False, response
    error = str(response.get("error"))
    assert (
        "Every scanner named by the scanners parameter is also named by the "
        "excluded_scanners parameter, so the selection cancels itself: selected "
        "bandit; excluded bandit. Refused rather than guessed: an empty allowlist "
        "means 'every scanner' further down, so this would silently run the "
        "scanners you excluded and skip the ones you chose. Drop one of the two."
        in error
    ), error
    _assert_names_no_flag(error)


@pytest.mark.asyncio
async def test_an_mcp_selection_that_names_nothing_names_the_parameter(workspace):
    response = await _mcp_scan(workspace, scanners=["no-such-scanner"])

    assert response["success"] is False, response
    error = str(response.get("error"))
    assert "None of the requested scanners exist: no-such-scanner." in error, error
    assert "drop the scanners parameter to run them all." in error, error
    _assert_names_no_flag(error)


@pytest.mark.parametrize(
    "selection, expected",
    [
        pytest.param(
            {"enabled_scanners": ("bandit",), "excluded_scanners": ("bandit",)},
            "Every scanner named by --scanners is also named by --exclude-scanners, "
            "so the selection cancels itself: selected bandit; excluded bandit. "
            "Refused rather than guessed: an empty allowlist means 'every scanner' "
            "further down, so this would silently run the scanners you excluded and "
            "skip the ones you chose. Drop one of the two flags.",
            id="cancels-itself",
        ),
        pytest.param(
            {"enabled_scanners": ("no-such-scanner",)},
            "drop --scanners to run them all.",
            id="names-nothing",
        ),
    ],
)
def test_a_cli_selection_refusal_names_the_flags(tmp_path, selection, expected):
    """Control: settings built without an origin keep the CLI's wording."""
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        execute_workspace,
    )
    from automated_security_helper.workspace.resolver import resolve_workspace

    root = tmp_path / "work"
    (root / "api").mkdir(parents=True)
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8"
    )
    settings = ProjectScanSettings(output_dir=Path(tmp_path / "out"), **selection)

    def _no_orchestrator(**kwargs):
        raise AssertionError("a refused selection must not start a project")

    with pytest.raises(ScannerSelectionError) as refused:
        execute_workspace(
            resolve_workspace(workspace_file),
            settings,
            orchestrator_factory=_no_orchestrator,
        )

    assert expected in str(refused.value), str(refused.value)


# ---------------------------------------------------------------------------
# A selection naming only a scanner whose constructor raises
# ---------------------------------------------------------------------------
#
# The workspace pre-flight and the engine check both pass, because the CLASS is
# registered. Construction fails inside the scan phase, and a registered class that
# failed to construct is not a scanner that does not exist: the scan phase's backstop
# refusal ("None of the requested scanners exist ... Check the spelling") is not
# made for it. The run records the scanner ERROR under its registered name, with the
# constructor's error, and the completeness gate fails it (exit 1), where the
# refusal was a usage error (exit 5) for what is an internal failure.
#
# A selection naming no registered scanner at all is still refused at the backstop,
# in the selection's own wording for its origin.

CONSTRUCTOR_ERROR = "constructor failure for the selection cells"


def _raising_scanner_class(name: str):
    """A scanner that declares *name* and whose constructor raises."""
    declared = name

    class _Config(ScannerPluginConfigBase):
        name: str = declared

    class _Scanner(ScannerPluginBase[_Config]):
        def model_post_init(self, context):
            raise RuntimeError(CONSTRUCTOR_ERROR)

        def validate_plugin_dependencies(self) -> bool:  # pragma: no cover
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError  # pragma: no cover

        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            raise NotImplementedError  # pragma: no cover

    _Scanner.__name__ = f"{name.replace('-', '_')}_scanner"
    return _Scanner


def _phase_with_a_raising_scanner(context, **phase_kwargs):
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[_scanner_class("tool-a"), _raising_scanner_class("tool-boom")],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    return phase._execute_phase(
        aggregated_results=aggregated, parallel=False, **phase_kwargs
    )


@pytest.mark.parametrize(
    "origin", [{}, {"selection_origin": "mcp"}], ids=["cli", "mcp"]
)
def test_a_selection_of_a_scanner_that_cannot_construct_is_not_refused(context, origin):
    """The scanner is ERROR under its registered name, with the constructor's error."""
    results = populate_metrics_from_unified_source(
        aggregated_results=_phase_with_a_raising_scanner(
            context, enabled_scanners=["tool-boom"], **origin
        )
    )

    assert "tool-boom" in results.scanner_results, sorted(results.scanner_results)
    assert "tool_boom_scanner" not in results.scanner_results, sorted(
        results.scanner_results
    )
    assert results.scanner_results["tool-boom"].status == ScannerStatus.ERROR
    reports = json.dumps(results.additional_reports.get("tool-boom"))
    assert "could not be constructed" in reports, reports
    assert CONSTRUCTOR_ERROR in reports, reports
    assert results.scanner_results["tool-a"].status == ScannerStatus.SKIPPED


@pytest.mark.parametrize(
    "origin, expected",
    [
        pytest.param({}, "drop --scanners to run them all.", id="cli"),
        pytest.param(
            {"selection_origin": "mcp"},
            "drop the scanners parameter to run them all.",
            id="mcp",
        ),
    ],
)
def test_a_selection_naming_nothing_beside_one_that_cannot_construct_is_refused(
    context, origin, expected
):
    """Control: the backstop still refuses a name no registered scanner has."""
    from automated_security_helper.core.exceptions import ScannerSelectionError

    with pytest.raises(ScannerSelectionError) as refused:
        _phase_with_a_raising_scanner(
            context, enabled_scanners=["no-such-scanner"], **origin
        )

    error = str(refused.value)
    assert "None of the requested scanners exist: no-such-scanner." in error, error
    assert expected in error, error
    if origin:
        _assert_names_no_flag(error)


def _raise_in_bandits_constructor(monkeypatch):
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        bandit_scanner,
    )

    def _raise(self, _context):
        raise RuntimeError(CONSTRUCTOR_ERROR)

    monkeypatch.setattr(bandit_scanner.BanditScanner, "model_post_init", _raise)


@pytest.mark.asyncio
async def test_an_mcp_scan_of_a_scanner_that_cannot_construct_reports_the_error(
    workspace, monkeypatch
):
    """What the MCP client sees: bandit ERROR, and why, rather than a spelling hint."""
    _raise_in_bandits_constructor(monkeypatch)
    response = await _mcp_scan(workspace, scanners=["bandit"])

    rendered = json.dumps(response)
    assert "None of the requested scanners exist" not in rendered, rendered
    assert "Check the spelling" not in rendered, rendered
    assert "banditscanner" not in rendered, rendered
    assert response.get("exit_code") == 1, response
    (project,) = response["projects"]
    assert project["scanners"].get("bandit") == "ERROR", project
    assert "bandit" in project["incomplete_scanners"], project
    assert "could not be constructed" in rendered, rendered
    assert CONSTRUCTOR_ERROR in rendered, rendered
    _assert_names_no_flag(rendered)


def test_a_cli_scan_of_a_scanner_that_cannot_construct_exits_one(
    tmp_path, monkeypatch, capsys
):
    """The completeness gate's exit 1, not the usage error's 5."""
    import typer

    from automated_security_helper.cli.scan import run_ash_scan_cli_command

    _raise_in_bandits_constructor(monkeypatch)
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "out"
    ctx = MagicMock()
    ctx.resilient_parsing = False
    ctx.invoked_subcommand = None
    ctx.args = []

    try:
        run_ash_scan_cli_command(
            ctx,
            source_dir=str(source),
            output_dir=str(output),
            phases=[ExecutionPhase.SCAN],
            scanners=["bandit"],
            progress=False,
            show_summary=False,
            quiet=True,
        )
        exit_code = 0
    except typer.Exit as exited:
        exit_code = exited.exit_code
    except SystemExit as exited:
        # ScanIncompleteExit and ScanRefusedExit carry the code.
        exit_code = exited.code

    printed = capsys.readouterr()
    assert "None of the requested scanners exist" not in printed.err, printed.err
    assert exit_code == 1, (exit_code, printed.err)
    results = AshAggregatedResults.model_validate_json(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    assert results.scanner_results["bandit"].status == ScannerStatus.ERROR
    assert "banditscanner" not in results.scanner_results


# ---------------------------------------------------------------------------
# A scanner's error never carries a value the config read from the environment
# ---------------------------------------------------------------------------
#
# The operator's config can take an option from the environment (``${VAR}``), and
# an exception that names the option's value, a path the scanner could not open
# say, then carries that value. The scanner's error goes to its report, the
# project's and the workspace's results files, scanner_reasons in the MCP
# response, and ash.log, and env values are never written: each is redacted with
# the config's environment values, as error_text does for every other
# config-derived error.
#
# The option is bandit's ``config_file``, which only the operator sets: from a
# config inside the scanned tree it is replaced by the trusted base's value with
# a warning (config/tool_config_trust.confine_scanner_config_files), so a
# project's own ``.ash/ash.yaml`` could not carry it to the scanner. The
# operator's chain (``ASH_CONFIG``, outside the tree) resolves ``${VAR}`` for a
# local caller and is the config each project of a workspace scan starts from.

ENV_CANARY = "/nonexistent/ENVCANARY-scanner-error/bandit.toml"


@pytest.fixture(params=["elsewhere", "under-home"])
def env_value(request):
    """The value the environment gives the option.

    Under the home directory as well as elsewhere: a stored error's home
    directory is written as ``~``, and if that ran before the redaction the value
    would no longer match and would reach the sinks as ``~/...``. Redaction comes
    first, where the text is built, so the value is gone before anything rewrites
    its prefix.
    """
    if request.param == "under-home":
        return str(Path.home() / "ENVCANARY-scanner-error" / "bandit.toml")
    return ENV_CANARY


def _operator_config_reading_the_environment(workspace, monkeypatch, value):
    """The operator's ``ASH_CONFIG``, outside the scanned tree, gives bandit its
    config file from the environment."""
    workspace_file, _ = workspace
    monkeypatch.setenv("ASH_CONFIG_FILE_FROM_ENV", value)
    operator_dir = workspace_file.parent.parent / "operator"
    operator_dir.mkdir(parents=True, exist_ok=True)
    operator = operator_dir / "ash.yaml"
    operator.write_text(
        "project_name: api\n"
        "scanners:\n"
        "  bandit:\n"
        "    options:\n"
        "      config_file: ${ASH_CONFIG_FILE_FROM_ENV}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))


def _assert_no_env_value(workspace, response, records):
    _, out = workspace
    sinks = {
        "the MCP response": json.dumps(response),
        "the workspace results": (out / "ash_aggregated_results.json").read_text(
            encoding="utf-8"
        ),
        "the project results": (
            out / "projects" / "api" / "ash_aggregated_results.json"
        ).read_text(encoding="utf-8"),
        "ash.log": "\n".join(records),
    }
    carrying = [
        name for name, text in sinks.items() if "ENVCANARY-scanner-error" in text
    ]
    assert not carrying, f"the environment value is in {carrying}"


@pytest.mark.asyncio
async def test_a_constructor_error_carries_no_environment_value(
    workspace, monkeypatch, env_value
):
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        bandit_scanner,
    )

    _operator_config_reading_the_environment(workspace, monkeypatch, env_value)

    def _raise(self, _context):
        path = getattr(getattr(self.config, "options", None), "config_file", None)
        raise FileNotFoundError(2, "No such file or directory", str(path))

    monkeypatch.setattr(bandit_scanner.BanditScanner, "model_post_init", _raise)
    with _ash_log() as records:
        response = await _mcp_scan(workspace, scanners=["bandit"])

    (project,) = response["projects"]
    assert project["scanners"].get("bandit") == "ERROR", project
    # The control: the option did reach the constructor, so its error had the value
    # to carry.
    assert "could not be constructed" in json.dumps(response), response
    _assert_no_env_value(workspace, response, records)


@pytest.mark.asyncio
async def test_a_scan_error_carries_no_environment_value(
    workspace, monkeypatch, env_value
):
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        bandit_scanner,
    )

    _operator_config_reading_the_environment(workspace, monkeypatch, env_value)
    seen = []

    def _scan(self, target, target_type, global_ignore_paths=None, config=None):
        path = str(self.config.options.config_file)
        seen.append(path)
        raise RuntimeError(f"bandit could not read {path}")

    monkeypatch.setattr(
        bandit_scanner.BanditScanner, "validate_plugin_dependencies", lambda self: True
    )
    monkeypatch.setattr(bandit_scanner.BanditScanner, "scan", _scan)
    with _ash_log() as records:
        response = await _mcp_scan(workspace, scanners=["bandit"])

    assert seen and env_value in seen[0], seen
    (project,) = response["projects"]
    assert project["scanners"].get("bandit") == "ERROR", project
    _assert_no_env_value(workspace, response, records)


@pytest.mark.asyncio
@pytest.mark.parametrize("where", ["whole-call", "outside-the-targets"])
async def test_an_unexpected_scanner_failure_carries_no_environment_value(
    workspace, monkeypatch, env_value, where
):
    """The executor's catch-all records it with the per-target handler's redaction.

    whole-call: the scanner's run raises as a whole, so only _safe_execute_scanner
    sees it. outside-the-targets: it raises inside the run but before any target's
    own handler, which _execute_scanner logs and re-raises.
    """
    from automated_security_helper.core.phases import scanner_executor
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        bandit_scanner,
    )

    _operator_config_reading_the_environment(workspace, monkeypatch, env_value)
    monkeypatch.setattr(
        bandit_scanner.BanditScanner, "validate_plugin_dependencies", lambda self: True
    )
    seen = []

    def _raise(*_args, **_kwargs):
        value = os.environ["ASH_CONFIG_FILE_FROM_ENV"]
        seen.append(value)
        raise RuntimeError(f"bandit failed outside its targets: {value}")

    if where == "whole-call":
        monkeypatch.setattr(
            scanner_executor.ScannerExecutor, "_execute_scanner", _raise
        )
    else:
        monkeypatch.setattr(scanner_executor, "_ScannerHeartbeat", _raise)
    with _ash_log() as records:
        response = await _mcp_scan(workspace, scanners=["bandit"])

    assert seen == [env_value], seen
    _, out = workspace
    project_results = (
        out / "projects" / "api" / "ash_aggregated_results.json"
    ).read_text(encoding="utf-8")
    # The control: the failure itself was recorded.
    assert "Unexpected error in scanner bandit" in project_results, project_results
    _assert_no_env_value(workspace, response, records)


@pytest.mark.asyncio
@pytest.mark.parametrize("ending", ["returns-nothing", "raises"])
async def test_the_tools_own_lines_carry_no_environment_value(
    workspace, monkeypatch, env_value, ending
):
    """What the tool printed is kept without the value, and is not the reason.

    A tool's stdout and stderr can name an option the config read from the
    environment, a file it could not load say, and the executor keeps those
    lines beside its own message in the results. A scan() that returns no
    result is reported in ASH's own words: the tool's first stderr line is not
    the cause, and it can say anything.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        bandit_scanner,
    )

    _operator_config_reading_the_environment(workspace, monkeypatch, env_value)
    monkeypatch.setattr(
        bandit_scanner.BanditScanner, "validate_plugin_dependencies", lambda self: True
    )
    seen = []

    def _scan(self, target, target_type, global_ignore_paths=None, config=None):
        path = str(self.config.options.config_file)
        seen.append(path)
        self._process_command_response(
            {
                "stdout": f"bandit read its settings from {path}\n",
                "stderr": f"[main] WARNING could not load {path}\n",
            }
        )
        if ending == "raises":
            raise RuntimeError("bandit stopped")
        return None

    monkeypatch.setattr(bandit_scanner.BanditScanner, "scan", _scan)
    with _ash_log() as records:
        response = await _mcp_scan(workspace, scanners=["bandit"])

    assert seen and env_value in seen[0], seen
    (project,) = response["projects"]
    assert project["scanners"].get("bandit") == "ERROR", project
    reason = (project.get("scanner_reasons") or {}).get("bandit", "")
    if ending == "returns-nothing":
        assert reason in (
            "bandit returned no result on source",
            "bandit returned no result on converted",
        ), reason
    else:
        assert reason.startswith("Failed to execute bandit scanner on "), reason
    _, out = workspace
    project_results = (
        out / "projects" / "api" / "ash_aggregated_results.json"
    ).read_text(encoding="utf-8")
    # The control: the tool's lines were kept.
    assert "could not load" in project_results, project_results
    assert "read its settings from" in project_results, project_results
    _assert_no_env_value(workspace, response, records)


@pytest.mark.asyncio
@pytest.mark.parametrize("found", ["before-the-scan", "by-the-scan"])
async def test_a_missing_reason_carries_no_environment_value(
    workspace, monkeypatch, env_value, found
):
    """A MISSING row's reason, and its WARNING, are redacted before the tilde.

    The plugin's own explanation of what it is missing can name an option the
    config read from the environment. ScanPhase gives it when the dependency
    check fails before the scan (before-the-scan); the executor gives it when
    scan() reports its dependencies unavailable by returning nothing
    (by-the-scan). Redacted first, so a value under the home directory is
    still matched before it is written as ``~/...``.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        bandit_scanner,
    )

    _operator_config_reading_the_environment(workspace, monkeypatch, env_value)
    seen = []

    def _reason(self):
        path = str(self.config.options.config_file)
        seen.append(path)
        return f"bandit could not use its settings file {path}"

    monkeypatch.setattr(
        bandit_scanner.BanditScanner, "missing_dependency_reason", _reason
    )
    monkeypatch.setattr(
        bandit_scanner.BanditScanner,
        "validate_plugin_dependencies",
        lambda self: found == "by-the-scan",
    )
    monkeypatch.setattr(
        bandit_scanner.BanditScanner,
        "scan",
        lambda self, target, target_type, global_ignore_paths=None, config=None: False,
    )
    with _ash_log() as records:
        response = await _mcp_scan(workspace, scanners=["bandit"])

    assert seen and env_value in seen[0], seen
    (project,) = response["projects"]
    assert project["scanners"].get("bandit") == "MISSING", project
    reason = (project.get("scanner_reasons") or {}).get("bandit", "")
    # The control: the plugin's explanation is the reason.
    assert "bandit could not use its settings file" in reason, project
    _assert_no_env_value(workspace, response, records)


def _a_report_with_one_high_finding() -> SarifReport:
    """bandit's report for the source files: one HIGH finding, so the row is FAILED."""
    from automated_security_helper.schemas.sarif_schema_model import (
        ArtifactLocation,
        Level,
        Location,
        Message,
        Message1,
        PhysicalLocation,
        PhysicalLocation2,
        PropertyBag,
        Region,
        Result,
    )

    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="test")),
                results=[
                    Result(
                        ruleId="B101",
                        level=Level("error"),
                        message=Message(root=Message1(text="bandit finding")),
                        properties=PropertyBag(issue_severity="HIGH"),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation(
                                    root=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(uri="app.py"),
                                        region=Region(startLine=1),
                                    )
                                )
                            )
                        ],
                    )
                ],
            )
        ],
    )


@pytest.mark.asyncio
async def test_a_failed_rows_missing_reason_carries_no_environment_value(
    workspace, monkeypatch, env_value
):
    """FAILED on the source files and MISSING on the converted ones, redacted.

    The row keeps FAILED, since findings outrank a tree that did not run, and
    carries the missing tree's reason, "on the converted files: <reason>". That
    reason is the plugin's own explanation, which can name an option the config
    read from the environment. The FAILED row's reason is built from the same
    redacted reason as a MISSING row's, so the value reaches no sink here either,
    elsewhere or under the home directory. Neither the FAILED-with-a-missing-tree
    rows nor the redaction of the reason could carry this alone.
    """
    import zipfile

    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        bandit_scanner,
    )

    _operator_config_reading_the_environment(workspace, monkeypatch, env_value)
    workspace_file, out = workspace
    # An archive, so the converter writes files and the scan has a converted tree.
    with zipfile.ZipFile(workspace_file.parent / "api" / "bundle.zip", "w") as bundle:
        bundle.writestr("lib.py", "y = 2\n")
    seen = []
    scanned = []

    def _reason(self):
        path = str(self.config.options.config_file)
        seen.append(path)
        return f"bandit could not use its settings file {path}"

    def _scan(self, target, target_type, global_ignore_paths=None, config=None):
        scanned.append(target_type)
        if target_type == "converted":
            return False
        return _a_report_with_one_high_finding()

    monkeypatch.setattr(
        bandit_scanner.BanditScanner, "missing_dependency_reason", _reason
    )
    monkeypatch.setattr(
        bandit_scanner.BanditScanner, "validate_plugin_dependencies", lambda self: True
    )
    monkeypatch.setattr(bandit_scanner.BanditScanner, "scan", _scan)
    with _ash_log() as records:
        response = await _mcp_scan(workspace, scanners=["bandit"])

    # The controls: both trees were scanned, the row is FAILED, and it carries
    # the converted tree's reason, which held the value when the plugin gave it.
    assert sorted(scanned) == ["converted", "source"], scanned
    assert seen and env_value in seen[0], seen
    (project,) = response["projects"]
    assert project["scanners"].get("bandit") == "FAILED", project
    project_results = (
        out / "projects" / "api" / "ash_aggregated_results.json"
    ).read_text(encoding="utf-8")
    assert (
        "on the converted files: bandit could not use its settings file"
        in project_results
    ), project_results
    _assert_no_env_value(workspace, response, records)


@pytest.mark.asyncio
async def test_an_mcp_scan_whose_scan_raised_says_why(workspace, monkeypatch):
    """An executor ERROR's cause reaches the client, its stack trace does not."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        bandit_scanner,
    )

    def _scan(self, target, target_type, global_ignore_paths=None, config=None):
        raise RuntimeError("bandit scan crashed on purpose")

    monkeypatch.setattr(
        bandit_scanner.BanditScanner, "validate_plugin_dependencies", lambda self: True
    )
    monkeypatch.setattr(bandit_scanner.BanditScanner, "scan", _scan)
    response = await _mcp_scan(workspace, scanners=["bandit"])

    (project,) = response["projects"]
    assert project["scanners"].get("bandit") == "ERROR", project
    reason = project["scanner_reasons"].get("bandit") or ""
    assert "bandit scan crashed on purpose" in reason, project
    assert "Traceback" not in json.dumps(response), response
