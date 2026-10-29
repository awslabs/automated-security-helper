"""Unit tests for Opengrep scanner version detection, metrics flags and patterns mode."""

import json
from pathlib import Path

import pytest
from unittest.mock import MagicMock, patch
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport


@pytest.fixture(autouse=True)
def _unresolved_names_reach_the_mocked_spawn(monkeypatch):
    """Hand names that resolve nowhere to the mocked subprocess.run on Windows too.

    opengrep is not installed here, and on Windows ASH refuses an unresolved name
    before spawning it (subprocess_utils._refuse_unresolved_on_windows). These tests
    are about what the version probe does with the spawn's answer.
    """
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "_refuse_unresolved_on_windows", False)


@pytest.fixture
def opengrep_scanner(test_plugin_context):
    """Create a test Opengrep scanner."""
    return OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(),
    )


def test_get_opengrep_version_success(opengrep_scanner):
    """Test successful version detection."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "opengrep 1.15.1"

    with patch(
        "automated_security_helper.utils.subprocess_utils._run_plain",
        return_value=mock_result,
    ):
        version = opengrep_scanner._get_opengrep_version()
        assert version == (1, 15, 1)


def test_get_opengrep_version_with_v_prefix(opengrep_scanner):
    """Test version detection with 'v' prefix."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "v1.6.0"

    with patch(
        "automated_security_helper.utils.subprocess_utils._run_plain",
        return_value=mock_result,
    ):
        version = opengrep_scanner._get_opengrep_version()
        assert version == (1, 6, 0)


def test_get_opengrep_version_failure(opengrep_scanner):
    """Test version detection failure."""
    with patch(
        "automated_security_helper.utils.subprocess_utils._run_plain",
        side_effect=Exception("Command failed"),
    ):
        version = opengrep_scanner._get_opengrep_version()
        assert version is None


def test_should_use_metrics_flag_old_version(opengrep_scanner):
    """Test metrics flag should be used for versions < 1.7.0."""
    with patch.object(
        opengrep_scanner, "_get_opengrep_version", return_value=(1, 6, 0)
    ):
        assert opengrep_scanner._should_use_metrics_flag() is True


def test_should_use_metrics_flag_new_version(opengrep_scanner):
    """Test metrics flag should not be used for versions >= 1.7.0."""
    with patch.object(
        opengrep_scanner, "_get_opengrep_version", return_value=(1, 7, 0)
    ):
        assert opengrep_scanner._should_use_metrics_flag() is False


def test_should_use_metrics_flag_newer_version(opengrep_scanner):
    """Test metrics flag should not be used for versions > 1.7.0."""
    with patch.object(
        opengrep_scanner, "_get_opengrep_version", return_value=(1, 15, 1)
    ):
        assert opengrep_scanner._should_use_metrics_flag() is False


def test_should_use_metrics_flag_unknown_version(opengrep_scanner):
    """Test metrics flag defaults to False when version cannot be determined."""
    with patch.object(opengrep_scanner, "_get_opengrep_version", return_value=None):
        assert opengrep_scanner._should_use_metrics_flag() is False


def test_process_config_options_offline_old_version(
    test_plugin_context, monkeypatch, tmp_path
):
    """Test offline mode with old version includes metrics flag."""
    (tmp_path / "rules.yaml").write_text("rules: []")
    monkeypatch.setenv("OPENGREP_RULES_CACHE_DIR", str(tmp_path))

    scanner = OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=True)
        ),
    )

    # Reset extra_args so we can inspect a clean _process_config_options run
    scanner.args.extra_args = []
    with patch.object(scanner, "_should_use_metrics_flag", return_value=True):
        scanner._process_config_options()

        metrics_args = [
            arg for arg in scanner.args.extra_args if arg.key == "--metrics"
        ]
        assert len(metrics_args) == 1
        assert metrics_args[0].value == "off"


def test_process_config_options_offline_new_version(
    test_plugin_context, monkeypatch, tmp_path
):
    """Test offline mode with new version excludes metrics flag."""
    (tmp_path / "rules.yaml").write_text("rules: []")
    monkeypatch.setenv("OPENGREP_RULES_CACHE_DIR", str(tmp_path))

    scanner = OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=True)
        ),
    )

    # Reset extra_args so we can inspect a clean _process_config_options run
    scanner.args.extra_args = []
    with patch.object(scanner, "_should_use_metrics_flag", return_value=False):
        scanner._process_config_options()

        metrics_args = [
            arg for arg in scanner.args.extra_args if arg.key == "--metrics"
        ]
        assert len(metrics_args) == 0


def test_process_config_options_online_old_version(test_plugin_context):
    """Test online mode with old version includes metrics flag."""
    scanner = OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=False, metrics="auto")
        ),
    )

    with patch.object(scanner, "_should_use_metrics_flag", return_value=True):
        scanner._process_config_options()

        metrics_args = [
            arg for arg in scanner.args.extra_args if arg.key == "--metrics"
        ]
        assert len(metrics_args) == 1
        assert metrics_args[0].value == "auto"


def test_process_config_options_online_new_version(test_plugin_context):
    """Test online mode with new version excludes metrics flag."""
    scanner = OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=False, metrics="auto")
        ),
    )

    with patch.object(scanner, "_should_use_metrics_flag", return_value=False):
        scanner._process_config_options()

        metrics_args = [
            arg for arg in scanner.args.extra_args if arg.key == "--metrics"
        ]
        assert len(metrics_args) == 0


def test_patterns_mode_reads_the_results_file_its_command_writes(tmp_path):
    """Patterns mode moves the results file to opengrep_results.json.

    _execute_scan resolves the command a second time after the move. Without that,
    the command still names results_sarif.sarif: opengrep writes its report there
    and the scan reads a file nothing wrote. No opengrep runs here: the spawn is a
    stand-in that writes an empty report where the command says, and the version
    probe and the tool check are answered without it.
    """
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    commands = []

    def opengrep(command, **_kwargs):
        commands.append(command)
        output = Path(command[command.index("--sarif-output") + 1])
        output.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [{"tool": {"driver": {"name": "opengrep"}}, "results": []}],
                }
            ),
            encoding="utf-8",
        )
        return {"returncode": 0}

    with (
        # Online, whatever ASH's offline mode is here: offline without a rule
        # cache, the scanner declines before it builds a command.
        patch.object(OpengrepScanner, "_scanner_offline", return_value=False),
        patch.object(OpengrepScanner, "_get_opengrep_version", return_value=(1, 15, 1)),
        patch.object(OpengrepScanner, "_validate_tool_dependencies", return_value=True),
        patch.object(OpengrepScanner, "_run_subprocess", side_effect=opengrep),
    ):
        scanner = OpengrepScanner(
            context=context,
            config=OpengrepScannerConfig(
                options=OpengrepScannerConfigOptions(patterns=["eval($X)"])
            ),
        )
        report = scanner.scan(target=source, target_type="source")

    (command,) = commands
    assert command[command.index("--pattern") + 1] == "eval($X)"
    assert "--json" in command
    written = Path(command[command.index("--sarif-output") + 1])
    assert written.name == "opengrep_results.json", command
    assert isinstance(report, SarifReport)
    assert len(report.runs) == 1
