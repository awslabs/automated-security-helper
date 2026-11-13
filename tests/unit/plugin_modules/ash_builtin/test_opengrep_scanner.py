"""Unit tests for Opengrep scanner version detection, metrics flags and the
refusal of patterns mode."""

import pytest
from unittest.mock import MagicMock, patch
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
    patterns_mode_refusal,
)

pytestmark = pytest.mark.unit


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


def test_patterns_mode_is_refused_before_a_command_is_built(test_plugin_context):
    """A configuration that sets ``patterns`` is refused while the scanner is built.

    opengrep runs a ``--pattern`` search only with ``--lang``, which no option of
    this scanner supplies, so the command the scanner used to build was started and
    failed at the tool. Red at the base: the scanner was built, its command carried
    one ``--pattern`` per entry and no ``--lang``, and nothing was raised. The
    refusal names the option, the missing language option and the rule-file shape,
    and no tool is started: the version probe is answered here and the spawn is a
    stand-in that records any call.
    """
    with (
        # Online, whatever ASH's offline mode is here, so the refusal is read
        # against the online argument build.
        patch.object(OpengrepScanner, "_scanner_offline", return_value=False),
        patch.object(OpengrepScanner, "_get_opengrep_version", return_value=(1, 15, 1)),
        patch.object(OpengrepScanner, "_run_subprocess") as spawn,
        pytest.raises(ScannerError) as refused,
    ):
        OpengrepScanner(
            context=test_plugin_context,
            config=OpengrepScannerConfig(
                options=OpengrepScannerConfigOptions(patterns=["eval($X)", "exec($X)"])
            ),
        )

    message = str(refused.value)
    assert message == patterns_mode_refusal(["eval($X)", "exec($X)"])
    assert "scanners.opengrep.options.patterns names 2 patterns" in message
    assert "--pattern" in message
    assert "--lang" in message
    assert "scanners.opengrep.options.config" in message
    spawn.assert_not_called()


def test_one_pattern_is_refused_in_the_singular(test_plugin_context):
    """The control for the count: one entry reads "1 pattern"."""
    with pytest.raises(ScannerError) as refused:
        OpengrepScanner(
            context=test_plugin_context,
            config=OpengrepScannerConfig(
                options=OpengrepScannerConfigOptions(patterns=["eval($X)"])
            ),
        )

    assert "names 1 pattern," in str(refused.value)


def test_rules_mode_is_not_refused(test_plugin_context):
    """The control: the default, no patterns, builds its rules command as before."""
    scanner = OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(options=OpengrepScannerConfigOptions()),
    )

    keys = [arg.key for arg in scanner.args.extra_args]
    assert "--config" in keys
    assert "--pattern" not in keys
