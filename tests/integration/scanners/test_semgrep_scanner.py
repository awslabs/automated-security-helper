"""Tests for Semgrep scanner."""

import pytest
from pathlib import Path
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)


@pytest.fixture
def test_semgrep_scanner(test_plugin_context):
    """Create a test Semgrep scanner."""
    return SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(),
    )


@pytest.fixture
def semgrep_rule_cache(tmp_path, monkeypatch):
    """A populated offline rule cache, which offline mode requires.

    ``_configure_offline_mode`` validates ``$SEMGREP_RULES_CACHE_DIR`` through
    ``OfflineModeValidator.validate_cache_directory`` and raises ``ScannerError``
    when it holds no ``.yaml``/``.yml`` files. That guard is correct -- running
    offline with no rules would scan nothing and report clean -- so a test that
    turns offline mode on has to supply the cache rather than avoid the check.

    Turning offline mode off instead would be the wrong repair: these two tests
    exist to exercise the offline path.
    """
    cache = tmp_path / "semgrep-rules"
    cache.mkdir()
    # One real-shaped rule file is enough for the validator, which checks for the
    # extensions rather than parsing them.
    (cache / "rules.yaml").write_text(
        "rules:\n"
        "  - id: ash-test-placeholder\n"
        "    languages: [python]\n"
        "    message: placeholder\n"
        "    severity: INFO\n"
        "    pattern: $X == $X\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(cache))
    return cache


def test_semgrep_scanner_init(test_plugin_context):
    """Test SemgrepScanner initialization."""
    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(),
    )
    assert scanner.config.name == "semgrep"
    assert scanner.command == "semgrep"
    assert scanner.tool_type == ScannerToolType.SAST
    assert scanner.use_uv_tool is True  # Verify UV tool is enabled


def test_semgrep_scanner_validate(test_semgrep_scanner):
    """Test SemgrepScanner validation."""
    assert test_semgrep_scanner.validate_plugin_dependencies() is True


def test_semgrep_scanner_uv_tool_integration(test_plugin_context):
    """Test SemgrepScanner UV tool integration."""
    import unittest.mock

    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(),
    )

    # Verify UV tool is enabled
    assert scanner.use_uv_tool is True
    assert scanner.command == "semgrep"

    # Test UV tool version detection
    with unittest.mock.patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
    ) as mock_runner:
        mock_runner_instance = unittest.mock.MagicMock()
        mock_runner.return_value = mock_runner_instance
        mock_runner_instance.is_uv_available.return_value = True
        mock_runner_instance.get_tool_version.return_value = "1.125.0"

        # Test version detection
        version = scanner._get_uv_tool_version("semgrep")
        assert version == "1.125.0"
        # Asserted against the scanner's own ``--from`` spec rather than a
        # literal, so a version-constraint bump does not break this test while
        # still pinning the property #426 and #549 added: the probe must run under
        # the same ``--from`` environment the scan will use. ``uv tool run semgrep``
        # and ``uv tool run --from '<spec>' semgrep`` resolve to different
        # environments, and stevedore's entry-point cache is keyed on
        # ``sys.executable``/``sys.prefix``, so probing the wrong one leaves the
        # scan's cache cold. The bare-name assertion this replaces could not tell
        # those two invocations apart.
        mock_runner_instance.get_tool_version.assert_called_with(
            "semgrep", scanner._uv_from_spec()
        )

    # Test validation with UV tool available
    with unittest.mock.patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
    ) as mock_runner:
        mock_runner_instance = unittest.mock.MagicMock()
        mock_runner.return_value = mock_runner_instance
        mock_runner_instance.is_uv_available.return_value = True

        assert scanner.validate_plugin_dependencies() is True

    # Test validation with UV tool unavailable but direct executable available
    with (
        unittest.mock.patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_runner,
        unittest.mock.patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners."
            "semgrep_scanner.get_uv_tool_command"
        ) as mock_find,
    ):
        mock_runner_instance = unittest.mock.MagicMock()
        mock_runner.return_value = mock_runner_instance
        mock_runner_instance.is_uv_available.return_value = False
        mock_find.return_value = "/usr/local/bin/semgrep"

        assert scanner.validate_plugin_dependencies() is True
        assert scanner.use_uv_tool is False  # Should be disabled after fallback

    # Restore the flag before the next case. These four blocks share one scanner
    # instance, and the fallback above leaves use_uv_tool False --
    # _validate_uv_tool_availability returns True immediately when it is False, so
    # the next case would skip the resolver entirely and pass for the wrong reason
    # regardless of what its mock returns.
    scanner.use_uv_tool = True

    # Test validation with neither UV tool nor direct executable available
    with (
        unittest.mock.patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_runner,
        unittest.mock.patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners."
            "semgrep_scanner.get_uv_tool_command"
        ) as mock_find,
    ):
        mock_runner_instance = unittest.mock.MagicMock()
        mock_runner.return_value = mock_runner_instance
        mock_runner_instance.is_uv_available.return_value = False
        mock_find.return_value = None

        assert scanner.validate_plugin_dependencies() is False


def test_semgrep_scanner_configure(test_plugin_context, semgrep_rule_cache):
    """Test SemgrepScanner configuration."""
    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(
                config="p/security-audit",
                exclude=["*.test.py", "test_*"],
                exclude_rule=["generic.secrets.security.detected-private-key"],
                severity=["ERROR", "WARNING"],
                metrics="off",
                offline=True,
            )
        ),
    )
    assert scanner.config.options.config == "p/security-audit"
    assert "*.test.py" in scanner.config.options.exclude
    assert (
        "generic.secrets.security.detected-private-key"
        in scanner.config.options.exclude_rule
    )
    assert "ERROR" in scanner.config.options.severity
    assert scanner.config.options.metrics == "off"
    assert scanner.config.options.offline is True


def test_semgrep_scanner_scan(test_semgrep_scanner, test_data_dir):
    """Test SemgrepScanner scan method."""
    # Mock the scan to avoid actual execution
    import unittest.mock

    with (
        unittest.mock.patch.object(test_semgrep_scanner, "_run_subprocess"),
        unittest.mock.patch("builtins.open", unittest.mock.mock_open(read_data="{}")),
        unittest.mock.patch("json.load", return_value={}),
    ):
        # Run the scan
        results = test_semgrep_scanner.scan(test_data_dir, target_type="source")

    # Check that results were returned
    assert results is not None


def test_semgrep_scanner_scan_error(test_semgrep_scanner):
    """Test SemgrepScanner scan method with error."""
    # Try to scan a non-existent directory
    resp = test_semgrep_scanner.scan(Path("nonexistent"), target_type="source")
    assert resp is not None
    assert resp is True
    assert (
        "(semgrep) Target directory nonexistent is empty or doesn't exist. Skipping scan."
        in test_semgrep_scanner.errors
    )


def test_process_config_options_offline_mode(test_plugin_context, semgrep_rule_cache):
    """Test processing of offline mode options."""
    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(
                offline=True,
            )
        ),
    )
    scanner._process_config_options()

    # Check that offline mode arguments were added
    extra_args = [arg.key for arg in scanner.args.extra_args]
    assert "--metrics" in extra_args


def test_process_config_options_exclude_patterns(test_plugin_context):
    """Test processing of exclude pattern options."""
    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(
                exclude=["*.test.py", "test_*", "examples/*"],
            )
        ),
    )
    scanner._process_config_options()

    # Check that exclude arguments were added
    exclude_args = [arg.key for arg in scanner.args.extra_args]
    assert "--exclude" in exclude_args


def test_process_config_options_severity_filters(test_plugin_context):
    """Test processing of severity filter options."""
    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(
                severity=["ERROR", "WARNING"],
            )
        ),
    )
    scanner._process_config_options()

    # Check that severity arguments were added
    severity_args = [arg.key for arg in scanner.args.extra_args]
    assert "--severity" in severity_args
