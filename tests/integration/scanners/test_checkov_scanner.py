"""Tests for Checkov scanner."""

import pytest
from pathlib import Path
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)
from automated_security_helper.models.core import IgnorePathWithReason


@pytest.fixture
def test_checkov_scanner(test_plugin_context):
    """Create a test Checkov scanner."""
    return CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(),
    )


def test_checkov_scanner_init(test_plugin_context):
    """Test CheckovScanner initialization."""
    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(),
    )
    assert scanner.config.name == "checkov"
    assert scanner.command == "checkov"
    assert scanner.tool_type == "IAC"


def test_checkov_scanner_validate(test_checkov_scanner):
    """Test CheckovScanner validation."""
    assert test_checkov_scanner.validate() is True


def test_checkov_scanner_configure(test_plugin_context):
    """Test CheckovScanner configuration."""
    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                config_file=".checkov.yaml",
                skip_path=[IgnorePathWithReason(path="tests/*", reason="Test files")],
                frameworks=["terraform", "cloudformation"],
                skip_frameworks=["secrets"],
                additional_formats=["json", "junitxml"],
            )
        ),
    )
    assert scanner.config.options.config_file == ".checkov.yaml"
    assert len(scanner.config.options.skip_path) == 1
    assert scanner.config.options.skip_path[0].path == "tests/*"
    assert "terraform" in scanner.config.options.frameworks
    assert "secrets" in scanner.config.options.skip_frameworks
    assert "json" in scanner.config.options.additional_formats


@pytest.mark.parametrize(
    "config_file",
    [
        ".checkov.yaml",
        ".checkov.yml",
        "custom_checkov.yaml",
    ],
)
def test_process_config_options_with_config_files(
    config_file, test_source_dir, test_plugin_context
):
    """Test processing of different config file types."""
    config_path = test_source_dir.joinpath(config_file)
    config_path.touch()

    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                config_file=config_path.as_posix(),
            )
        ),
    )
    scanner._process_config_options()

    # Check that the config file argument was added
    config_args = [arg.key for arg in scanner.args.extra_args]
    assert "--config-file" in config_args


def test_process_config_options_frameworks(test_plugin_context):
    """Test processing of framework options."""
    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                frameworks=["terraform", "cloudformation"],
                skip_frameworks=["secrets"],
            )
        ),
    )
    scanner._process_config_options()

    # Check that framework arguments were added
    framework_args = [arg.key for arg in scanner.args.extra_args]
    assert "--framework" in framework_args
    assert "--skip-framework" in framework_args


def test_process_config_options_skip_paths(test_plugin_context):
    """Test processing of skip path options."""
    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                skip_path=[
                    IgnorePathWithReason(path="tests/*", reason="Test files"),
                    IgnorePathWithReason(path="examples/*", reason="Example files"),
                ]
            )
        ),
    )
    scanner._process_config_options()

    # Check that skip path arguments were added
    skip_args = [arg.key for arg in scanner.args.extra_args]
    assert "--skip-path" in skip_args


def test_checkov_scanner_scan(test_checkov_scanner, test_data_dir):
    """Test CheckovScanner scan method."""
    # Mock the scan to avoid actual execution
    import unittest.mock

    with (
        unittest.mock.patch.object(test_checkov_scanner, "_run_subprocess"),
        unittest.mock.patch("builtins.open", unittest.mock.mock_open(read_data="{}")),
        unittest.mock.patch("json.load", return_value={}),
    ):
        # Run the scan
        results = test_checkov_scanner.scan(test_data_dir, target_type="source")

    # Check that results were returned
    assert results is not None


def test_checkov_scanner_scan_error(test_checkov_scanner):
    """Test CheckovScanner scan method with error."""
    # Try to scan a non-existent directory
    resp = test_checkov_scanner.scan(Path("nonexistent"), target_type="source")
    assert resp is not None
    assert resp is True
    assert (
        "(checkov) Target directory nonexistent is empty or doesn't exist. Skipping scan."
        in test_checkov_scanner.errors
    )


def test_checkov_scanner_additional_formats(test_plugin_context):
    """Test CheckovScanner with additional output formats."""
    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                additional_formats=["sarif", "json"],
            )
        ),
    )
    scanner._process_config_options()

    # Check that additional format arguments were added
    format_args = [arg.key for arg in scanner.args.extra_args]
    assert "--output" in format_args
