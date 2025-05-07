"""Tests for Bandit scanner."""

import pytest
from pathlib import Path
from automated_security_helper.scanners.ash_default.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
)
from automated_security_helper.models.core import IgnorePathWithReason


@pytest.fixture
def test_bandit_scanner(test_plugin_context):
    """Create a test Bandit scanner."""
    return BanditScanner(
        context=test_plugin_context,
        config=BanditScannerConfig(),
    )


def test_bandit_scanner_init(test_plugin_context):
    """Test BanditScanner initialization."""
    scanner = BanditScanner(
        context=test_plugin_context,
        config=BanditScannerConfig(),
    )
    assert scanner.config.name == "bandit"
    assert scanner.command == "bandit"
    assert scanner.args.format_arg == "--format"
    assert scanner.args.format_arg_value == "sarif"


def test_bandit_scanner_configure(test_plugin_context, test_source_dir):
    """Test BanditScanner configuration."""
    test_config_file = test_source_dir.joinpath(".bandit")
    test_config_file.touch()
    scanner = BanditScanner(
        context=test_plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                config_file=test_config_file,
                excluded_paths=[
                    IgnorePathWithReason(path="tests/*", reason="Test files")
                ],
            )
        ),
    )
    assert scanner.config.options.config_file.name == ".bandit"
    assert len(scanner.config.options.excluded_paths) == 1
    assert scanner.config.options.excluded_paths[0].path == "tests/*"


def test_bandit_scanner_validate(test_bandit_scanner):
    """Test BanditScanner validation."""
    assert test_bandit_scanner.validate() is True


@pytest.mark.parametrize(
    "config_file,config_arg",
    [
        (".bandit", "--ini"),
        ("bandit.yaml", "--configfile"),
        ("bandit.toml", "--configfile"),
    ],
)
def test_process_config_options_with_config_files(
    config_file, config_arg, test_source_dir, test_plugin_context
):
    """Test processing of different config file types."""
    config_path = test_source_dir.joinpath(config_file)
    config_path.touch()

    scanner = BanditScanner(
        context=test_plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                config_file=config_path,
            )
        ),
    )
    scanner._process_config_options()

    # Check that the correct config argument was added
    config_args_keys = [arg.key for arg in scanner.args.extra_args]
    # The config args are now in the format "--configfile" or "--ini"
    assert any(arg.startswith(config_arg) for arg in config_args_keys)


def test_process_config_options_exclusions(test_plugin_context):
    """Test processing of exclusion paths."""
    scanner = BanditScanner(
        context=test_plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                excluded_paths=[
                    IgnorePathWithReason(path="tests/*", reason="Test files"),
                    IgnorePathWithReason(path="examples/*", reason="Example files"),
                ]
            )
        ),
    )
    scanner._process_config_options()

    # Check that exclusion arguments were added
    exclusion_args = [arg.key for arg in scanner.args.extra_args]
    # The exclusion args are now in the format '--exclude="tests/*"'
    assert any("--exclude=" in arg and "tests/*" in arg for arg in exclusion_args)


def test_bandit_scanner_scan(test_bandit_scanner, test_source_dir):
    """Test BanditScanner scan method."""
    # Create a test Python file with a known vulnerability
    test_file = test_source_dir.joinpath("test_file.py")
    test_file.write_text("import pickle\npickle.loads(b'test')")  # Known security issue

    # Run the scan
    results = test_bandit_scanner.scan(test_source_dir, target_type="source")

    # Check that results were returned
    assert results is not None


def test_bandit_scanner_scan_nonexistent_path(test_bandit_scanner):
    """Test BanditScanner scan method with error."""
    # Try to scan a non-existent directory
    resp = test_bandit_scanner.scan(Path("/nonexistent"), target_type="source")
    assert resp is not None
    assert resp is True
    assert (
        "(bandit) Target directory /nonexistent is empty or doesn't exist. Skipping scan."
        in test_bandit_scanner.errors
    )


def test_bandit_scanner_additional_formats(test_plugin_context):
    """Test BanditScanner with additional output formats."""
    scanner = BanditScanner(
        context=test_plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                additional_formats=["sarif", "html"],
            )
        ),
    )
    scanner._process_config_options()

    # Check that additional format arguments were added
    format_args = [arg.key for arg in scanner.args.extra_args]
    format_values = [arg.value for arg in scanner.args.extra_args]

    # Check that the --format argument is present with the additional formats
    assert "--format" in format_args
    assert "sarif" in format_values or "html" in format_values
