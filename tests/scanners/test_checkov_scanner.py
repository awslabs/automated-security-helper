"""Tests for the Checkov scanner implementation."""

from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch

from automated_security_helper.scanners.ash_default.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import PathExclusionEntry


@pytest.fixture
def checkov_scanner():
    """Create a CheckovScanner instance for testing."""
    return CheckovScanner()


@pytest.fixture
def mock_subprocess_run():
    """Mock subprocess.run for testing."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        yield mock_run


def test_checkov_scanner_init(checkov_scanner):
    """Test CheckovScanner initialization."""
    assert checkov_scanner.command == "checkov"
    assert checkov_scanner.tool_type == "IAC"
    assert isinstance(checkov_scanner.config, CheckovScannerConfig)
    assert checkov_scanner.args.format_arg == "--output"
    assert checkov_scanner.args.format_arg_value == "sarif"


def test_checkov_scanner_configure():
    """Test CheckovScanner configuration."""
    scanner = CheckovScanner(
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                config_file=".checkov.yaml",
                skip_path=[PathExclusionEntry(path="tests/*", reason="Test files")],
                frameworks=["terraform", "cloudformation"],
                skip_frameworks=["secrets"],
                additional_formats=["json", "junitxml"],
            )
        )
    )
    assert scanner.config.options.config_file == ".checkov.yaml"
    assert len(scanner.config.options.skip_path) == 1
    assert len(scanner.config.options.frameworks) == 2
    assert len(scanner.config.options.skip_frameworks) == 1
    assert len(scanner.config.options.additional_formats) == 2


def test_checkov_scanner_validate(checkov_scanner):
    """Test CheckovScanner validation."""
    assert checkov_scanner.validate() is True


@pytest.mark.parametrize(
    "config_file",
    [
        ".checkov.yaml",
        ".checkov.yml",
        "custom_checkov.yaml",
    ],
)
def test_process_config_options_with_config_files(config_file, test_source_dir):
    """Test processing of different config file types."""
    checkov_scanner = CheckovScanner(
        source_dir=test_source_dir,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                config_file=(test_source_dir / config_file).as_posix(),
            )
        ),
    )
    (test_source_dir / config_file).write_text("{}")

    checkov_scanner.source_dir = str(test_source_dir)

    checkov_scanner._process_config_options()

    config_args = [
        arg
        for arg in checkov_scanner.args.extra_args
        if "--config-file" in str(arg.key)
    ]
    assert len(config_args) > 0


def test_process_config_options_frameworks(checkov_scanner):
    """Test processing of framework options."""
    checkov_scanner.config.options.frameworks = ["terraform", "kubernetes"]
    checkov_scanner.config.options.skip_frameworks = ["secrets"]
    checkov_scanner._process_config_options()

    framework_args = [
        arg for arg in checkov_scanner.args.extra_args if arg.key == "--framework"
    ]
    skip_framework_args = [
        arg for arg in checkov_scanner.args.extra_args if arg.key == "--skip-framework"
    ]

    assert len(framework_args) == 2
    assert len(skip_framework_args) == 1


def test_process_config_options_skip_paths(checkov_scanner):
    """Test processing of skip path options."""
    checkov_scanner.config.options.skip_path = [
        PathExclusionEntry(path="tests/*", reason="Test files"),
        PathExclusionEntry(path="venv/*", reason="Virtual environment"),
    ]
    checkov_scanner._process_config_options()

    skip_path_args = [
        arg for arg in checkov_scanner.args.extra_args if arg.key == "--skip-path"
    ]
    assert len(skip_path_args) == 2


@pytest.mark.asyncio
async def test_checkov_scanner_scan(checkov_scanner, test_source_dir):
    """Test CheckovScanner scan execution."""
    Path(test_source_dir).mkdir(parents=True, exist_ok=True)
    Path(test_source_dir).joinpath("test.py").touch()
    result = checkov_scanner.scan(test_source_dir)
    assert result is not None


def test_checkov_scanner_scan_error(checkov_scanner, mock_subprocess_run):
    """Test CheckovScanner scan with error."""
    mock_subprocess_run.side_effect = Exception("Scan failed")

    with pytest.raises(ScannerError) as exc_info:
        checkov_scanner.scan(Path("/nonexistent"))
    assert "Target /nonexistent does not exist!" in str(exc_info.value)


def test_checkov_scanner_additional_formats(checkov_scanner):
    """Test CheckovScanner with additional output formats."""
    checkov_scanner.config.options.additional_formats = ["json", "junitxml"]
    checkov_scanner._process_config_options()

    format_args = [
        arg for arg in checkov_scanner.args.extra_args if arg.key == "--output"
    ]
    assert len(format_args) >= 2
