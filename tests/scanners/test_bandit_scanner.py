"""Tests for the Bandit scanner implementation."""

from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch

from automated_security_helper.scanners.ash_default.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason


@pytest.fixture
def bandit_scanner():
    """Create a BanditScanner instance for testing."""
    return BanditScanner()


@pytest.fixture
def mock_subprocess_run():
    """Mock subprocess.run for testing."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        yield mock_run


def test_bandit_scanner_init(bandit_scanner):
    """Test BanditScanner initialization."""
    assert bandit_scanner.command == "bandit"
    assert bandit_scanner.tool_type == "SAST"
    assert isinstance(bandit_scanner.config, BanditScannerConfig)
    assert "--recursive" in [arg.key for arg in bandit_scanner.args.extra_args]


def test_bandit_scanner_configure():
    """Test BanditScanner configuration."""
    scanner = BanditScanner()
    config = BanditScannerConfig(
        options=BanditScannerConfigOptions(
            confidence_level="high",
            severity_level="medium",
            ignore_nosec=True,
            excluded_paths=[IgnorePathWithReason(path="tests/*", reason="Test files")],
        )
    )
    scanner.configure(config)
    assert scanner.config.options.confidence_level == "high"
    assert scanner.config.options.severity_level == "medium"
    assert scanner.config.options.ignore_nosec is True
    assert len(scanner.config.options.excluded_paths) == 1


def test_bandit_scanner_validate(bandit_scanner):
    """Test BanditScanner validation."""
    assert bandit_scanner.validate() is True


@pytest.mark.parametrize(
    "config_file,expected_arg",
    [
        (".bandit", "--ini"),
        ("bandit.yaml", "--configfile"),
        ("bandit.toml", "--configfile"),
    ],
)
def test_process_config_options_with_config_files(
    bandit_scanner, config_file, expected_arg, tmp_path
):
    """Test processing of different config file types."""
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    config_path = source_dir / config_file
    config_path.touch()

    bandit_scanner.source_dir = str(source_dir)
    bandit_scanner._process_config_options()

    config_args = [
        arg for arg in bandit_scanner.args.extra_args if expected_arg in arg.key
    ]
    assert len(config_args) > 0


def test_process_config_options_exclusions(bandit_scanner):
    """Test processing of exclusion options."""
    bandit_scanner.config.options.excluded_paths = [
        IgnorePathWithReason(path="tests/*", reason="Test files"),
        IgnorePathWithReason(path="venv/*", reason="Virtual environment"),
    ]
    bandit_scanner._process_config_options()

    exclusion_args = [
        arg for arg in bandit_scanner.args.extra_args if "--exclude" in arg.key
    ]
    assert len(exclusion_args) >= 2


@pytest.mark.asyncio
async def test_bandit_scanner_scan(bandit_scanner, test_source_dir):
    """Test BanditScanner scan execution."""

    Path(test_source_dir).mkdir(parents=True, exist_ok=True)
    Path(test_source_dir).joinpath("test.py").touch()
    result = bandit_scanner.scan(test_source_dir, target_type="source")
    assert result is not None


def test_bandit_scanner_scan_error(bandit_scanner, mock_subprocess_run):
    """Test BanditScanner scan with error."""
    mock_subprocess_run.side_effect = Exception("Scan failed")

    with pytest.raises(ScannerError) as exc_info:
        bandit_scanner.scan(Path("/nonexistent"), target_type="source")
    assert "Bandit scan failed" in str(exc_info.value)


def test_bandit_scanner_additional_formats(bandit_scanner):
    """Test BanditScanner with additional output formats."""
    bandit_scanner.config.options.additional_formats = ["json", "txt"]
    bandit_scanner._process_config_options()

    format_args = [
        arg for arg in bandit_scanner.args.extra_args if arg.key == "--format"
    ]
    assert len(format_args) >= 2
