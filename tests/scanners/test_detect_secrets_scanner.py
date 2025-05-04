"""Tests for the detect-secrets scanner implementation."""

from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.scanners.ash_default.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import Level, Kind


@pytest.fixture
def detect_secrets_scanner(test_plugin_context):
    """Create a DetectSecretsScanner instance for testing."""
    return DetectSecretsScanner(
        context=test_plugin_context,
        config=DetectSecretsScannerConfig(),
    )


@pytest.fixture
def mock_secrets_collection():
    """Mock SecretsCollection for testing."""
    from detect_secrets.core.potential_secret import PotentialSecret

    with patch("detect_secrets.SecretsCollection") as mock_collection:
        mock_instance = MagicMock()
        mock_data = {
            "test_file.py": set(
                [
                    PotentialSecret(
                        type="Base64 High Entropy String",
                        filename="test_file.py",
                        secret="abcd1234",  # nosec B106 - This is a fake value for testing Secrets Detection in unit/integration tests
                        line_number=10,
                        is_secret=True,
                        is_verified=True,
                    )
                ]
            )
        }
        mock_instance.data = mock_data

        # Mock the scan_files method to populate the data
        def mock_scan_files(*args):
            mock_instance.data = mock_data
            return mock_instance

        mock_instance.scan_files = mock_scan_files
        mock_collection.return_value = mock_instance
        yield mock_collection


def test_detect_secrets_scanner_init(detect_secrets_scanner):
    """Test DetectSecretsScanner initialization."""
    assert detect_secrets_scanner.command == "detect-secrets"
    assert isinstance(detect_secrets_scanner.config, DetectSecretsScannerConfig)
    assert detect_secrets_scanner._secrets_collection is not None


def test_detect_secrets_scanner_validate(detect_secrets_scanner):
    """Test DetectSecretsScanner validation."""
    assert detect_secrets_scanner.validate() is True


def test_detect_secrets_scanner_process_config_options(detect_secrets_scanner):
    """Test processing of configuration options."""
    # Currently no custom options, but test the method call
    detect_secrets_scanner._process_config_options()
    # Test passes if no exception is raised


def test_detect_secrets_scanner_scan(
    detect_secrets_scanner, test_source_dir, test_output_dir
):
    """Test DetectSecretsScanner scan execution."""
    target_dir = test_source_dir / "target"
    target_dir.mkdir()

    # Create a test file with a potential secret
    test_file = target_dir / "test_file.py"
    test_file.write_text('secret = "base64_encoded_secret=="')

    detect_secrets_scanner.source_dir = test_source_dir
    detect_secrets_scanner.output_dir = test_output_dir

    result = detect_secrets_scanner.scan(test_source_dir, target_type="source")

    assert result is not None
    assert len(result.runs) == 1
    assert result.runs[0].tool.driver.name == "detect-secrets"

    # Verify SARIF report structure
    assert len(result.runs[0].results) == 1
    finding = result.runs[0].results[0]
    assert finding.ruleId == "SECRET-SECRET-KEYWORD"
    assert finding.level == Level.error
    assert finding.kind == Kind.fail
    assert "detect-secrets" in finding.properties.tags
    assert "secret" in finding.properties.tags


def test_detect_secrets_scanner_scan_error(
    detect_secrets_scanner, mock_secrets_collection
):
    """Test DetectSecretsScanner scan with error."""
    mock_secrets_collection.side_effect = Exception("Scan failed")

    # Use a platform-independent nonexistent path
    nonexistent_path = Path("nonexistent_directory_for_testing")

    with pytest.raises(ScannerError) as exc_info:
        detect_secrets_scanner.scan(nonexistent_path, target_type="source")

    # Use a more flexible assertion that works across platforms
    assert "does not exist" in str(exc_info.value)
    assert str(nonexistent_path) in str(exc_info.value)


def test_detect_secrets_scanner_with_no_findings(
    detect_secrets_scanner, mock_secrets_collection, tmp_path
):
    """Test DetectSecretsScanner when no secrets are found."""
    mock_secrets_collection.return_value.data = {}

    target_dir = tmp_path / "target"
    target_dir.mkdir()

    from automated_security_helper.config.ash_config import AshConfig

    detect_secrets_scanner.context = PluginContext(
        source_dir=target_dir,
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "output" / ASH_WORK_DIR_NAME,
        config=AshConfig(),  # Use default AshConfig instead of None
    )

    result = detect_secrets_scanner.scan(target_dir, target_type="source")

    assert result is not None
    assert len(result.runs) == 1
    assert len(result.runs[0].results) == 0


def test_detect_secrets_scanner_sarif_output(
    detect_secrets_scanner, mock_secrets_collection, tmp_path
):
    """Test DetectSecretsScanner SARIF output format."""
    # Set up mock data
    from detect_secrets.core.potential_secret import PotentialSecret

    mock_secrets_collection.return_value.data = {
        "test_file.py": set(
            [
                PotentialSecret(
                    type="Base64 High Entropy String",
                    filename="test_file.py",
                    secret="abcd1234",  # nosec B106 - This is a fake value for testing Secrets Detection in unit/integration tests
                    line_number=10,
                    is_secret=True,
                    is_verified=True,
                )
            ]
        )
    }

    target_dir = tmp_path / "target"
    target_dir.mkdir()

    detect_secrets_scanner.source_dir = str(target_dir)
    detect_secrets_scanner.output_dir = str(tmp_path / "output")

    result = detect_secrets_scanner.scan(target_dir, target_type="source")

    # Verify SARIF structure
    assert result.runs[0].tool.driver.name == "detect-secrets"
    assert result.runs[0].tool.driver.organization == "Yelp"
    assert (
        result.runs[0].tool.driver.informationUri.__str__()
        == "https://github.com/Yelp/detect-secrets"
    )

    # Verify invocation details
    invocation = result.runs[0].invocations[0]
    assert invocation.commandLine == "ash-detect-secrets-scanner"
    assert "--target" in invocation.arguments
    assert invocation.executionSuccessful is True


def test_detect_secrets_scanner_with_multiple_files(
    detect_secrets_scanner, mock_secrets_collection, tmp_path
):
    """Test DetectSecretsScanner with multiple files containing secrets."""
    from detect_secrets.core.potential_secret import PotentialSecret

    mock_secrets_collection.return_value.data = {
        "file1.py": set(
            [
                PotentialSecret(
                    type="Secret1",
                    filename="test_file.py",
                    secret="hash1",  # nosec B106 - This is a fake value for testing Secrets Detection in unit/integration tests
                    line_number=81,
                    is_secret=True,
                    is_verified=True,
                ),
            ]
        ),
        "file2.py": set(
            [
                PotentialSecret(
                    type="AWSSecretKey",
                    filename="test_file.py",
                    secret="1239491230230912",  # nosec B106 - This is a fake value for testing Secrets Detection in unit/integration tests
                    line_number=4,
                    is_secret=True,
                    is_verified=True,
                )
            ]
        ),
    }

    target_dir = tmp_path / "target"
    target_dir.mkdir()

    detect_secrets_scanner.source_dir = str(target_dir)
    detect_secrets_scanner.output_dir = str(tmp_path / "output")

    result = detect_secrets_scanner.scan(target_dir, target_type="source")

    assert result is not None
