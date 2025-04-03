"""Tests for the CDK Nag scanner."""

import glob
import os
import pytest
from automated_security_helper.scanners.abstract_scanner import ScannerError
from automated_security_helper.scanners.cdk_nag_scanner import CDKNagScanner

# def test_scanner_validate_script_missing(tmp_path):
#     """Test validation fails when docker script is missing."""
#     scanner = CDKNagScanner()
#     with pytest.raises(ScannerError, match=".*requires cdk-docker-execute.sh script"):
#         scanner.validate()

# def test_scanner_scan_parses_findings(tmp_path, mocker):
#     """Test scanning parses findings from CSV output."""
#     scanner = CDKNagScanner()

#     # Mock subprocess execution
#     mock_run = mocker.patch.object(scanner, "_run_cdk_synthesis")
#     mock_findings = mocker.patch.object(scanner, "_parse_findings")
#     mock_findings.return_value = []

#     # Configure scanner
#     scanner.configure(ScannerConfig(name="cdk-nag"))

#     # Run scan
#     result = scanner.scan("/test/path")

#     # Verify mocks were called correctly
#     mock_run.assert_called_once()
#     mock_findings.assert_called_once()
#     assert isinstance(result.findings, list)
#     assert len(result.findings) == 0

# def test_scanner_parse_csv_findings(tmp_path):
#     """Test parsing of CDK Nag CSV output."""
#     scanner = CDKNagScanner()
#     scanner.configure(ScannerConfig(name="cdk-nag"))

#     # Create test working directory and CSV file
#     scanner.work_dir = tmp_path / "test_cdk_nag_results"
#     scanner.work_dir.mkdir()

#     # Create mock CSV output
#     csv_content = "\n".join([
#         "Rule ID,Resource ID,Compliance,Exception Reason,Rule Level,Rule Info",
#         "AwsSolutions-S1,test/bucket1,Non-Compliant,N/A,Error,Server access logs disabled",
#         "AwsSolutions-S2,test/bucket1,Compliant,N/A,Error,Public access blocked"
#     ])
#     csv_file = scanner.work_dir / "AwsSolutions-test-NagReport.csv"
#     csv_file.write_text(csv_content)

#     # Parse findings and verify
#     findings = scanner._parse_findings()
#     assert len(findings) == 2
#     assert findings[0].rule_id == "AwsSolutions-S1"
#     assert findings[0].resource_id == "test/bucket1"

# def test_scanner_scan_error(tmp_path, mocker):
#     """Test error handling during scan."""
#     scanner = CDKNagScanner()
#     scanner.configure(ScannerConfig(name="cdk-nag"))

#     # Mock subprocess failure
#     mock_run = mocker.patch.object(scanner, "_run_cdk_synthesis")
#     mock_run.side_effect = Exception("CDK synthesis failed")

#     with pytest.raises(ScannerError, match="CDK synthesis failed"):
#         scanner.scan("/test/path")


@pytest.fixture
def scanner():
    """Create a CDK Nag scanner instance for testing."""
    return CDKNagScanner()


def get_template_files():
    """Get all template JSON files from test data directory."""
    test_data_dir = os.path.join(
        "tests", "test_data", "scanners", "cdk", "test.yaml_cdk_nag_results"
    )
    return glob.glob(os.path.join(test_data_dir, "*.template.json"))


def get_csv_files():
    """Get all CSV result files from test data directory."""
    test_data_dir = os.path.join(
        "tests", "test_data", "scanners", "cdk", "test.yaml_cdk_nag_results"
    )
    return glob.glob(os.path.join(test_data_dir, "*NagReport.csv"))


@pytest.mark.parametrize("template_file", get_template_files())
def test_scanner_scan_parses_findings(mocker, template_file):
    """Test that scanner can parse findings from CDK nag output."""
    scanner = CDKNagScanner()
    mocker.patch(
        "automated_security_helper.scanners.cdk_nag_scanner.CDKNagScanner.validate"
    )
    mocker.patch("automated_security_helper.scanners.cdk_nag_scanner.subprocess.run")

    report = scanner.scan(template_file)
    assert report is not None


@pytest.mark.parametrize("csv_file", get_csv_files())
def test_scanner_parse_csv_findings(csv_file):
    """Test that scanner can parse findings from CSV file."""
    scanner = CDKNagScanner()
    findings = scanner._parse_findings(csv_file)

    assert findings is not None
    assert len(findings) > 0
    for finding in findings:
        assert finding.id is not None
        assert finding.severity is not None
        assert finding.title is not None
        assert finding.description is not None
        assert finding.location is not None


def test_scanner_scan_error(mocker):
    """Test that scanner handles CDK synthesis errors."""
    scanner = CDKNagScanner()
    mocker.patch(
        "automated_security_helper.scanners.cdk_nag_scanner.CDKNagScanner.validate"
    )
    mocker.patch(
        "automated_security_helper.scanners.cdk_nag_scanner.subprocess.run",
        side_effect=Exception("Target /test/path does not exist"),
    )

    with pytest.raises(ScannerError, match="Target /test/path does not exist"):
        scanner.scan("/test/path")
