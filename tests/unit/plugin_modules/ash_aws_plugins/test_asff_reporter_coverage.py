"""Unit tests for AsffReporter to increase coverage."""

from pathlib import Path
from unittest.mock import patch, MagicMock


from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugin_modules.ash_aws_plugins.asff_reporter import (
    AsffReporter,
    AsffReporterConfig,
    AsffReporterConfigOptions,
)
from automated_security_helper.config.ash_config import AshConfig

# Rebuild models to resolve forward references
AshConfig.model_rebuild()


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.asff_reporter.boto3")
def test_asff_reporter_validate_success(mock_boto3):
    """Test AsffReporter validate method with successful validation."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=MagicMock(),
    )

    # Create mock boto3 session and clients
    mock_session = MagicMock()
    mock_boto3.Session.return_value = mock_session

    mock_sts_client = MagicMock()
    mock_session.client.side_effect = lambda service: {
        "sts": mock_sts_client,
        "securityhub": MagicMock(),
    }[service]

    mock_sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

    # Create reporter
    reporter = AsffReporter(context=mock_context)
    reporter.config = AsffReporterConfig(
        options=AsffReporterConfigOptions(aws_region="us-west-2")
    )

    # Validate
    result = reporter.validate()

    # Verify result
    assert result is True
    assert reporter.dependencies_satisfied is True
    mock_boto3.Session.assert_called_once_with(
        profile_name=None, region_name="us-west-2"
    )
    mock_sts_client.get_caller_identity.assert_called_once()


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.asff_reporter.boto3")
def test_asff_reporter_validate_aws_error(mock_boto3):
    """Test AsffReporter validate method with AWS error."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=MagicMock(),
    )

    # Create mock boto3 session and clients
    mock_session = MagicMock()
    mock_boto3.Session.return_value = mock_session

    # Mock STS client to raise exception
    mock_sts_client = MagicMock()
    mock_session.client.side_effect = lambda service: {
        "sts": mock_sts_client,
    }[service]

    mock_sts_client.get_caller_identity.side_effect = Exception("AWS Error")

    # Create reporter
    reporter = AsffReporter(context=mock_context)
    reporter.config = AsffReporterConfig(
        options=AsffReporterConfigOptions(aws_region="us-west-2")
    )

    # Validate
    result = reporter.validate()

    # Verify result
    assert result is False
    assert reporter.dependencies_satisfied is False


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.asff_reporter.boto3")
def test_asff_reporter_validate_missing_config(mock_boto3):
    """Test AsffReporter validate method with missing config."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=MagicMock(),
    )

    # Create reporter
    reporter = AsffReporter(context=mock_context)
    reporter.config = AsffReporterConfig(
        options=AsffReporterConfigOptions(
            aws_region=None  # Missing region
        )
    )

    # Validate
    result = reporter.validate()

    # Verify result
    assert result is False
    assert reporter.dependencies_satisfied is False
    # Verify boto3 was not called
    mock_boto3.Session.assert_not_called()


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.asff_reporter.boto3")
def test_asff_reporter_report(mock_boto3):
    """Test AsffReporter report method."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=MagicMock(),
    )

    # Create mock boto3 session and clients
    mock_session = MagicMock()
    mock_boto3.Session.return_value = mock_session

    mock_securityhub_client = MagicMock()
    mock_session.client.return_value = mock_securityhub_client

    # Create reporter
    reporter = AsffReporter(context=mock_context)
    reporter.config = AsffReporterConfig(
        options=AsffReporterConfigOptions(aws_region="us-west-2")
    )
    reporter.dependencies_satisfied = True

    # Create mock model with findings
    mock_model = MagicMock()
    mock_finding1 = MagicMock()
    mock_finding1.id = "finding1"
    mock_finding1.rule_id = "rule1"
    mock_finding1.severity = "HIGH"
    mock_finding1.message = "Test finding 1"
    mock_finding1.location.path = "/test/file1.py"
    mock_finding1.location.start_line = 10

    mock_finding2 = MagicMock()
    mock_finding2.id = "finding2"
    mock_finding2.rule_id = "rule2"
    mock_finding2.severity = "MEDIUM"
    mock_finding2.message = "Test finding 2"
    mock_finding2.location.path = "/test/file2.py"
    mock_finding2.location.start_line = 20

    mock_model.findings = [mock_finding1, mock_finding2]
    mock_model.scan_metadata.scan_time.isoformat.return_value = "2025-01-01T12:00:00"

    # Call report
    result = reporter.report(mock_model)

    # Verify SecurityHub client was called
    mock_securityhub_client.batch_import_findings.assert_called_once()
    args, kwargs = mock_securityhub_client.batch_import_findings.call_args
    assert "Findings" in kwargs
    assert len(kwargs["Findings"]) == 2

    # Verify result
    assert result is not None
    assert "Successfully" in result


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.asff_reporter.boto3")
def test_asff_reporter_report_error(mock_boto3):
    """Test AsffReporter report method with error."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=MagicMock(),
    )

    # Create mock boto3 session and clients
    mock_session = MagicMock()
    mock_boto3.Session.return_value = mock_session

    mock_securityhub_client = MagicMock()
    mock_session.client.return_value = mock_securityhub_client
    mock_securityhub_client.batch_import_findings.side_effect = Exception(
        "SecurityHub Error"
    )

    # Create reporter
    reporter = AsffReporter(context=mock_context)
    reporter.config = AsffReporterConfig(
        options=AsffReporterConfigOptions(aws_region="us-west-2")
    )
    reporter.dependencies_satisfied = True

    # Create mock model with findings
    mock_model = MagicMock()
    mock_finding = MagicMock()
    mock_finding.id = "finding1"
    mock_finding.rule_id = "rule1"
    mock_finding.severity = "HIGH"
    mock_finding.message = "Test finding"
    mock_finding.location.path = "/test/file.py"
    mock_finding.location.start_line = 10

    mock_model.findings = [mock_finding]
    mock_model.scan_metadata.scan_time.isoformat.return_value = "2025-01-01T12:00:00"

    # Call report
    result = reporter.report(mock_model)

    # Verify result contains error message
    assert "Error sending findings" in result
