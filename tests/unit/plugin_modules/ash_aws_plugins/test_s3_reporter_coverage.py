"""Unit tests for S3Reporter to increase coverage."""

from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open


from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
    S3ReporterConfig,
    S3ReporterConfigOptions,
)
from automated_security_helper.config.ash_config import AshConfig

# Rebuild models to resolve forward references
AshConfig.model_rebuild()


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter.boto3")
def test_s3_reporter_validate_aws_error(mock_boto3):
    """Test S3Reporter validate method with AWS error."""
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
    reporter = S3Reporter(context=mock_context)
    reporter.config = S3ReporterConfig(
        options=S3ReporterConfigOptions(
            aws_region="us-west-2", bucket_name="test-bucket"
        )
    )

    # Validate
    result = reporter.validate()

    # Verify result
    assert result is False
    assert reporter.dependencies_satisfied is False


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter.boto3")
def test_s3_reporter_validate_missing_config(mock_boto3):
    """Test S3Reporter validate method with missing config."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=MagicMock(),
    )

    # Create reporter
    reporter = S3Reporter(context=mock_context)
    reporter.config = S3ReporterConfig(
        options=S3ReporterConfigOptions(
            aws_region=None,  # Missing region
            bucket_name=None,  # Missing bucket
        )
    )

    # Validate
    result = reporter.validate()

    # Verify result
    assert result is False
    assert reporter.dependencies_satisfied is False
    # Verify boto3 was not called
    mock_boto3.Session.assert_not_called()


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter.boto3")
def test_s3_reporter_report_json_format(mock_boto3):
    """Test S3Reporter report method with JSON format."""
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

    mock_s3_client = MagicMock()
    mock_session.client.return_value = mock_s3_client

    # Create reporter
    reporter = S3Reporter(context=mock_context)
    reporter.config = S3ReporterConfig(
        options=S3ReporterConfigOptions(
            aws_region="us-west-2", bucket_name="test-bucket", file_format="json"
        )
    )
    reporter.dependencies_satisfied = True

    # Create mock model
    mock_model = MagicMock()
    mock_model.scan_metadata.scan_time.strftime.return_value = "20250101-120000"
    mock_model.to_simple_dict.return_value = {"test": "data"}

    # Mock open
    with patch("builtins.open", mock_open()) as mock_file:
        # Call report
        result = reporter.report(mock_model)

    # Verify S3 client was called
    mock_s3_client.put_object.assert_called_once()
    args, kwargs = mock_s3_client.put_object.call_args
    assert kwargs["Bucket"] == "test-bucket"
    assert "ash-report-20250101-120000.json" in kwargs["Key"]
    assert kwargs["ContentType"] == "application/json"

    # Verify file was written
    mock_file.assert_called_once()

    # Verify result
    assert "s3://" in result
    assert "test-bucket" in result


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter.boto3")
def test_s3_reporter_report_yaml_format(mock_boto3):
    """Test S3Reporter report method with YAML format."""
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

    mock_s3_client = MagicMock()
    mock_session.client.return_value = mock_s3_client

    # Create reporter
    reporter = S3Reporter(context=mock_context)
    reporter.config = S3ReporterConfig(
        options=S3ReporterConfigOptions(
            aws_region="us-west-2", bucket_name="test-bucket", file_format="yaml"
        )
    )
    reporter.dependencies_satisfied = True

    # Create mock model
    mock_model = MagicMock()
    mock_model.scan_metadata.scan_time.strftime.return_value = "20250101-120000"
    mock_model.to_simple_dict.return_value = {"test": "data"}

    # Mock open
    with patch("builtins.open", mock_open()) as mock_file:
        # Call report
        result = reporter.report(mock_model)

    # Verify S3 client was called
    mock_s3_client.put_object.assert_called_once()
    args, kwargs = mock_s3_client.put_object.call_args
    assert kwargs["Bucket"] == "test-bucket"
    assert "ash-report-20250101-120000.yaml" in kwargs["Key"]
    assert kwargs["ContentType"] == "application/yaml"

    # Verify file was written
    mock_file.assert_called_once()

    # Verify result
    assert "s3://" in result
    assert "test-bucket" in result


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter.boto3")
def test_s3_reporter_report_error_handling(mock_boto3):
    """Test S3Reporter report method with error handling."""
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

    mock_s3_client = MagicMock()
    mock_session.client.return_value = mock_s3_client
    mock_s3_client.put_object.side_effect = Exception("S3 Error")

    # Create reporter
    reporter = S3Reporter(context=mock_context)
    reporter.config = S3ReporterConfig(
        options=S3ReporterConfigOptions(
            aws_region="us-west-2", bucket_name="test-bucket", file_format="json"
        )
    )
    reporter.dependencies_satisfied = True

    # Create mock model
    mock_model = MagicMock()
    mock_model.scan_metadata.scan_time.strftime.return_value = "20250101-120000"
    mock_model.to_simple_dict.return_value = {"test": "data"}

    # Mock open
    with patch("builtins.open", mock_open()) as _:
        # Call report
        result = reporter.report(mock_model)

    # Verify result contains error message
    assert "Error uploading to S3" in result
