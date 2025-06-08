"""Unit tests for the S3 reporter plugin."""

from unittest.mock import MagicMock, patch, mock_open
import os
from pathlib import Path

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
    S3ReporterConfig,
    S3ReporterConfigOptions,
)

# Rebuild models to resolve forward references
AshConfig.model_rebuild()


def test_s3_reporter_config_options_defaults():
    """Test default values for S3 reporter config options."""
    # Save original environment variables
    original_region = os.environ.get("AWS_REGION")
    original_default_region = os.environ.get("AWS_DEFAULT_REGION")
    original_profile = os.environ.get("AWS_PROFILE")
    original_bucket = os.environ.get("ASH_S3_BUCKET_NAME")

    try:
        # Set environment variables for testing
        os.environ["AWS_REGION"] = "us-west-2"
        os.environ["AWS_PROFILE"] = "test-profile"
        os.environ["ASH_S3_BUCKET_NAME"] = "test-bucket"

        # Create config options
        options = S3ReporterConfigOptions()

        # Verify environment variables were used
        assert options.aws_region == "us-west-2"
        assert options.aws_profile == "test-profile"
        assert options.bucket_name == "test-bucket"
        assert options.key_prefix == "ash-reports/"
        assert options.file_format == "json"
    finally:
        # Restore original environment variables
        if original_region:
            os.environ["AWS_REGION"] = original_region
        elif "AWS_REGION" in os.environ:
            del os.environ["AWS_REGION"]

        if original_default_region:
            os.environ["AWS_DEFAULT_REGION"] = original_default_region
        elif "AWS_DEFAULT_REGION" in os.environ:
            del os.environ["AWS_DEFAULT_REGION"]

        if original_profile:
            os.environ["AWS_PROFILE"] = original_profile
        elif "AWS_PROFILE" in os.environ:
            del os.environ["AWS_PROFILE"]

        if original_bucket:
            os.environ["ASH_S3_BUCKET_NAME"] = original_bucket
        elif "ASH_S3_BUCKET_NAME" in os.environ:
            del os.environ["ASH_S3_BUCKET_NAME"]


def test_s3_reporter_config_defaults(ash_temp_path):
    """Test default values for S3 reporter config."""
    config = S3ReporterConfig()
    assert config.name == "s3"
    assert config.extension == "s3.json"
    assert config.enabled is True
    assert isinstance(config.options, S3ReporterConfigOptions)


def test_s3_reporter_model_post_init(ash_temp_path):
    """Test model_post_init creates default config if none provided."""
    from automated_security_helper.base.plugin_context import PluginContext

    # Create reporter with proper context
    context = PluginContext(
        source_dir=Path(f"{ash_temp_path}/source"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )
    reporter = S3Reporter(context=context)

    # Call model_post_init
    reporter.model_post_init(context)

    # Verify config was created
    assert reporter.config is not None
    assert isinstance(reporter.config, S3ReporterConfig)


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter.boto3")
def test_s3_reporter_validate_success(mock_boto3, ash_temp_path):
    """Test validate method with successful AWS access."""
    from automated_security_helper.base.plugin_context import PluginContext

    # Create mock session and clients
    mock_session = MagicMock()
    mock_sts_client = MagicMock()
    mock_s3_client = MagicMock()

    # Configure mocks
    mock_boto3.Session.return_value = mock_session
    mock_session.client.side_effect = lambda service: {
        "sts": mock_sts_client,
        "s3": mock_s3_client,
    }[service]

    mock_sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

    # Create reporter with proper context and config
    context = PluginContext(
        source_dir=Path(f"{ash_temp_path}/source"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )
    config = S3ReporterConfig(
        options=S3ReporterConfigOptions(
            aws_region="us-west-2",
            aws_profile="test-profile",
            bucket_name="test-bucket",
        )
    )
    reporter = S3Reporter(context=context, config=config)

    # Call validate
    result = reporter.validate()

    # Verify result
    assert result is True
    assert reporter.dependencies_satisfied is True

    # Verify boto3 calls
    mock_boto3.Session.assert_called_once_with(
        profile_name="test-profile", region_name="us-west-2"
    )
    mock_sts_client.get_caller_identity.assert_called_once()
    mock_s3_client.head_bucket.assert_called_once_with(Bucket="test-bucket")


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter.boto3")
def test_s3_reporter_validate_missing_config(mock_boto3, ash_temp_path):
    """Test validate method with missing configuration."""
    # Create reporter with context and config with missing values
    context = PluginContext(
        source_dir=Path(f"{ash_temp_path}/test"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )
    config = S3ReporterConfig(
        options=S3ReporterConfigOptions(aws_region=None, bucket_name=None)
    )
    reporter = S3Reporter(context=context, config=config)

    # Call validate
    result = reporter.validate()

    # Verify result
    assert result is False
    assert reporter.dependencies_satisfied is False

    # Verify boto3 was not called
    mock_boto3.Session.assert_not_called()


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter.boto3")
def test_s3_reporter_validate_aws_error(mock_boto3, ash_temp_path):
    """Test validate method with AWS error."""
    # Create mock session and clients
    mock_session = MagicMock()
    mock_sts_client = MagicMock()

    # Configure mocks
    mock_boto3.Session.return_value = mock_session
    mock_session.client.side_effect = lambda service: {
        "sts": mock_sts_client,
    }[service]

    # Make sts client raise an exception
    mock_sts_client.get_caller_identity.side_effect = Exception("AWS error")

    # Create reporter with context and config
    context = PluginContext(
        source_dir=Path(f"{ash_temp_path}/test"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )
    config = S3ReporterConfig(
        options=S3ReporterConfigOptions(
            aws_region="us-west-2",
            aws_profile="test-profile",
            bucket_name="test-bucket",
        )
    )
    reporter = S3Reporter(context=context, config=config)

    # Mock _plugin_log to avoid actual logging
    reporter._plugin_log = MagicMock()

    # Call validate
    result = reporter.validate()

    # Verify result
    assert result is False
    assert reporter.dependencies_satisfied is False

    # Verify error was logged
    reporter._plugin_log.assert_called_once()
    assert "Error when validating S3 access" in reporter._plugin_log.call_args[0][0]


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter.boto3")
def test_s3_reporter_report_json_format(mock_boto3, ash_temp_path):
    """Test report method with JSON format."""
    # Create mock session and client
    mock_session = MagicMock()
    mock_s3_client = MagicMock()

    # Configure mocks
    mock_boto3.Session.return_value = mock_session
    mock_session.client.return_value = mock_s3_client

    # Create reporter with context and config
    context = PluginContext(
        source_dir=Path(f"{ash_temp_path}/test"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )
    config = S3ReporterConfig(
        options=S3ReporterConfigOptions(
            aws_region="us-west-2",
            aws_profile="test-profile",
            bucket_name="test-bucket",
            file_format="json",
        )
    )
    reporter = S3Reporter(context=context, config=config)

    # Create mock model
    model = MagicMock()
    model.scan_metadata.scan_time.strftime.return_value = "20250606-120000"
    model.to_simple_dict.return_value = {"test": "data"}

    # Mock file operations
    with (
        patch("builtins.open", mock_open()) as mock_file,
        patch.object(Path, "mkdir") as mock_mkdir,
    ):
        # Call report
        result = reporter.report(model)

        # Verify S3 upload
        mock_s3_client.put_object.assert_called_once()
        call_args = mock_s3_client.put_object.call_args[1]
        assert call_args["Bucket"] == "test-bucket"
        assert call_args["Key"].startswith("ash-reports/ash-report-20250606-120000")
        assert call_args["ContentType"] == "application/json"

        # Verify local file operations
        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
        mock_file.assert_called_once()

        # Verify result is the S3 URL
        assert result.startswith("s3://test-bucket/ash-reports/")


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter.boto3")
@patch("automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter.yaml")
def test_s3_reporter_report_yaml_format(mock_yaml, mock_boto3, ash_temp_path):
    """Test report method with YAML format."""
    # Create mock session and client
    mock_session = MagicMock()
    mock_s3_client = MagicMock()

    # Configure mocks
    mock_boto3.Session.return_value = mock_session
    mock_session.client.return_value = mock_s3_client
    mock_yaml.dump.return_value = "yaml content"

    # Create reporter with context and config
    context = PluginContext(
        source_dir=Path(f"{ash_temp_path}/test"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )
    config = S3ReporterConfig(
        options=S3ReporterConfigOptions(
            aws_region="us-west-2",
            aws_profile="test-profile",
            bucket_name="test-bucket",
            file_format="yaml",
        )
    )
    reporter = S3Reporter(context=context, config=config)

    # Create mock model
    model = MagicMock()
    model.scan_metadata.scan_time.strftime.return_value = "20250606-120000"
    model.to_simple_dict.return_value = {"test": "data"}

    # Mock file operations
    with (
        patch("builtins.open", mock_open()) as mock_file,
        patch.object(Path, "mkdir") as mock_mkdir,
    ):
        # Call report
        result = reporter.report(model)

        # Verify YAML was used
        mock_yaml.dump.assert_called_once()

        # Verify S3 upload
        mock_s3_client.put_object.assert_called_once()
        call_args = mock_s3_client.put_object.call_args[1]
        assert call_args["Bucket"] == "test-bucket"
        assert call_args["Key"].endswith(".yaml")
        assert call_args["ContentType"] == "application/yaml"

        # Verify local file operations
        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
        mock_file.assert_called_once()

        # Verify result is the S3 URL
        assert result.startswith("s3://test-bucket/ash-reports/")


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter.boto3")
def test_s3_reporter_report_error_handling(mock_boto3, ash_temp_path):
    """Test report method error handling."""
    # Create mock session and client
    mock_session = MagicMock()
    mock_s3_client = MagicMock()

    # Configure mocks
    mock_boto3.Session.return_value = mock_session
    mock_session.client.return_value = mock_s3_client

    # Make s3_client raise an exception
    mock_s3_client.put_object.side_effect = Exception("S3 error")

    # Create reporter with context and config
    context = PluginContext(
        source_dir=Path(f"{ash_temp_path}/test"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )
    context.output_dir = "/test/output"
    config = S3ReporterConfig(
        options=S3ReporterConfigOptions(
            aws_region="us-west-2",
            aws_profile="test-profile",
            bucket_name="test-bucket",
        )
    )
    reporter = S3Reporter(context=context, config=config)

    # Mock _plugin_log to avoid actual logging
    reporter._plugin_log = MagicMock()

    # Create mock model
    model = MagicMock()
    model.scan_metadata.scan_time.strftime.return_value = "20250606-120000"
    model.to_simple_dict.return_value = {"test": "data"}

    # Mock Path operations
    mock_path = MagicMock()

    with patch("pathlib.Path") as mock_path_class:
        # Configure Path mock
        mock_path_class.return_value = mock_path

        # Call report
        result = reporter.report(model)

        # Verify error was logged
        reporter._plugin_log.assert_called_once()
        assert "Error uploading to S3" in reporter._plugin_log.call_args[0][0]

        # Verify result contains error message
        assert "Error uploading to S3" in result
