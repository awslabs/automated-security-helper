"""Simple unit tests for S3Reporter to increase coverage."""

import os
from pathlib import Path
from unittest.mock import patch, MagicMock


from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
    S3ReporterConfig,
    S3ReporterConfigOptions,
)
from automated_security_helper.config.ash_config import AshConfig

# Rebuild models to resolve forward references
AshConfig.model_rebuild()


def test_s3_reporter_config_options_defaults_without_env():
    """Test S3ReporterConfigOptions defaults without environment variables."""
    # Save original environment variables
    original_aws_region = os.environ.get("AWS_REGION")
    original_aws_default_region = os.environ.get("AWS_DEFAULT_REGION")
    original_aws_profile = os.environ.get("AWS_PROFILE")
    original_bucket_name = os.environ.get("ASH_S3_BUCKET_NAME")
    try:
        # Clear environment variables
        if "AWS_REGION" in os.environ:
            del os.environ["AWS_REGION"]
        if "AWS_DEFAULT_REGION" in os.environ:
            del os.environ["AWS_DEFAULT_REGION"]
            if "AWS_PROFILE" in os.environ:
                del os.environ["AWS_PROFILE"]
            if "ASH_S3_BUCKET_NAME" in os.environ:
                del os.environ["ASH_S3_BUCKET_NAME"]

        # Create config options
        options = S3ReporterConfigOptions()

        # Verify defaults
        assert options.aws_region is None
        assert options.aws_profile is None
        assert options.bucket_name is None
        assert options.key_prefix == "ash-reports/"
        assert options.file_format == "json"
    finally:
        # Restore environment variables
        if original_aws_region is not None:
            os.environ["AWS_REGION"] = original_aws_region
        if original_aws_default_region is not None:
            os.environ["AWS_DEFAULT_REGION"] = original_aws_default_region
        if original_aws_profile is not None:
            os.environ["AWS_PROFILE"] = original_aws_profile
        if original_bucket_name is not None:
            os.environ["ASH_S3_BUCKET_NAME"] = original_bucket_name


def test_s3_reporter_with_config():
    """Test S3Reporter initialization with config."""
    # Create mock context
    mock_context = MagicMock(spec=PluginContext)
    mock_context.source_dir = Path("/test/source")
    mock_context.output_dir = Path("/test/output")

    # Create config
    config = S3ReporterConfig(
        options=S3ReporterConfigOptions(
            aws_region="us-west-2",
            aws_profile="test-profile",
            bucket_name="test-bucket",
            key_prefix="test-prefix/",
            file_format="json",
        )
    )

    # Create reporter
    reporter = S3Reporter(context=mock_context, config=config)

    # Verify config
    assert reporter.config.options.aws_region == "us-west-2"
    assert reporter.config.options.aws_profile == "test-profile"
    assert reporter.config.options.bucket_name == "test-bucket"
    assert reporter.config.options.key_prefix == "test-prefix/"
    assert reporter.config.options.file_format == "json"


@patch("automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter.boto3")
def test_s3_reporter_validate_success(mock_boto3):
    """Test S3Reporter validate method with successful validation."""
    # Create mock context
    mock_context = MagicMock(spec=PluginContext)

    # Create mock boto3 session and clients
    mock_session = MagicMock()
    mock_boto3.Session.return_value = mock_session

    mock_sts_client = MagicMock()
    mock_session.client.side_effect = lambda service: {
        "sts": mock_sts_client,
        "s3": MagicMock(),
    }[service]

    mock_sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

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
    assert result is True
    assert reporter.dependencies_satisfied is True
    mock_boto3.Session.assert_called_once_with(
        profile_name=None, region_name="us-west-2"
    )
    mock_sts_client.get_caller_identity.assert_called_once()
