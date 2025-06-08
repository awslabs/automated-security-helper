"""Simple unit tests for AsffReporter to increase coverage."""

import os
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


def test_asff_reporter_config_options_defaults_without_env():
    """Test AsffReporterConfigOptions defaults without environment variables."""
    # Save original environment variables
    original_aws_region = os.environ.get("AWS_REGION")
    original_aws_default_region = os.environ.get("AWS_DEFAULT_REGION")
    original_aws_profile = os.environ.get("AWS_PROFILE")

    try:
        # Clear environment variables
        if "AWS_REGION" in os.environ:
            del os.environ["AWS_REGION"]
        if "AWS_DEFAULT_REGION" in os.environ:
            del os.environ["AWS_DEFAULT_REGION"]
        if "AWS_PROFILE" in os.environ:
            del os.environ["AWS_PROFILE"]

        # Create config options
        options = AsffReporterConfigOptions()

        # Verify defaults
        assert options.aws_region is None
        assert options.aws_profile is None
    finally:
        # Restore environment variables
        if original_aws_region is not None:
            os.environ["AWS_REGION"] = original_aws_region
        if original_aws_default_region is not None:
            os.environ["AWS_DEFAULT_REGION"] = original_aws_default_region
        if original_aws_profile is not None:
            os.environ["AWS_PROFILE"] = original_aws_profile


def test_asff_reporter_with_config():
    """Test AsffReporter initialization with config."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=MagicMock(),
    )

    # Create config
    config = AsffReporterConfig(
        options=AsffReporterConfigOptions(
            aws_region="us-west-2", aws_profile="test-profile"
        )
    )

    # Create reporter
    reporter = AsffReporter(context=mock_context, config=config)

    # Verify config
    assert reporter.config.options.aws_region == "us-west-2"
    assert reporter.config.options.aws_profile == "test-profile"


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
