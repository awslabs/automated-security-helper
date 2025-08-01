"""Simple unit tests for CloudWatchLogsReporter to increase coverage."""

import os
from pathlib import Path


from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    CloudWatchLogsReporter,
    CloudWatchLogsReporterConfig,
    CloudWatchLogsReporterConfigOptions,
)
from automated_security_helper.config.ash_config import AshConfig

# Rebuild models to resolve forward references
AshConfig.model_rebuild()


def test_cloudwatch_logs_reporter_config_options_defaults_without_env():
    """Test CloudWatchLogsReporterConfigOptions defaults without environment variables."""
    # Save original environment variables
    original_aws_region = os.environ.get("AWS_REGION")
    original_aws_default_region = os.environ.get("AWS_DEFAULT_REGION")
    original_log_group = os.environ.get("ASH_CLOUDWATCH_LOG_GROUP")
    original_log_stream = os.environ.get("ASH_CLOUDWATCH_LOG_STREAM")

    try:
        # Clear environment variables
        if "AWS_REGION" in os.environ:
            del os.environ["AWS_REGION"]
        if "AWS_DEFAULT_REGION" in os.environ:
            del os.environ["AWS_DEFAULT_REGION"]
        if "ASH_CLOUDWATCH_LOG_GROUP" in os.environ:
            del os.environ["ASH_CLOUDWATCH_LOG_GROUP"]
        if "ASH_CLOUDWATCH_LOG_STREAM" in os.environ:
            del os.environ["ASH_CLOUDWATCH_LOG_STREAM"]

        # Create config options
        options = CloudWatchLogsReporterConfigOptions()

        # Verify defaults
        assert options.aws_region is None
        assert options.log_group_name is None
        assert options.log_stream_name == "ASHScanResults"
    finally:
        # Restore environment variables
        if original_aws_region is not None:
            os.environ["AWS_REGION"] = original_aws_region
        if original_aws_default_region is not None:
            os.environ["AWS_DEFAULT_REGION"] = original_aws_default_region
        if original_log_group is not None:
            os.environ["ASH_CLOUDWATCH_LOG_GROUP"] = original_log_group
        if original_log_stream is not None:
            os.environ["ASH_CLOUDWATCH_LOG_STREAM"] = original_log_stream


def test_cloudwatch_logs_reporter_config_options_defaults():
    """Test CloudWatchLogsReporterConfigOptions defaults with environment variables."""
    # Save original environment variables
    original_aws_region = os.environ.get("AWS_REGION")
    original_aws_default_region = os.environ.get("AWS_DEFAULT_REGION")
    original_log_group = os.environ.get(
        "ASH_CLOUDWATCH_LOG_GROUP_NAME"
    )  # Fixed env var name
    original_log_stream = os.environ.get("ASH_CLOUDWATCH_LOG_STREAM")

    try:
        # Set environment variables
        os.environ["AWS_REGION"] = "us-west-2"
        os.environ["ASH_CLOUDWATCH_LOG_GROUP_NAME"] = (
            "test-log-group"  # Fixed env var name
        )
        os.environ["ASH_CLOUDWATCH_LOG_STREAM"] = "test-log-stream"

        # Create config options
        options = CloudWatchLogsReporterConfigOptions()

        # Verify defaults
        assert options.aws_region == "us-west-2"
        assert options.log_group_name == "test-log-group"
        assert (
            options.log_stream_name == "ASHScanResults"
        )  # This is hardcoded, not from env
    finally:
        # Restore environment variables
        if original_aws_region is not None:
            os.environ["AWS_REGION"] = original_aws_region
        elif "AWS_REGION" in os.environ:
            del os.environ["AWS_REGION"]

        if original_aws_default_region is not None:
            os.environ["AWS_DEFAULT_REGION"] = original_aws_default_region
        elif "AWS_DEFAULT_REGION" in os.environ:
            del os.environ["AWS_DEFAULT_REGION"]

        if original_log_group is not None:
            os.environ["ASH_CLOUDWATCH_LOG_GROUP_NAME"] = (
                original_log_group  # Fixed env var name
            )
        elif "ASH_CLOUDWATCH_LOG_GROUP_NAME" in os.environ:
            del os.environ["ASH_CLOUDWATCH_LOG_GROUP_NAME"]  # Fixed env var name

        if original_log_stream is not None:
            os.environ["ASH_CLOUDWATCH_LOG_STREAM"] = original_log_stream
        elif "ASH_CLOUDWATCH_LOG_STREAM" in os.environ:
            del os.environ["ASH_CLOUDWATCH_LOG_STREAM"]


def test_cloudwatch_logs_reporter_with_config():
    """Test CloudWatchLogsReporter initialization with config."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=get_default_config(),
    )

    # Create config
    config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region="us-west-2",
            log_group_name="test-log-group",
            log_stream_name="test-log-stream",
        )
    )

    # Create reporter
    reporter = CloudWatchLogsReporter(context=mock_context, config=config)

    # Verify config
    assert reporter.config.options.aws_region == "us-west-2"
    assert reporter.config.options.log_group_name == "test-log-group"
    assert reporter.config.options.log_stream_name == "test-log-stream"
