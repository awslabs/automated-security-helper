"""Unit tests for CloudWatchLogsReporter to increase coverage."""

from pathlib import Path
from unittest.mock import patch, MagicMock


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


@patch(
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.boto3"
)
def test_cloudwatch_logs_reporter_validate_success(mock_boto3):
    """Test CloudWatchLogsReporter validate method with successful validation."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=get_default_config(),
    )

    # Create mock STS client - the validate method calls boto3.client directly
    mock_sts_client = MagicMock()
    mock_boto3.client.return_value = mock_sts_client
    mock_sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

    # Create reporter
    reporter = CloudWatchLogsReporter(context=mock_context)
    reporter.config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region="us-west-2", log_group_name="test-log-group"
        )
    )

    # Validate
    result = reporter.validate_plugin_dependencies()

    # Verify result
    assert result is True
    assert reporter.dependencies_satisfied is True
    mock_boto3.client.assert_called_once_with("sts", region_name="us-west-2")
    mock_sts_client.get_caller_identity.assert_called_once()


@patch(
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.boto3"
)
def test_cloudwatch_logs_reporter_validate_aws_error(mock_boto3):
    """Test CloudWatchLogsReporter validate method with AWS error."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=get_default_config(),
    )

    # Mock STS client to raise exception - the validate method calls boto3.client directly
    mock_sts_client = MagicMock()
    mock_boto3.client.return_value = mock_sts_client
    mock_sts_client.get_caller_identity.side_effect = Exception("AWS Error")

    # Create reporter
    reporter = CloudWatchLogsReporter(context=mock_context)
    reporter.config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region="us-west-2", log_group_name="test-log-group"
        )
    )

    # Validate
    result = reporter.validate_plugin_dependencies()

    # Verify result
    assert result is False
    assert reporter.dependencies_satisfied is False


@patch(
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.boto3"
)
def test_cloudwatch_logs_reporter_validate_missing_config(mock_boto3):
    """Test CloudWatchLogsReporter validate method with missing config."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=get_default_config(),
    )

    # Create reporter
    reporter = CloudWatchLogsReporter(context=mock_context)
    reporter.config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region=None,
            log_group_name=None,  # Missing region  # Missing log group
        )
    )

    # Validate
    result = reporter.validate_plugin_dependencies()

    # Verify result
    assert result is False
    assert reporter.dependencies_satisfied is False
    # Verify boto3 was not called
    mock_boto3.client.assert_not_called()


@patch(
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.boto3"
)
def test_cloudwatch_logs_reporter_report_success(mock_boto3):
    """Test CloudWatchLogsReporter report method with successful report."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=get_default_config(),
    )

    # Create mock CloudWatch Logs client - the report method calls boto3.client directly
    mock_logs_client = MagicMock()
    mock_boto3.client.return_value = mock_logs_client

    # Mock successful responses
    mock_logs_client.create_log_stream.return_value = {}
    mock_logs_client.put_log_events.return_value = {"nextSequenceToken": "token123"}

    # Create reporter
    reporter = CloudWatchLogsReporter(context=mock_context)
    reporter.config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region="us-west-2",
            log_group_name="test-log-group",
            log_stream_name="test-stream",
        )
    )
    reporter.dependencies_satisfied = True

    # Create mock model
    mock_model = MagicMock()
    mock_model.to_simple_dict.return_value = {"test": "data"}

    # Call report
    result = reporter.report(mock_model)

    # Verify logs client was called
    mock_boto3.client.assert_called_once_with("logs", region_name="us-west-2")
    mock_logs_client.create_log_stream.assert_called_once_with(
        logGroupName="test-log-group", logStreamName="test-stream"
    )
    mock_logs_client.put_log_events.assert_called_once()

    # Verify result contains the expected structure
    assert result is not None
    assert "message" in result
    assert "response" in result


@patch(
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.boto3"
)
def test_cloudwatch_logs_reporter_report_create_stream_error(mock_boto3):
    """Test CloudWatchLogsReporter report method with create stream error."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=get_default_config(),
    )

    # Create mock CloudWatch Logs client
    mock_logs_client = MagicMock()
    mock_boto3.client.return_value = mock_logs_client

    # Mock create_log_stream to raise exception
    mock_logs_client.create_log_stream.side_effect = Exception("Create stream error")
    # Mock put_log_events to also raise exception (since create_log_stream failed)
    mock_logs_client.put_log_events.side_effect = Exception("Put events error")

    # Create reporter
    reporter = CloudWatchLogsReporter(context=mock_context)
    reporter.config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region="us-west-2",
            log_group_name="test-log-group",
            log_stream_name="test-stream",
        )
    )
    reporter.dependencies_satisfied = True

    # Create mock model
    mock_model = MagicMock()
    mock_model.to_simple_dict.return_value = {"test": "data"}

    # Call report
    result = reporter.report(mock_model)

    # The actual implementation returns the exception string when put_log_events fails
    # Since both create_log_stream and put_log_events fail, we get the put_log_events error
    assert "Put events error" in result


@patch(
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.boto3"
)
def test_cloudwatch_logs_reporter_report_put_events_error(mock_boto3):
    """Test CloudWatchLogsReporter report method with put events error."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=get_default_config(),
    )

    # Create mock CloudWatch Logs client
    mock_logs_client = MagicMock()
    mock_boto3.client.return_value = mock_logs_client

    # Mock create_log_stream to succeed
    mock_logs_client.create_log_stream.return_value = {}
    # Mock put_log_events to raise exception
    mock_logs_client.put_log_events.side_effect = Exception("Put events error")

    # Create reporter
    reporter = CloudWatchLogsReporter(context=mock_context)
    reporter.config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region="us-west-2",
            log_group_name="test-log-group",
            log_stream_name="test-stream",
        )
    )
    reporter.dependencies_satisfied = True

    # Create mock model
    mock_model = MagicMock()
    mock_model.to_simple_dict.return_value = {"test": "data"}

    # Call report
    result = reporter.report(mock_model)

    # The actual implementation returns the exception string when put_log_events fails
    assert "Put events error" in result
