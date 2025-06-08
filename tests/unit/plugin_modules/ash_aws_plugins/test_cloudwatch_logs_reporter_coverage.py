"""Unit tests for CloudWatchLogsReporter to increase coverage."""

from pathlib import Path
from unittest.mock import patch, MagicMock


from automated_security_helper.base.plugin_context import PluginContext
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
        config=MagicMock(),
    )

    # Create mock boto3 session and clients
    mock_session = MagicMock()
    mock_boto3.Session.return_value = mock_session

    mock_sts_client = MagicMock()
    mock_session.client.side_effect = lambda service: {
        "sts": mock_sts_client,
        "logs": MagicMock(),
    }[service]

    mock_sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

    # Create reporter
    reporter = CloudWatchLogsReporter(context=mock_context)
    reporter.config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region="us-west-2", log_group_name="test-log-group"
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
    reporter = CloudWatchLogsReporter(context=mock_context)
    reporter.config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region="us-west-2", log_group_name="test-log-group"
        )
    )

    # Validate
    result = reporter.validate()

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
        config=MagicMock(),
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
    result = reporter.validate()

    # Verify result
    assert result is False
    assert reporter.dependencies_satisfied is False
    # Verify boto3 was not called
    mock_boto3.Session.assert_not_called()


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
        config=MagicMock(),
    )

    # Create mock boto3 session and clients
    mock_session = MagicMock()
    mock_boto3.Session.return_value = mock_session

    mock_logs_client = MagicMock()
    mock_session.client.return_value = mock_logs_client

    # Mock describe_log_streams to return no streams
    mock_logs_client.describe_log_streams.return_value = {"logStreams": []}

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
    mock_logs_client.create_log_stream.assert_called_once_with(
        logGroupName="test-log-group", logStreamName="test-stream"
    )
    mock_logs_client.put_log_events.assert_called_once()

    # Verify result
    assert result is not None
    assert "Successfully" in result


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
        config=MagicMock(),
    )

    # Create mock boto3 session and clients
    mock_session = MagicMock()
    mock_boto3.Session.return_value = mock_session

    mock_logs_client = MagicMock()
    mock_session.client.return_value = mock_logs_client

    # Mock describe_log_streams to return no streams
    mock_logs_client.describe_log_streams.return_value = {"logStreams": []}

    # Mock create_log_stream to raise exception
    mock_logs_client.create_log_stream.side_effect = Exception("Create stream error")

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

    # Verify result contains error message
    assert "Error creating log stream" in result


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
        config=MagicMock(),
    )

    # Create mock boto3 session and clients
    mock_session = MagicMock()
    mock_boto3.Session.return_value = mock_session

    mock_logs_client = MagicMock()
    mock_session.client.return_value = mock_logs_client

    # Mock describe_log_streams to return existing stream
    mock_logs_client.describe_log_streams.return_value = {
        "logStreams": [
            {"logStreamName": "test-stream", "uploadSequenceToken": "token123"}
        ]
    }

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

    # Verify result contains error message
    assert "Error sending logs" in result
