"""Unit tests for the CloudWatch Logs reporter plugin."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import json
import os
from datetime import datetime, timezone

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    CloudWatchLogsReporter,
    CloudWatchLogsReporterConfig,
    CloudWatchLogsReporterConfigOptions,
)

# Rebuild models to resolve forward references
AshConfig.model_rebuild()


def test_cloudwatch_logs_reporter_config_options_defaults():
    """Test default values for CloudWatch Logs reporter config options."""
    # Save original environment variables
    original_region = os.environ.get("AWS_REGION")
    original_default_region = os.environ.get("AWS_DEFAULT_REGION")
    original_log_group = os.environ.get("ASH_CLOUDWATCH_LOG_GROUP_NAME")

    try:
        # Set environment variables for testing
        os.environ["AWS_REGION"] = "us-west-2"
        os.environ["ASH_CLOUDWATCH_LOG_GROUP_NAME"] = "test-log-group"

        # Create config options
        options = CloudWatchLogsReporterConfigOptions()

        # Verify environment variables were used
        assert options.aws_region == "us-west-2"
        assert options.log_group_name == "test-log-group"
        assert options.log_stream_name == "ASHScanResults"
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

        if original_log_group:
            os.environ["ASH_CLOUDWATCH_LOG_GROUP_NAME"] = original_log_group
        elif "ASH_CLOUDWATCH_LOG_GROUP_NAME" in os.environ:
            del os.environ["ASH_CLOUDWATCH_LOG_GROUP_NAME"]


def test_cloudwatch_logs_reporter_config_defaults():
    """Test default values for CloudWatch Logs reporter config."""
    config = CloudWatchLogsReporterConfig()
    assert config.name == "cloudwatch-logs"
    assert config.extension == "cwlog.json"
    assert config.enabled is True
    assert isinstance(config.options, CloudWatchLogsReporterConfigOptions)


def test_cloudwatch_logs_reporter_model_post_init(ash_temp_path):
    """Test model_post_init creates default config if none provided."""
    from pathlib import Path
    from automated_security_helper.base.plugin_context import PluginContext

    # Create reporter with proper context
    context = PluginContext(
        source_dir=Path(f"{ash_temp_path}/source"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )
    reporter = CloudWatchLogsReporter(context=context)

    # Call model_post_init
    reporter.model_post_init(context)

    # Verify config was created
    assert reporter.config is not None
    assert isinstance(reporter.config, CloudWatchLogsReporterConfig)


@patch(
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.boto3"
)
def test_cloudwatch_logs_reporter_validate_success(mock_boto3, ash_temp_path):
    """Test validate method with successful AWS access."""
    # Create mock client
    mock_sts_client = MagicMock()

    # Configure mocks
    mock_boto3.client.return_value = mock_sts_client
    mock_sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

    # Create reporter with context and config
    context = PluginContext(
        source_dir=Path(f"{ash_temp_path}/test"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )
    config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region="us-west-2", log_group_name="test-log-group"
        )
    )
    reporter = CloudWatchLogsReporter(context=context, config=config)

    # Call validate
    result = reporter.validate_plugin_dependencies()

    # Verify result
    assert result is True
    assert reporter.dependencies_satisfied is True

    # Verify boto3 calls
    mock_boto3.client.assert_called_once_with("sts", region_name="us-west-2")
    mock_sts_client.get_caller_identity.assert_called_once()


@patch(
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.boto3"
)
def test_cloudwatch_logs_reporter_validate_missing_config(mock_boto3, ash_temp_path):
    """Test validate method with missing configuration."""
    # Create reporter with context and config with missing values
    from automated_security_helper.base.plugin_context import PluginContext
    from pathlib import Path

    context = PluginContext(
        source_dir=Path(f"{ash_temp_path}/test"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )
    config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region=None, log_group_name=None
        )
    )
    reporter = CloudWatchLogsReporter(context=context, config=config)

    # Call validate
    result = reporter.validate_plugin_dependencies()

    # Verify result
    assert result is False
    assert reporter.dependencies_satisfied is False

    # Verify boto3 was not called
    mock_boto3.client.assert_not_called()


@patch(
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.boto3"
)
def test_cloudwatch_logs_reporter_validate_aws_error(mock_boto3, ash_temp_path):
    """Test validate method with AWS error."""
    # Create mock client
    mock_sts_client = MagicMock()

    # Configure mocks
    mock_boto3.client.return_value = mock_sts_client

    # Make sts client raise an exception
    mock_sts_client.get_caller_identity.side_effect = Exception("AWS error")

    # Create reporter with context and config
    context = PluginContext(
        source_dir=Path(f"{ash_temp_path}/test"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )
    config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region="us-west-2", log_group_name="test-log-group"
        )
    )
    reporter = CloudWatchLogsReporter(context=context, config=config)

    # Mock _plugin_log to avoid actual logging
    reporter._plugin_log = MagicMock()

    # Call validate
    result = reporter.validate_plugin_dependencies()

    # Verify result
    assert result is False
    assert reporter.dependencies_satisfied is False

    # Verify error was logged
    reporter._plugin_log.assert_called_once()
    assert "Error when calling STS" in reporter._plugin_log.call_args[0][0]


@patch(
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.boto3"
)
@patch(
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.datetime"
)
def test_cloudwatch_logs_reporter_report_success(
    mock_datetime, mock_boto3, ash_temp_path
):
    """Test report method with successful CloudWatch Logs publishing."""
    # Mock datetime for consistent timestamp
    mock_now = MagicMock()
    mock_now.return_value = datetime(2025, 6, 6, 12, 0, 0, tzinfo=timezone.utc)
    mock_datetime.now.return_value = mock_now
    mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

    # Create mock client
    mock_cwlogs_client = MagicMock()

    # Configure mocks
    mock_boto3.client.return_value = mock_cwlogs_client
    mock_cwlogs_client.put_log_events.return_value = {"nextSequenceToken": "token123"}

    # Create reporter with context and config
    context = PluginContext(
        source_dir=Path(f"{ash_temp_path}/test"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )
    config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region="us-west-2",
            log_group_name="test-log-group",
            log_stream_name="test-stream",
        )
    )
    reporter = CloudWatchLogsReporter(context=context, config=config)

    # Create mock model
    model = MagicMock()
    model.to_simple_dict.return_value = {"test": "data"}

    # Call report
    with patch(
        "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.ASH_LOGGER"
    ):
        result = reporter.report(model)

    # Verify CloudWatch Logs calls
    mock_boto3.client.assert_called_with("logs", region_name="us-west-2")
    mock_cwlogs_client.create_log_stream.assert_called_once_with(
        logGroupName="test-log-group", logStreamName="test-stream"
    )

    # Verify put_log_events was called with correct parameters
    mock_cwlogs_client.put_log_events.assert_called_once()
    call_args = mock_cwlogs_client.put_log_events.call_args
    # The method is called with **kwargs, so check both positional and keyword args
    if call_args[1]:  # keyword arguments
        kwargs = call_args[1]
        assert kwargs["logGroupName"] == "test-log-group"
        assert kwargs["logStreamName"] == "test-stream"
        assert len(kwargs["logEvents"]) == 1
        assert kwargs["logEvents"][0]["message"] == json.dumps(
            {"test": "data"}, default=str
        )
    else:  # positional arguments (shouldn't happen but let's be safe)
        args = call_args[0]
        assert len(args) >= 3

    # Verify result contains response
    result_dict = json.loads(result)
    assert "message" in result_dict
    assert "response" in result_dict
    assert result_dict["response"] == {"nextSequenceToken": "token123"}


@patch(
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.boto3"
)
def test_cloudwatch_logs_reporter_report_create_stream_error(mock_boto3, ash_temp_path):
    """Test report method with error creating log stream."""
    # Create mock client
    mock_cwlogs_client = MagicMock()

    # Configure mocks
    mock_boto3.client.return_value = mock_cwlogs_client
    mock_cwlogs_client.create_log_stream.side_effect = Exception(
        "Stream already exists"
    )
    mock_cwlogs_client.put_log_events.return_value = {"nextSequenceToken": "token123"}

    # Create reporter with context and config
    context = PluginContext(
        source_dir=Path(f"{ash_temp_path}/test"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )
    config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region="us-west-2",
            log_group_name="test-log-group",
            log_stream_name="test-stream",
        )
    )
    reporter = CloudWatchLogsReporter(context=context, config=config)

    # Mock _plugin_log to avoid actual logging
    reporter._plugin_log = MagicMock()

    # Create mock model
    model = MagicMock()
    model.to_simple_dict.return_value = {"test": "data"}

    # Call report
    with patch(
        "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.ASH_LOGGER"
    ):
        result = reporter.report(model)

    # Verify error was logged but operation continued
    reporter._plugin_log.assert_called_once()
    assert "Error when creating log stream" in reporter._plugin_log.call_args[0][0]

    # Verify put_log_events was still called
    mock_cwlogs_client.put_log_events.assert_called_once()

    # Verify result contains response
    result_dict = json.loads(result)
    assert "message" in result_dict
    assert "response" in result_dict


@patch(
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.boto3"
)
def test_cloudwatch_logs_reporter_report_put_events_error(mock_boto3, ash_temp_path):
    """Test report method with error putting log events."""
    # Create mock client
    mock_cwlogs_client = MagicMock()

    # Configure mocks
    mock_boto3.client.return_value = mock_cwlogs_client
    mock_cwlogs_client.put_log_events.side_effect = Exception("Invalid sequence token")

    # Create reporter with context and config
    context = PluginContext(
        source_dir=Path(f"{ash_temp_path}/test"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )
    config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region="us-west-2",
            log_group_name="test-log-group",
            log_stream_name="test-stream",
        )
    )
    reporter = CloudWatchLogsReporter(context=context, config=config)

    # Mock _plugin_log to avoid actual logging
    reporter._plugin_log = MagicMock()

    # Create mock model
    model = MagicMock()
    model.to_simple_dict.return_value = {"test": "data"}

    # Call report
    with patch(
        "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.ASH_LOGGER"
    ):
        result = reporter.report(model)

    # Verify error was logged
    reporter._plugin_log.assert_called_once()
    assert (
        "Error when publishing results to CloudWatch Logs"
        in reporter._plugin_log.call_args[0][0]
    )

    # Verify result contains error message
    assert "Invalid sequence token" in result
