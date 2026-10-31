# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the CloudWatch Logs reporter refuses before and after PutLogEvents.

Each test failed at the base: the region pattern refused mx-central-1; an
empty AWS_REGION hid AWS_DEFAULT_REGION and an empty log group passed the
``is None`` check into CreateLogStream; a blank region or group name from a
config file was refused by the pattern or kept as ""; a failed dependency check was logged
at WARNING, which --quiet hides; a workspace's unified results were published
as one more event; an event over the PutLogEvents size was sent to fail there;
and an event the service listed in rejectedLogEventsInfo was returned as a
successful publish.

No test here calls AWS: boto3 is patched out of the module and the clients are
MagicMocks.
"""

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel, ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugin_modules.ash_aws_plugins import aws_utils
from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    LOG_EVENT_OVERHEAD_BYTES,
    MAX_PUT_LOG_EVENTS_BYTES,
    CloudWatchLogsReporter,
    CloudWatchLogsReporterConfig,
    CloudWatchLogsReporterConfigOptions,
)

pytestmark = pytest.mark.unit

CW = "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter"


@pytest.fixture
def context(tmp_path):
    return PluginContext(
        source_dir=Path(tmp_path / "src"),
        output_dir=Path(tmp_path / "output"),
        work_dir=Path(tmp_path / "work"),
    )


@pytest.fixture(autouse=True)
def _fresh_missing_setting_notices():
    aws_utils.reset_missing_setting_notices()
    yield
    aws_utils.reset_missing_setting_notices()


class _Workspace(BaseModel):
    """Stands in for the results' ``workspace`` record: any model, not None."""


def _reporter(context, **options):
    settings = {
        "aws_region": "us-west-2",
        "log_group_name": "a-log-group",
        "log_stream_name": "a-stream",
    }
    settings.update(options)
    config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(**settings)
    )
    reporter = CloudWatchLogsReporter(context=context, config=config)
    reporter._plugin_log = MagicMock()
    return reporter


def _model(payload=None, workspace=None):
    model = MagicMock()
    model.to_simple_dict.return_value = payload if payload is not None else {"a": 1}
    model.workspace = workspace
    return model


def _logged_levels(reporter):
    return [call.kwargs.get("level") for call in reporter._plugin_log.call_args_list]


def test_a_published_region_outside_the_two_letter_areas_is_accepted():
    options = CloudWatchLogsReporterConfigOptions(
        aws_region="mx-central-1", log_group_name="a-log-group"
    )

    assert options.aws_region == "mx-central-1"


def test_a_name_that_is_not_a_region_is_still_refused():
    with pytest.raises(ValidationError):
        CloudWatchLogsReporterConfigOptions(
            aws_region="not-a-region", log_group_name="a-log-group"
        )


def test_an_empty_aws_region_does_not_hide_aws_default_region(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")
    monkeypatch.setenv("ASH_CLOUDWATCH_LOG_GROUP_NAME", "")

    options = CloudWatchLogsReporterConfigOptions()

    assert options.aws_region == "us-west-2"
    # An empty group name is no group name.
    assert options.log_group_name is None


@pytest.mark.parametrize("field", ["aws_region", "log_group_name"])
@pytest.mark.parametrize("value", ["", "  "])
def test_a_blank_value_from_the_config_is_unset(field, value):
    """``aws_region: "${AWS_REGION}"`` with the variable empty, or an empty
    --config-overrides value, arrives through the field, not the environment
    default: a blank region was refused by the pattern as a configuration
    error and a blank group name reached CreateLogStream."""
    settings = {"aws_region": "us-west-2", "log_group_name": "a-log-group"}
    settings[field] = value

    options = CloudWatchLogsReporterConfigOptions(**settings)

    assert getattr(options, field) is None


@patch(f"{CW}.boto3")
def test_report_names_an_empty_log_group_and_makes_no_call(mock_boto3, context, caplog):
    reporter = _reporter(context, log_group_name="")

    with caplog.at_level(logging.ERROR):
        result = reporter.report(_model())

    assert result is None
    mock_boto3.client.assert_not_called()
    assert "log_group_name" in caplog.text, caplog.text


@patch(f"{CW}.boto3")
def test_an_empty_log_group_fails_the_dependency_check(mock_boto3, context, caplog):
    reporter = _reporter(context, log_group_name="")

    with caplog.at_level(logging.ERROR):
        satisfied = reporter.validate_plugin_dependencies()

    assert satisfied is False
    mock_boto3.client.assert_not_called()
    assert "log_group_name" in caplog.text, caplog.text


@patch(f"{CW}.boto3")
def test_a_failed_dependency_check_is_logged_at_error(mock_boto3, context):
    """The report phase drops the reporter on False, so the line is the only
    word of why an enabled publish did not happen; --quiet hides WARNING."""
    sts = MagicMock()
    sts.get_caller_identity.side_effect = RuntimeError("no credentials here")
    mock_boto3.client.return_value = sts
    reporter = _reporter(context)

    satisfied = reporter.validate_plugin_dependencies()

    assert satisfied is False
    assert _logged_levels(reporter) == [logging.ERROR]
    assert "no credentials here" in reporter._plugin_log.call_args[0][0]


@patch(f"{CW}.boto3")
def test_a_workspaces_unified_results_are_not_published(mock_boto3, context):
    reporter = _reporter(context)

    result = reporter.report(_model(workspace=_Workspace()))

    assert result is None
    mock_boto3.client.assert_not_called()
    assert _logged_levels(reporter) == [logging.ERROR]
    assert "workspace" in reporter._plugin_log.call_args[0][0]


@patch(f"{CW}.boto3")
def test_an_event_over_the_put_log_events_size_is_not_sent(mock_boto3, context):
    too_big = {"inputs": "x" * (MAX_PUT_LOG_EVENTS_BYTES - LOG_EVENT_OVERHEAD_BYTES)}
    reporter = _reporter(context)

    result = reporter.report(_model(too_big))

    assert result is None
    mock_boto3.client.assert_not_called()
    assert _logged_levels(reporter) == [logging.ERROR]
    assert str(MAX_PUT_LOG_EVENTS_BYTES) in reporter._plugin_log.call_args[0][0]


@patch(f"{CW}.boto3")
def test_an_event_that_fits_is_sent(mock_boto3, context):
    """The control: the size check admits an event under the bound."""
    logs = MagicMock()
    logs.put_log_events.return_value = {"nextSequenceToken": "token"}
    mock_boto3.client.return_value = logs
    reporter = _reporter(context)

    result = reporter.report(_model({"inputs": "x" * 1000}))

    assert result is not None
    assert json.loads(result)["response"] == {"nextSequenceToken": "token"}
    logs.put_log_events.assert_called_once()


@patch(f"{CW}.boto3")
def test_an_event_the_service_rejected_is_not_a_publish(mock_boto3, context):
    logs = MagicMock()
    logs.put_log_events.return_value = {
        "nextSequenceToken": "token",
        "rejectedLogEventsInfo": {"tooOldLogEventEndIndex": 0},
    }
    mock_boto3.client.return_value = logs
    reporter = _reporter(context)

    result = reporter.report(_model())

    assert result is None
    assert _logged_levels(reporter) == [logging.ERROR]
    assert "tooOldLogEventEndIndex" in reporter._plugin_log.call_args[0][0]
