# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the S3 reporter reads from the environment and refuses.

Each test failed at the base: an empty AWS_REGION hid AWS_DEFAULT_REGION and an
empty bucket or profile passed the ``is None`` checks into boto3; a blank
profile from a config file reached boto3.Session as a profile named ""; a failed
dependency check was logged at WARNING, which --quiet hides; and a workspace's
unified results were uploaded as one more object. The object name a
``key_prefix`` gives is in ``test_s3_reporter_key_prefix_is_used_as_written.py``.

No test here calls AWS: boto3 is patched out of the module and the clients are
MagicMocks.
"""

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugin_modules.ash_aws_plugins import aws_utils
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
    S3ReporterConfig,
    S3ReporterConfigOptions,
)

pytestmark = pytest.mark.unit

S3 = "automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter"


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
    settings = {"aws_region": "us-west-2", "bucket_name": "a-bucket"}
    settings.update(options)
    config = S3ReporterConfig(options=S3ReporterConfigOptions(**settings))
    reporter = S3Reporter(context=context, config=config)
    reporter._plugin_log = MagicMock()
    return reporter


def _model(workspace=None):
    model = MagicMock()
    model.to_simple_dict.return_value = {"a": 1}
    model.sarif = None
    model.metadata.generated_at = "2026-01-15T12:00:00+00:00"
    model.metadata.workspace_project = None
    model.workspace = workspace
    return model


def _logged_levels(reporter):
    return [call.kwargs.get("level") for call in reporter._plugin_log.call_args_list]


def test_empty_environment_values_are_unset(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")
    monkeypatch.setenv("AWS_PROFILE", "")
    monkeypatch.setenv("ASH_S3_BUCKET_NAME", "")

    options = S3ReporterConfigOptions()

    assert options.aws_region == "us-west-2"
    assert options.aws_profile is None
    assert options.bucket_name is None


@pytest.mark.parametrize("field", ["aws_region", "aws_profile", "bucket_name"])
@pytest.mark.parametrize("value", ["", "  "])
def test_a_blank_value_from_the_config_is_unset(field, value):
    """``aws_profile: "${AWS_PROFILE}"`` with the variable empty, or an empty
    --config-overrides value, arrives through the field, not the environment
    default: a blank region was refused by the pattern, and a blank profile or
    bucket reached boto3 as a name."""
    settings = {"aws_region": "us-west-2", "bucket_name": "a-bucket"}
    settings[field] = value

    options = S3ReporterConfigOptions(**settings)

    assert getattr(options, field) is None


@patch(f"{S3}.boto3")
def test_an_empty_profile_from_the_config_is_no_profile(mock_boto3, context):
    """botocore reads profile_name="" as a profile named "" and raises
    ProfileNotFound; the session is made with no profile instead."""
    reporter = _reporter(context, aws_profile="")

    reporter.report(_model())

    assert mock_boto3.Session.call_args.kwargs["profile_name"] is None


@patch(f"{S3}.boto3")
def test_report_names_an_empty_bucket_and_makes_no_call(mock_boto3, context, caplog):
    reporter = _reporter(context, bucket_name="")

    with caplog.at_level(logging.ERROR):
        result = reporter.report(_model())

    assert result is None
    mock_boto3.Session.assert_not_called()
    assert "bucket_name" in caplog.text, caplog.text


@patch(f"{S3}.boto3")
def test_an_empty_bucket_fails_the_dependency_check(mock_boto3, context, caplog):
    reporter = _reporter(context, bucket_name="")

    with caplog.at_level(logging.ERROR):
        satisfied = reporter.validate_plugin_dependencies()

    assert satisfied is False
    mock_boto3.Session.assert_not_called()
    assert "bucket_name" in caplog.text, caplog.text


@patch(f"{S3}.boto3")
def test_a_failed_dependency_check_is_logged_at_error(mock_boto3, context):
    """The report phase drops the reporter on False, so the line is the only
    word of why an enabled upload did not happen; --quiet hides WARNING."""
    mock_boto3.Session.side_effect = RuntimeError("the profile does not exist")
    reporter = _reporter(context)

    satisfied = reporter.validate_plugin_dependencies()

    assert satisfied is False
    assert _logged_levels(reporter) == [logging.ERROR]
    assert "the profile does not exist" in reporter._plugin_log.call_args[0][0]


@patch(f"{S3}.boto3")
def test_a_workspaces_unified_results_are_not_uploaded(mock_boto3, context):
    reporter = _reporter(context)

    result = reporter.report(_model(workspace=_Workspace()))

    assert result is None
    mock_boto3.Session.assert_not_called()
    assert _logged_levels(reporter) == [logging.ERROR]
    assert "workspace" in reporter._plugin_log.call_args[0][0]
