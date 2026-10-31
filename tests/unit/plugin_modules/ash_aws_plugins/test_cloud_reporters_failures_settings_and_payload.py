# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the CloudWatch Logs and S3 reporters answer when they cannot deliver,
what they check before calling AWS, and what the S3 upload holds.

Each test failed at the base: a failed CloudWatch Logs publish came back as the
error text, which the report phase wrote as a report; `ash report`, which never
calls validate_plugin_dependencies, reached the AWS call with an unset log
group or bucket; the S3 dependency check refused the documented write-only
policy; the uploaded object carried no findings and its YAML form held a
Python-only tag; a failed local copy discarded the receipt of a finished
upload; and the region pattern refused published region names.

No test here calls AWS: boto3 is patched out of each module and the clients
are MagicMocks.
"""

import json
from enum import Enum
from pathlib import Path
from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest
import yaml
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugin_modules.ash_aws_plugins import aws_utils
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    CloudWatchLogsReporter,
    CloudWatchLogsReporterConfig,
    CloudWatchLogsReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
    S3ReporterConfig,
    S3ReporterConfigOptions,
)
from tests.unit.plugin_modules.ash_aws_plugins.bedrock_reporter_doubles import (
    finding,
    sarif_model,
)

pytestmark = pytest.mark.unit

CW = "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter"
S3 = "automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter"


@pytest.fixture
def context(ash_temp_path):
    return PluginContext(
        source_dir=Path(f"{ash_temp_path}/src"),
        output_dir=Path(f"{ash_temp_path}/output"),
        work_dir=Path(f"{ash_temp_path}/work"),
    )


@pytest.fixture(autouse=True)
def _fresh_missing_setting_notices():
    aws_utils.reset_missing_setting_notices()
    yield
    aws_utils.reset_missing_setting_notices()


def _cloudwatch(context, **options):
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


def _s3(context, **options):
    settings = {"aws_region": "us-west-2", "bucket_name": "a-bucket"}
    settings.update(options)
    config = S3ReporterConfig(options=S3ReporterConfigOptions(**settings))
    reporter = S3Reporter(context=context, config=config)
    reporter._plugin_log = MagicMock()
    return reporter


def _client_error(code, message="it failed", operation="PutLogEvents", status=400):
    return botocore.exceptions.ClientError(
        {
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        operation,
    )


# ---------------------------------------------------------------------------
# CloudWatch Logs
# ---------------------------------------------------------------------------


@patch(f"{CW}.boto3")
def test_a_failed_publish_produces_no_report(mock_boto3, context):
    """None, not the error text: the report phase writes a text as the report."""
    logs = MagicMock()
    logs.put_log_events.side_effect = _client_error(
        "InvalidSequenceTokenException", "Invalid sequence token"
    )
    mock_boto3.client.return_value = logs
    reporter = _cloudwatch(context, max_retries=0)
    model = MagicMock()
    model.to_simple_dict.return_value = {"test": "data"}

    result = reporter.report(model)

    assert result is None
    logged = reporter._plugin_log.call_args[0][0]
    assert "Invalid sequence token" in logged, logged


@patch(f"{CW}.boto3")
def test_report_names_an_unset_log_group_and_makes_no_call(mock_boto3, context, caplog):
    """`ash report` skips the dependency check, so report() checks the setting
    itself and names it as the check would."""
    reporter = _cloudwatch(context, log_group_name=None)

    with caplog.at_level("ERROR"):
        result = reporter.report(MagicMock())

    assert result is None
    mock_boto3.client.assert_not_called()
    assert "log_group_name" in caplog.text, caplog.text


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------


@patch(f"{S3}.boto3")
def test_report_names_an_unset_bucket_and_makes_no_call(mock_boto3, context, caplog):
    reporter = _s3(context, bucket_name=None)

    with caplog.at_level("ERROR"):
        result = reporter.report(MagicMock())

    assert result is None
    mock_boto3.Session.assert_not_called()
    assert "bucket_name" in caplog.text, caplog.text


@patch(f"{S3}.boto3")
def test_a_refused_head_bucket_passes_the_dependency_check(mock_boto3, context):
    """The documented policy grants s3:PutObject alone. S3 answers HeadBucket
    with 403 for a bucket that exists and cannot be listed, so the check passes
    and the upload is tried; a missing bucket (404) still fails it."""
    session = mock_boto3.Session.return_value
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    s3 = MagicMock()
    s3.head_bucket.side_effect = _client_error("403", "Forbidden", "HeadBucket", 403)
    session.client.side_effect = lambda service, **kw: {"sts": sts, "s3": s3}[service]

    assert _s3(context).validate_plugin_dependencies() is True

    s3.head_bucket.side_effect = _client_error("404", "Not Found", "HeadBucket", 404)
    assert _s3(context).validate_plugin_dependencies() is False


def _upload(mock_boto3, reporter, model):
    s3 = mock_boto3.Session.return_value.client.return_value
    receipt = reporter.report(model)
    return receipt, s3.put_object.call_args.kwargs["Body"]


@patch(f"{S3}.boto3")
def test_the_uploaded_object_carries_the_findings(mock_boto3, context):
    """The documentation says the uploaded file contains the findings."""
    reporter = _s3(context)

    receipt, body = _upload(mock_boto3, reporter, sarif_model([finding("R1")]))

    uploaded = json.loads(body)
    assert uploaded["sarif"]["runs"][0]["results"][0]["ruleId"] == "R1", uploaded
    assert json.loads(receipt)["bucket"] == "a-bucket"


class _Status(Enum):
    PASSED = "PASSED"


@patch(f"{S3}.boto3")
def test_the_yaml_form_holds_no_python_tag(mock_boto3, context):
    """A model whose simple dict carries an enum member: the YAML written used
    to hold a !!python/object/apply tag that yaml.safe_load refuses."""
    reporter = _s3(context, file_format="yaml")
    model = MagicMock()
    model.sarif = None
    model.metadata.generated_at = "2026-01-01T00:00:00+00:00"
    model.to_simple_dict.return_value = {
        "scanner_results": {"bandit": {"status": _Status.PASSED}}
    }

    _receipt, body = _upload(mock_boto3, reporter, model)

    loaded = yaml.safe_load(body)
    assert "python" not in body, body
    assert "PASSED" in str(loaded["scanner_results"]["bandit"]["status"]), loaded


@patch(f"{S3}.boto3")
def test_a_failed_local_copy_keeps_the_receipt_of_the_upload(mock_boto3, context):
    reporter = _s3(context)
    with patch(f"{S3}.write_report_file", side_effect=OSError("read-only")):
        receipt, _body = _upload(mock_boto3, reporter, sarif_model([finding("R1")]))

    assert receipt is not None
    document = json.loads(receipt)
    assert document["key"].startswith("ash-reports/ash-report-")
    assert document["local_copy"] is None
    logged = reporter._plugin_log.call_args[0][0]
    assert "local copy" in logged and "uploaded" in logged, logged


@pytest.mark.parametrize(
    "region", ["mx-central-1", "us-isof-south-1", "eu-isoe-west-1", "eusc-de-east-1"]
)
def test_a_published_region_name_is_accepted_in_config(region):
    options = S3ReporterConfigOptions(aws_region=region, bucket_name="a-bucket")

    assert options.aws_region == region


def test_a_name_that_is_no_region_is_refused_in_config():
    with pytest.raises(ValidationError):
        S3ReporterConfigOptions(aws_region="nowhere-1", bucket_name="a-bucket")


# A region written as a YAML block scalar keeps its final newline, so the value
# the model sees is "us-east-1\n". The pattern is anchored at both ends and the
# engine of record (pydantic-core) reads "$" as the end of the value, so the
# newline is refused as a configuration error; the same name on one line is
# accepted. Before the anchors the pattern was a search and admitted any value
# holding a region name, this one included.
_REGION_OPTIONS = [
    pytest.param(BedrockSummaryReporterConfigOptions, {}, id="bedrock"),
    pytest.param(
        CloudWatchLogsReporterConfigOptions,
        {"log_group_name": "a-log-group"},
        id="cloudwatch",
    ),
    pytest.param(S3ReporterConfigOptions, {"bucket_name": "a-bucket"}, id="s3"),
]


@pytest.mark.parametrize(("options_type", "required"), _REGION_OPTIONS)
def test_a_block_scalar_region_keeps_its_newline_and_is_refused(options_type, required):
    region = yaml.safe_load("aws_region: |\n  us-east-1\n")["aws_region"]
    assert region == "us-east-1\n"

    with pytest.raises(ValidationError):
        options_type(aws_region=region, **required)


@pytest.mark.parametrize(("options_type", "required"), _REGION_OPTIONS)
def test_the_same_region_on_one_line_is_accepted(options_type, required):
    region = yaml.safe_load("aws_region: us-east-1\n")["aws_region"]

    options = options_type(aws_region=region, **required)

    assert options.aws_region == "us-east-1"
