# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""An enabled off-host reporter that lacks a setting it needs says so, and how to set it.

Each AWS reporter's dependency check returns before any AWS call when a setting
it needs is unset: S3's region or bucket, CloudWatch Logs' region or log group,
Security Hub's region, the Bedrock summary reporter's region. The report phase
then leaves the reporter out, and with no format requested nothing else names
it, so an upload the operator turned on did not happen and nothing said why.
Each case here builds the reporter enabled, with every other setting it needs,
and checks that its check fails without contacting AWS and logs one error that
names the reporter, the setting, the ``--config-overrides`` key and the
environment variables the setting is read from; a second check logs nothing
more. ``ash merge`` is covered end to end for S3 with no region.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Tuple
from unittest.mock import MagicMock

import boto3
import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_aws_plugins import aws_utils
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfig,
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
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
    SecurityHubReporterConfig,
    SecurityHubReporterConfigOptions,
)
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.secret_bearing_scan import isolate_from_aws

pytestmark = pytest.mark.unit

# The reporters' models refer to AshConfig, which must be defined before one is
# built, as in the other reporter tests here.
AshConfig.model_rebuild()
for _model in (
    S3ReporterConfig,
    S3Reporter,
    CloudWatchLogsReporterConfig,
    CloudWatchLogsReporter,
    SecurityHubReporterConfig,
    SecurityHubReporter,
    BedrockSummaryReporterConfig,
    BedrockSummaryReporter,
):
    _model.model_rebuild()

AWS_PLUGIN_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"
REGION_VARIABLES = ("AWS_REGION", "AWS_DEFAULT_REGION")


class Case(NamedTuple):
    key: str
    reporter: type
    config: type
    options: type
    #: The options set, so that only ``missing`` is unset.
    given: Dict[str, Any]
    missing: str
    environment: Tuple[str, ...]


CASES = [
    Case(
        "s3",
        S3Reporter,
        S3ReporterConfig,
        S3ReporterConfigOptions,
        {"bucket_name": "operator-bucket"},
        "aws_region",
        REGION_VARIABLES,
    ),
    Case(
        "s3",
        S3Reporter,
        S3ReporterConfig,
        S3ReporterConfigOptions,
        {"aws_region": "us-east-1"},
        "bucket_name",
        ("ASH_S3_BUCKET_NAME",),
    ),
    Case(
        "cloudwatch-logs",
        CloudWatchLogsReporter,
        CloudWatchLogsReporterConfig,
        CloudWatchLogsReporterConfigOptions,
        {"log_group_name": "operator-group"},
        "aws_region",
        REGION_VARIABLES,
    ),
    Case(
        "cloudwatch-logs",
        CloudWatchLogsReporter,
        CloudWatchLogsReporterConfig,
        CloudWatchLogsReporterConfigOptions,
        {"aws_region": "us-east-1"},
        "log_group_name",
        ("ASH_CLOUDWATCH_LOG_GROUP_NAME",),
    ),
    Case(
        "aws-security-hub",
        SecurityHubReporter,
        SecurityHubReporterConfig,
        SecurityHubReporterConfigOptions,
        {"account_id": "123456789012"},
        "aws_region",
        REGION_VARIABLES,
    ),
    Case(
        "bedrock-summary-reporter",
        BedrockSummaryReporter,
        BedrockSummaryReporterConfig,
        BedrockSummaryReporterConfigOptions,
        # The region defaults to us-east-1 when no variable sets one, so only a
        # config that sets it to null leaves it unset.
        {"aws_region": None},
        "aws_region",
        REGION_VARIABLES,
    ),
]


@pytest.fixture(autouse=True)
def _fresh_notices():
    aws_utils.reset_missing_setting_notices()
    yield
    aws_utils.reset_missing_setting_notices()


@pytest.fixture
def aws_contact(monkeypatch, tmp_path) -> List[str]:
    """Every boto3 session or client built; none may be. No variable sets a destination."""
    isolate_from_aws(monkeypatch, tmp_path)
    for name in ("ASH_S3_BUCKET_NAME", "ASH_CLOUDWATCH_LOG_GROUP_NAME"):
        monkeypatch.delenv(name, raising=False)
    made: List[str] = []
    real_session = boto3.Session
    real_client = boto3.client

    def recording_session(*args, **kwargs):
        made.append(f"Session({kwargs})")
        return real_session(*args, **kwargs)

    def recording_client(service_name, *args, **kwargs):
        made.append(f"client({service_name})")
        return real_client(service_name, *args, **kwargs)

    monkeypatch.setattr(boto3, "Session", recording_session)
    monkeypatch.setattr(boto3, "client", recording_client)
    return made


@pytest.fixture
def errors_logged():
    """The messages ASH logs at ERROR or above while the test runs.

    Collected by a filter on the logger, not a handler: a command sets the logger
    up again (``utils.log.get_logger``), which drops every handler it had but
    keeps its filters.
    """
    records: List[str] = []

    class _Collect(logging.Filter):
        def filter(self, record):
            if record.levelno >= logging.ERROR:
                records.append(record.getMessage())
            return True

    collect = _Collect()
    ASH_LOGGER.addFilter(collect)
    try:
        yield records
    finally:
        ASH_LOGGER.removeFilter(collect)


def _naming(case: Case, messages: List[str]) -> List[str]:
    return [
        m
        for m in messages
        if f"'{case.key}'" in m and f"reporters.{case.key}.options.{case.missing}=" in m
    ]


def _build(case: Case):
    context = MagicMock(spec=PluginContext)
    context.source_dir = Path("/src")
    context.output_dir = Path("/out")
    config = case.config(enabled=True, options=case.options(**case.given))
    reporter = case.reporter(context=context, config=config)
    assert getattr(reporter.config.options, case.missing) is None
    return reporter


@pytest.mark.parametrize(
    "case", CASES, ids=[f"{case.key}-{case.missing}" for case in CASES]
)
def test_the_missing_setting_is_named_with_how_to_set_it(
    case, aws_contact, errors_logged
):
    reporter = _build(case)

    assert reporter.validate_plugin_dependencies() is False

    named = _naming(case, errors_logged)
    assert len(named) == 1, errors_logged
    for variable in case.environment:
        assert variable in named[0], named[0]
    assert aws_contact == []


@pytest.mark.parametrize(
    "case", CASES, ids=[f"{case.key}-{case.missing}" for case in CASES]
)
def test_it_is_named_once_per_process(case, aws_contact, errors_logged):
    """A workspace builds a reporter for each project; the operator hears it once."""
    _build(case).validate_plugin_dependencies()
    _build(case).validate_plugin_dependencies()

    assert len(_naming(case, errors_logged)) == 1, errors_logged


def test_both_of_s3s_missing_settings_are_named(aws_contact, errors_logged):
    """Neither the region nor the bucket is set: each gets its own line."""
    context = MagicMock(spec=PluginContext)
    config = S3ReporterConfig(enabled=True, options=S3ReporterConfigOptions())
    reporter = S3Reporter(context=context, config=config)

    assert reporter.validate_plugin_dependencies() is False

    for missing in ("aws_region", "bucket_name"):
        assert [m for m in errors_logged if f"reporters.s3.options.{missing}=" in m], (
            errors_logged
        )
    assert aws_contact == []


def test_ash_merge_names_s3s_missing_region(tmp_path, aws_contact, errors_logged):
    """The measured case: overrides enable S3 and name its bucket but no region."""
    import typer

    from automated_security_helper.cli.merge import merge_command
    from automated_security_helper.core.enums import AshLogLevel
    from tests.unit.cli.test_merge import build_shards, write_shards

    paths = write_shards(tmp_path / "artifacts", build_shards(2))
    try:
        merge_command(
            results=paths,
            output_dir=str(tmp_path / "merged"),
            output_formats=None,
            min_severity="low",
            ignore_suppressions=False,
            fail_on_findings=False,
            fail_on_incomplete_scanners=None,
            config=None,
            config_overrides=[
                f"ash_plugin_modules=[{AWS_PLUGIN_MODULE}]",
                "reporters.s3.enabled=true",
                "reporters.s3.options.bucket_name=operator-bucket",
            ],
            log_level=AshLogLevel.ERROR,
            verbose=False,
            debug=False,
            color=False,
        )
    except typer.Exit:
        pass

    named = _naming(CASES[0], errors_logged)
    assert len(named) == 1, errors_logged
    assert aws_contact == []
    assert not (tmp_path / "merged" / "reports" / "ash.s3.json").exists()
