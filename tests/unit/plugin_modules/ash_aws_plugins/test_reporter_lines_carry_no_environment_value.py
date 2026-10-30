# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An AWS reporter's log lines name no value the config read from the environment.

These reporters log the configured bucket, log group, log stream and region at
INFO, VERBOSE or DEBUG while they work. ash.log keeps those lines (DEBUG under
``--debug``), and any configured option can come from ``${VAR}``, so each line is
redacted with the config's environment values
(``AshConfig._environment_values``), as the scanners' lines are.
"""

import logging
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.error_text import config_environment_values
from automated_security_helper.utils.log import ASH_LOGGER


pytestmark = pytest.mark.unit


@pytest.fixture
def logged():
    lines = []

    class _Collect(logging.Handler):
        def emit(self, record):
            lines.append(record.getMessage())

    handler = _Collect(level=logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield lines
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _context(tmp_path, values) -> PluginContext:
    for name in ("source", "output", "work"):
        (tmp_path / name).mkdir(exist_ok=True)
    config = AshConfig(project_name="reporter-lines")
    config._environment_values = list(values)
    return PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=config,
    )


def _no_value(lines, control: str, canary: str) -> None:
    text = "\n".join(lines)
    assert control in text, f"the control: {control!r} was logged:\n{text}"
    assert canary not in text, text


def test_s3_uploaded_url(tmp_path, logged, monkeypatch):
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        s3_reporter as module,
    )

    bucket = "envcanary-upload-bucket"
    monkeypatch.setattr(module.boto3, "Session", MagicMock())
    monkeypatch.setattr(
        module.S3Reporter, "_put_object_with_retry", lambda self, *a, **k: None
    )
    reporter = module.S3Reporter(
        context=_context(tmp_path, [bucket]),
        config=module.S3ReporterConfig(
            options=module.S3ReporterConfigOptions(
                aws_region="us-east-1", bucket_name=bucket
            )
        ),
    )
    logged.clear()

    reporter.report(AshAggregatedResults())

    _no_value(logged, "Successfully uploaded report to", bucket)


def test_cloudwatch_publish_line(tmp_path, logged, monkeypatch):
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        cloudwatch_logs_reporter as module,
    )

    group = "/ENVCANARY-publish/group"
    monkeypatch.setattr(module.boto3, "client", MagicMock())
    monkeypatch.setattr(
        module.CloudWatchLogsReporter,
        "_create_log_stream_with_retry",
        lambda self, client: None,
    )
    monkeypatch.setattr(
        module.CloudWatchLogsReporter,
        "_put_log_events_with_retry",
        lambda self, client, **kwargs: {},
    )
    reporter = module.CloudWatchLogsReporter(
        context=_context(tmp_path, [group]),
        config=module.CloudWatchLogsReporterConfig(
            options=module.CloudWatchLogsReporterConfigOptions(
                aws_region="us-east-1",
                log_group_name=group,
                log_stream_name="ASHScanResults",
            )
        ),
    )
    logged.clear()

    reporter.report(AshAggregatedResults())

    _no_value(logged, "Publishing event to CloudWatch Logs, to the log group", group)


def test_cloudwatch_stream_already_exists(tmp_path, logged, monkeypatch):
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        cloudwatch_logs_reporter as module,
    )

    stream = "ENVCANARY-named-stream"
    reporter = module.CloudWatchLogsReporter(
        context=_context(tmp_path, [stream]),
        config=module.CloudWatchLogsReporterConfig(
            options=module.CloudWatchLogsReporterConfigOptions(
                aws_region="us-east-1",
                log_group_name="/ash/results",
                log_stream_name=stream,
            )
        ),
    )
    client = MagicMock()
    client.create_log_stream.side_effect = ClientError(
        {"Error": {"Code": "ResourceAlreadyExistsException", "Message": "exists"}},
        "CreateLogStream",
    )
    logged.clear()

    reporter._create_log_stream_with_retry(client)

    _no_value(
        logged,
        "The log stream the log_stream_name option names already exists",
        stream,
    )


def test_security_hub_validated_region(tmp_path, logged, monkeypatch):
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        security_hub_reporter as module,
    )

    region = "ENVCANARY-region-a"
    monkeypatch.setattr(module.boto3, "Session", MagicMock())
    reporter = module.SecurityHubReporter(
        context=_context(tmp_path, [region]),
        config=module.SecurityHubReporterConfig(
            options=module.SecurityHubReporterConfigOptions(
                aws_region=region, account_id="123456789012"
            )
        ),
    )
    logged.clear()

    assert reporter.validate_plugin_dependencies() is True
    _no_value(logged, "Security Hub reporter validated for the region", region)


def test_security_hub_import_line(tmp_path, logged, monkeypatch):
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        security_hub_reporter as module,
    )

    region = "ENVCANARY-region-b"
    monkeypatch.setattr(module.boto3, "Session", MagicMock())
    monkeypatch.setattr(
        module.SecurityHubReporter,
        "_caller_account",
        lambda self, session, region: "123456789012",
    )
    # A completed scope with nothing archivable, so report() passes the
    # no-findings early return and reaches the import summary with zero to send.
    monkeypatch.setattr(
        module.SecurityHubReporter,
        "_archive_scope",
        lambda self, model: ("source", None),
    )
    monkeypatch.setattr(
        module.SecurityHubReporter,
        "build_asff_findings",
        lambda self, model, account_id, region: [],
    )
    reporter = module.SecurityHubReporter(
        context=_context(tmp_path, [region]),
        config=module.SecurityHubReporterConfig(
            # Cloud reporters are disabled until an operator enables them.
            enabled=True,
            options=module.SecurityHubReporterConfigOptions(
                aws_region=region,
                account_id="123456789012",
                archive_resolved_findings=False,
                findings_scope="ash-reporter-lines-test",
            ),
        ),
    )
    logged.clear()

    reporter.report(AshAggregatedResults())

    _no_value(logged, "Imported 0 finding(s) into Security Hub", region)


# ---------------------------------------------------------------------------
# The exceptions' own text
# ---------------------------------------------------------------------------
#
# An AWS call's exception can name a configured option: botocore's
# ProfileNotFound names the profile, a refused request the bucket, group or
# region. Each reporter logs that text, and puts it in its errors, so each line
# is redacted with the config's environment values too.


@pytest.fixture
def no_aws_files(tmp_path, monkeypatch):
    """No AWS config or credentials a test could read, and no metadata lookup.

    botocore resolves a profile from these files when a Session is made, so a
    profile the files lack fails there, offline, with its own message.
    """
    config = tmp_path / "aws-config"
    credentials = tmp_path / "aws-credentials"
    config.write_text("", encoding="utf-8")
    credentials.write_text("", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_PROFILE", raising=False)


def _no_value_in(texts, control: str, canary: str) -> None:
    text = "\n".join(texts)
    assert control in text, f"the control: {control!r} was recorded:\n{text}"
    assert canary not in text, text


def test_s3_access_check_profile_not_found(tmp_path, logged, no_aws_files):
    """botocore's ProfileNotFound names the configured profile."""
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        s3_reporter as module,
    )

    profile = "ENVCANARY-missing-profile"
    reporter = module.S3Reporter(
        context=_context(tmp_path, [profile]),
        config=module.S3ReporterConfig(
            options=module.S3ReporterConfigOptions(
                aws_region="us-east-1",
                bucket_name="ash-check-bucket",
                aws_profile=profile,
            )
        ),
    )
    logged.clear()

    assert reporter.validate_plugin_dependencies() is False
    _no_value_in(
        [*logged, *reporter.errors], "Error when validating S3 access", profile
    )


def test_s3_upload_failure(tmp_path, logged, monkeypatch):
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        s3_reporter as module,
    )

    bucket = "envcanary-denied-bucket"

    def _refused(self, *args, **kwargs):
        raise RuntimeError(f"Access Denied for bucket {bucket}")

    monkeypatch.setattr(module.boto3, "Session", MagicMock())
    monkeypatch.setattr(module.S3Reporter, "_put_object_with_retry", _refused)
    reporter = module.S3Reporter(
        context=_context(tmp_path, [bucket]),
        config=module.S3ReporterConfig(
            options=module.S3ReporterConfigOptions(
                aws_region="us-east-1", bucket_name=bucket
            )
        ),
    )
    logged.clear()

    assert reporter.report(AshAggregatedResults()) is None
    _no_value_in(
        [*logged, *reporter.errors], "Error uploading to S3 after retries", bucket
    )


def test_security_hub_validation_client_error(tmp_path, logged, monkeypatch):
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        security_hub_reporter as module,
    )

    region = "ENVCANARY-hub-region"
    session = MagicMock()
    session.return_value.client.return_value.describe_hub.side_effect = ClientError(
        {
            "Error": {
                "Code": "UnrecognizedClientException",
                "Message": f"no endpoint in {region}",
            }
        },
        "DescribeHub",
    )
    monkeypatch.setattr(module.boto3, "Session", session)
    reporter = module.SecurityHubReporter(
        context=_context(tmp_path, [region]),
        config=module.SecurityHubReporterConfig(
            options=module.SecurityHubReporterConfigOptions(
                aws_region=region, account_id="123456789012"
            )
        ),
    )
    logged.clear()

    assert reporter.validate_plugin_dependencies() is False
    _no_value(logged, "AWS Security Hub validation failed", region)


def test_security_hub_validation_profile_not_found(tmp_path, logged, no_aws_files):
    """botocore's ProfileNotFound names the configured profile."""
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        security_hub_reporter as module,
    )

    profile = "ENVCANARY-hub-profile"
    reporter = module.SecurityHubReporter(
        context=_context(tmp_path, [profile]),
        config=module.SecurityHubReporterConfig(
            options=module.SecurityHubReporterConfigOptions(
                aws_region="us-east-1",
                account_id="123456789012",
                aws_profile=profile,
            )
        ),
    )
    logged.clear()

    assert reporter.validate_plugin_dependencies() is False
    _no_value(logged, "Security Hub reporter validation failed", profile)


def test_security_hub_existing_findings_unread(tmp_path, logged, monkeypatch):
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        security_hub_reporter as module,
    )

    scope = "envcanary-import-scope"

    def _unreadable(self, client, **kwargs):
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": f"GetFindings refused for {scope}",
                }
            },
            "GetFindings",
        )

    monkeypatch.setattr(module.boto3, "Session", MagicMock())
    monkeypatch.setattr(
        module.SecurityHubReporter,
        "_caller_account",
        lambda self, session, region: "123456789012",
    )
    monkeypatch.setattr(
        module.SecurityHubReporter,
        "_archive_scope",
        lambda self, model: ("source", None),
    )
    monkeypatch.setattr(
        module.SecurityHubReporter,
        "build_asff_findings",
        lambda self, model, account_id, region: [],
    )
    monkeypatch.setattr(module.SecurityHubReporter, "_existing_findings", _unreadable)
    reporter = module.SecurityHubReporter(
        context=_context(tmp_path, [scope]),
        config=module.SecurityHubReporterConfig(
            enabled=True,
            options=module.SecurityHubReporterConfigOptions(
                aws_region="us-east-1",
                account_id="123456789012",
                archive_resolved_findings=True,
                findings_scope=scope,
            ),
        ),
    )
    logged.clear()

    # The unread findings fail the import afterwards; this cell reads the line
    # logged where the read failed.
    with pytest.raises(module.SecurityHubImportError):
        reporter.report(AshAggregatedResults())
    _no_value(logged, "could not read the existing findings", scope)


def test_cloudwatch_sts_check_failure(tmp_path, logged, monkeypatch):
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        cloudwatch_logs_reporter as module,
    )

    # A region the options' pattern admits; an unused one, so it is the
    # configured value wherever it shows.
    region = "eu-central-7"

    def _no_client(service, region_name=None):
        raise RuntimeError(
            "Could not connect to the endpoint URL: "
            f"https://sts.{region_name}.amazonaws.com/"
        )

    monkeypatch.setattr(module.boto3, "client", _no_client)
    reporter = module.CloudWatchLogsReporter(
        context=_context(tmp_path, [region]),
        config=module.CloudWatchLogsReporterConfig(
            options=module.CloudWatchLogsReporterConfigOptions(
                aws_region=region, log_group_name="/ash/results"
            )
        ),
    )
    logged.clear()

    assert reporter.validate_plugin_dependencies() is False
    _no_value_in([*logged, *reporter.errors], "Error when calling STS", region)


def test_cloudwatch_publish_failure(tmp_path, logged, monkeypatch):
    """The failure is logged and kept in the errors, redacted; report() returns
    None, so no report is written from the failure text."""
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        cloudwatch_logs_reporter as module,
    )

    group = "/ENVCANARY-absent/group"

    def _refused(self, client, **kwargs):
        raise RuntimeError(f"ResourceNotFoundException: {group} does not exist")

    monkeypatch.setattr(module.boto3, "client", MagicMock())
    monkeypatch.setattr(
        module.CloudWatchLogsReporter,
        "_create_log_stream_with_retry",
        lambda self, client: None,
    )
    monkeypatch.setattr(
        module.CloudWatchLogsReporter, "_put_log_events_with_retry", _refused
    )
    reporter = module.CloudWatchLogsReporter(
        context=_context(tmp_path, [group]),
        config=module.CloudWatchLogsReporterConfig(
            options=module.CloudWatchLogsReporterConfigOptions(
                aws_region="us-east-1",
                log_group_name=group,
                log_stream_name="ASHScanResults",
            )
        ),
    )
    logged.clear()

    returned = reporter.report(AshAggregatedResults())

    _no_value_in(
        [*logged, *reporter.errors],
        "Error when publishing results to CloudWatch Logs after retries",
        group,
    )
    # A failed publish produces no report: the error is in the log, redacted,
    # and report() returns None (a text would be written as the report).
    assert returned is None
    _no_value_in([*logged, *reporter.errors], "does not exist", "ENVCANARY-absent")


@pytest.mark.parametrize("code", ["AccessDeniedException", None])
def test_cloudwatch_create_stream_failure(tmp_path, logged, code):
    """A ClientError other than already-exists, and any other exception."""
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        cloudwatch_logs_reporter as module,
    )

    group = "/ENVCANARY-failed/group"
    reporter = module.CloudWatchLogsReporter(
        context=_context(tmp_path, [group]),
        config=module.CloudWatchLogsReporterConfig(
            options=module.CloudWatchLogsReporterConfigOptions(
                aws_region="us-east-1",
                log_group_name=group,
                log_stream_name="ASHScanResults",
                max_retries=0,
            )
        ),
    )
    client = MagicMock()
    client.create_log_stream.side_effect = (
        ClientError(
            {"Error": {"Code": code, "Message": f"no access to {group}"}},
            "CreateLogStream",
        )
        if code
        else RuntimeError(f"no access to {group}")
    )
    logged.clear()

    reporter._create_log_stream_with_retry(client)

    _no_value_in([*logged, *reporter.errors], "Error when creating log stream", group)


# ---------------------------------------------------------------------------
# Defaults the reporters' options read from the environment
# ---------------------------------------------------------------------------
#
# An option the config leaves unset takes its value from an ASH_* variable:
# s3's bucket_name from ASH_S3_BUCKET_NAME, cloudwatch-logs' log_group_name from
# ASH_CLOUDWATCH_LOG_GROUP_NAME, bedrock-summary-reporter's model_id from
# ASH_BEDROCK_MODEL_ID. That value never went through the config's ${VAR}
# expansion, so the config records it when it is built, and the lines that name
# the option are redacted with it. AWS_REGION, AWS_DEFAULT_REGION and AWS_PROFILE
# are left as written.

REPORTER_DEFAULTS = {
    "ASH_S3_BUCKET_NAME": "envcanary-default-bucket",
    "ASH_CLOUDWATCH_LOG_GROUP_NAME": "/ENVCANARY-default/group",
    "ASH_BEDROCK_MODEL_ID": "envcanary-default-model",
}


def _config_from_a_file(tmp_path) -> AshConfig:
    """The config a run loads from its file, which reads one value through ${VAR}."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    profile = tmp_path / "project-from-env.ash.yaml"
    profile.write_text("project_name: ${ASH_PROJECT_FROM_ENV}\n", encoding="utf-8")
    return load_config_file_for_run(profile)[1]


def _run_context(tmp_path, config: AshConfig) -> PluginContext:
    """A context with *config* as it was built: its own environment values."""
    for name in ("source", "output", "work"):
        (tmp_path / name).mkdir(exist_ok=True)
    return PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=config,
    )


@pytest.mark.parametrize("built", ["in memory", "from a file"])
@pytest.mark.parametrize("variable", sorted(REPORTER_DEFAULTS))
def test_a_reporter_default_read_from_the_environment_is_recorded(
    tmp_path, monkeypatch, variable, built
):
    value = REPORTER_DEFAULTS[variable]
    monkeypatch.setenv(variable, value)
    monkeypatch.setenv("ASH_PROJECT_FROM_ENV", "envcanary-project-from-env")

    config = AshConfig() if built == "in memory" else _config_from_a_file(tmp_path)

    recorded = config_environment_values(config)
    assert value in recorded, recorded
    if built == "from a file":
        # The value the file read through ${VAR} is kept beside it.
        assert "envcanary-project-from-env" in recorded, recorded


@pytest.mark.parametrize(
    "variable", ["AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE"]
)
def test_the_standard_aws_variables_are_left_as_written(monkeypatch, variable):
    monkeypatch.setenv(variable, "left-as-written-value")

    assert "left-as-written-value" not in config_environment_values(AshConfig())


def test_a_default_bucket_is_redacted_from_the_upload_line(
    tmp_path, logged, monkeypatch
):
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        s3_reporter as module,
    )

    bucket = REPORTER_DEFAULTS["ASH_S3_BUCKET_NAME"]
    monkeypatch.setenv("ASH_S3_BUCKET_NAME", bucket)
    monkeypatch.setattr(module.boto3, "Session", MagicMock())
    monkeypatch.setattr(
        module.S3Reporter, "_put_object_with_retry", lambda self, *a, **k: None
    )
    reporter = module.S3Reporter(
        context=_run_context(tmp_path, AshConfig()),
        config=module.S3ReporterConfig(
            options=module.S3ReporterConfigOptions(aws_region="us-east-1")
        ),
    )
    # The control: the bucket is the default the variable gave.
    assert reporter.config.options.bucket_name == bucket
    logged.clear()

    reporter.report(AshAggregatedResults())

    _no_value(logged, "Successfully uploaded report to", bucket)


def test_a_default_log_group_is_redacted_from_the_publish_line(
    tmp_path, logged, monkeypatch
):
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        cloudwatch_logs_reporter as module,
    )

    group = REPORTER_DEFAULTS["ASH_CLOUDWATCH_LOG_GROUP_NAME"]
    monkeypatch.setenv("ASH_CLOUDWATCH_LOG_GROUP_NAME", group)
    monkeypatch.setenv("ASH_PROJECT_FROM_ENV", "project-from-env")
    monkeypatch.setattr(module.boto3, "client", MagicMock())
    monkeypatch.setattr(
        module.CloudWatchLogsReporter,
        "_create_log_stream_with_retry",
        lambda self, client: None,
    )
    monkeypatch.setattr(
        module.CloudWatchLogsReporter,
        "_put_log_events_with_retry",
        lambda self, client, **kwargs: {},
    )
    reporter = module.CloudWatchLogsReporter(
        context=_run_context(tmp_path, _config_from_a_file(tmp_path)),
        config=module.CloudWatchLogsReporterConfig(
            options=module.CloudWatchLogsReporterConfigOptions(aws_region="us-east-1")
        ),
    )
    # The control: the group is the default the variable gave.
    assert reporter.config.options.log_group_name == group
    logged.clear()

    reporter.report(AshAggregatedResults())

    _no_value(logged, "Publishing event to CloudWatch Logs, to the log group", group)
