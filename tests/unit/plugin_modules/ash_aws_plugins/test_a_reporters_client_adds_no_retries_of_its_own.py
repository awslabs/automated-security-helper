# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reporter's own retries are the only retries its client makes.

The Bedrock summary, CloudWatch Logs and S3 reporters repeat a failed call
``max_retries`` times with ``retry_with_backoff``, and that decorator repeats a
connection failure (``failure_is_transient``). A client built with no botocore
``Config`` retries a connection failure itself, five attempts in legacy mode,
inside every call the decorator makes. One failed call is then
``(max_retries + 1) * 5`` requests, a slow model holds a call for many minutes
before the fallback walk moves on, ``PutLogEvents`` can write twice, and
``max_retries: 0`` still sends five requests.

Each reporter now builds the client it wraps in ``retry_with_backoff`` with a
``Config`` that makes one attempt per call, so ``max_retries`` decides the
count. These tests read the ``Config`` each reporter hands its client factory,
then build a real botocore client from it and count the requests a failing
connection costs. No request leaves the process: the client's endpoint is a
loopback address, which the suite's botocore guard lets through to botocore's
HTTP session, and that session is replaced by a counter that raises a connection
error. The credentials are placeholders.
"""

import os
import time
from unittest.mock import MagicMock

import boto3
import botocore.exceptions
import botocore.httpsession
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
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
    MODULE as BEDROCK_MODULE,
    finding,
    make_reporter,
    sarif_model,
)

pytestmark = pytest.mark.unit

LOGS_MODULE = (
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter"
)
S3_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter"

#: What botocore is told for a client whose calls the reporter repeats itself.
ONE_ATTEMPT = {"mode": "standard", "total_max_attempts": 1}

#: botocore's retries in legacy mode, the mode of a client built with no Config.
LEGACY_ATTEMPTS = 5

#: The endpoint of every real client below. The suite refuses a botocore request
#: to any other host before it reaches the HTTP session this module replaces, and
#: a client left on its default endpoint names a real AWS host.
LOOPBACK_ENDPOINT = "http://localhost:9"


def _disarm(monkeypatch):
    """No profile, retry setting or credential file of the host reaches a client."""
    for name in ("AWS_MAX_ATTEMPTS", "AWS_RETRY_MODE", "AWS_PROFILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", os.devnull)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", os.devnull)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


def _failing_connection(monkeypatch):
    """Replace botocore's HTTP session with a counter that fails every request
    with a connection error, and stop every sleep. Returns the requests sent."""
    sent = []

    def send(self, request):
        sent.append(request)
        raise botocore.exceptions.EndpointConnectionError(endpoint_url=request.url)

    monkeypatch.setattr(botocore.httpsession.URLLib3Session, "send", send)
    monkeypatch.setattr(time, "sleep", lambda seconds: None)
    return sent


def _real_client(service, config):
    """A real botocore client built with the ``config`` a reporter handed its
    factory (None when it handed none), aimed at a loopback endpoint."""
    session = boto3.session.Session(
        aws_access_key_id="placeholder",
        aws_secret_access_key="placeholder",
        region_name="us-east-1",
    )
    return session.client(service, config=config, endpoint_url=LOOPBACK_ENDPOINT)


def _config_for(built, service):
    configs = [kwargs.get("config") for name, kwargs in built if name == service]
    assert len(configs) == 1, built
    return configs[0]


def _bedrock(context, monkeypatch, max_retries):  # noqa: F811
    """The reporter and the Config it gave the bedrock-runtime client."""
    reporter = make_reporter(
        context,
        max_retries=max_retries,
        base_delay=0.0,
        max_delay=0.0,
        add_section_headers=False,
        output_markdown=False,
    )
    built = []

    class Session:
        def __init__(self, **kwargs):
            pass

        def client(self, service, **kwargs):
            built.append((service, kwargs))
            return MagicMock()

    monkeypatch.setattr(f"{BEDROCK_MODULE}.boto3.Session", Session)
    monkeypatch.setattr(
        BedrockSummaryReporter, "_run_simple_report", lambda *args, **kwargs: "text"
    )

    reporter.report(sarif_model([finding()]))

    return reporter, _config_for(built, "bedrock-runtime")


def _logs(context, monkeypatch, max_retries):  # noqa: F811
    """The reporter and the Config it gave the CloudWatch Logs client."""
    reporter = CloudWatchLogsReporter(
        context=context,
        config=CloudWatchLogsReporterConfig(
            options=CloudWatchLogsReporterConfigOptions(
                aws_region="us-west-2",
                log_group_name="group",
                log_stream_name="stream",
                max_retries=max_retries,
                base_delay=0.0,
                max_delay=0.0,
            )
        ),
    )
    built = []

    def client(service, **kwargs):
        built.append((service, kwargs))
        return MagicMock()

    monkeypatch.setattr(f"{LOGS_MODULE}.boto3.client", client)
    model = MagicMock()
    model.to_simple_dict.return_value = {"finding": "none"}

    reporter.report(model)

    return reporter, _config_for(built, "logs")


def _s3(context, monkeypatch, max_retries):  # noqa: F811
    """The reporter and the Config it gave the S3 client."""
    reporter = S3Reporter(
        context=context,
        config=S3ReporterConfig(
            options=S3ReporterConfigOptions(
                aws_region="us-west-2",
                bucket_name="bucket",
                max_retries=max_retries,
                base_delay=0.0,
                max_delay=0.0,
            )
        ),
    )
    built = []

    class Session:
        def __init__(self, **kwargs):
            pass

        def client(self, service, **kwargs):
            built.append((service, kwargs))
            return MagicMock()

    monkeypatch.setattr(f"{S3_MODULE}.boto3.Session", Session)
    model = MagicMock()
    model.to_simple_dict.return_value = {"finding": "none"}
    model.metadata.generated_at = "2026-01-01T00:00:00+00:00"

    reporter.report(model)

    return reporter, _config_for(built, "s3")


@pytest.mark.parametrize("build", [_bedrock, _logs, _s3], ids=["bedrock", "logs", "s3"])
def test_the_reporter_builds_its_client_to_make_one_attempt_per_call(
    context,  # noqa: F811
    monkeypatch,
    build,
):
    _, config = build(context, monkeypatch, 2)

    assert config is not None, "the client was built with no Config"
    assert config.retries == ONE_ATTEMPT, config.retries


@pytest.mark.parametrize("max_retries", [0, 2])
def test_a_failed_connection_costs_the_bedrock_runtime_max_retries_plus_one_requests(
    context,  # noqa: F811
    monkeypatch,
    max_retries,
):
    _disarm(monkeypatch)
    reporter, config = _bedrock(context, monkeypatch, max_retries)
    sent = _failing_connection(monkeypatch)
    runtime = _real_client("bedrock-runtime", config)

    outcome = reporter._make_model_client(runtime).call("a prompt", "a system prompt")

    assert outcome.ok is False, outcome
    assert len(sent) == max_retries + 1, (
        f"{len(sent)} requests for max_retries={max_retries}; "
        f"{(max_retries + 1) * LEGACY_ATTEMPTS} means botocore retries inside "
        "each of the reporter's attempts"
    )


@pytest.mark.parametrize("max_retries", [0, 2])
def test_a_failed_connection_costs_put_log_events_max_retries_plus_one_requests(
    context,  # noqa: F811
    monkeypatch,
    max_retries,
):
    _disarm(monkeypatch)
    reporter, config = _logs(context, monkeypatch, max_retries)
    sent = _failing_connection(monkeypatch)
    logs = _real_client("logs", config)

    with pytest.raises(botocore.exceptions.EndpointConnectionError):
        reporter._put_log_events_with_retry(
            logs,
            logGroupName="group",
            logStreamName="stream",
            logEvents=[{"timestamp": 1, "message": "a message"}],
        )

    assert len(sent) == max_retries + 1, (
        f"{len(sent)} requests for max_retries={max_retries}; "
        f"{(max_retries + 1) * LEGACY_ATTEMPTS} means botocore retries inside "
        "each of the reporter's attempts, and a write can land twice"
    )


@pytest.mark.parametrize("max_retries", [0, 2])
def test_a_failed_connection_costs_put_object_max_retries_plus_one_requests(
    context,  # noqa: F811
    monkeypatch,
    max_retries,
):
    _disarm(monkeypatch)
    reporter, config = _s3(context, monkeypatch, max_retries)
    sent = _failing_connection(monkeypatch)
    s3 = _real_client("s3", config)

    with pytest.raises(botocore.exceptions.EndpointConnectionError):
        reporter._put_object_with_retry(s3, Bucket="bucket", Key="key", Body=b"data")

    assert len(sent) == max_retries + 1, (
        f"{len(sent)} requests for max_retries={max_retries}; "
        f"{(max_retries + 1) * LEGACY_ATTEMPTS} means botocore retries inside "
        "each of the reporter's attempts"
    )
