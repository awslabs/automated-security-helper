# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What each AWS reporter returns, and exactly what it sends to AWS.

Two snapshots per reporter and model shape: the string ``report()`` returns, which
ASH writes to ``reports/ash.<extension>``, and the list of API calls the reporter
made, with their parameters. The second is the one that matters most for these
reporters, because the payload is what leaves the machine.

AWS is stubbed with real botocore clients whose ``before-call`` hook answers every
operation in-process, the mechanism ``botocore.stub.Stubber`` is built on. A
Stubber needs its responses queued in call order, and the Bedrock reporter's call
count depends on the findings, so the stub answers by operation instead. Parameters
are still validated against the service model, the request is still serialized, and
an operation the stub does not expect fails the test instead of reaching the network.

Every option a reporter would otherwise read from the environment (region, profile,
bucket, log group, model id) is pinned in its config here: those defaults are taken
from ``os.environ`` when the reporter module is imported, so leaving them unset
would make the snapshot depend on the shell that ran the test.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Callable

import pytest

from tests.snapshot.support.reporter_catalog import (
    AWS_REPORTER_NAMES,
    MODEL_VARIANTS,
    reporter_classes,
    snapshot_extension,
)

# The AWS reporters render the fixture scan under the pinned clock; durations are fixed.
pytestmark = pytest.mark.snapshot_masking(
    mask_durations=False, mask_duration_keys=False
)

REGION = "us-east-1"


class AwsStub:
    """Hands out botocore clients that record every call and never open a socket."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self._converse_count = 0
        self._responders: dict[tuple[str, str], Callable[[dict], dict]] = {
            ("logs", "CreateLogStream"): lambda params: {},
            ("logs", "PutLogEvents"): lambda params: {
                "nextSequenceToken": "fixture-sequence-token-1"
            },
            ("s3", "PutObject"): lambda params: {"ETag": '"fixture-etag"'},
            ("bedrock-runtime", "Converse"): self._converse,
        }

    def _converse(self, params: dict) -> dict:
        self._converse_count += 1
        return {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"text": f"[stubbed model response {self._converse_count}]"}
                    ],
                }
            },
            "stopReason": "end_turn",
            "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
            "metrics": {"latencyMs": 1},
        }

    def client(self, service_name: str, region_name: str | None = None, **_: Any):
        import botocore.session

        client = botocore.session.Session().create_client(
            service_name,
            region_name=region_name or REGION,
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            aws_session_token="testing",
        )
        client.meta.events.register("provide-client-params.*.*", self._record)
        client.meta.events.register_first("before-call.*.*", self._respond)
        return client

    def session(self, **session_kwargs: Any):
        stub = self

        class _Session:
            def client(self, service_name: str, **kwargs: Any):
                return stub.client(
                    service_name,
                    region_name=kwargs.get("region_name")
                    or session_kwargs.get("region_name"),
                )

        return _Session()

    def _record(self, params: dict, model: Any, **_: Any) -> None:
        self.calls.append(
            {
                "service": model.service_model.service_name,
                "operation": model.name,
                "params": copy.deepcopy(params),
            }
        )

    def _respond(self, model: Any, **_: Any):
        from botocore.awsrequest import AWSResponse

        key = (model.service_model.service_name, model.name)
        if key not in self._responders:
            raise AssertionError(f"unexpected AWS call {key}; add a stubbed response")
        params = self.calls[-1]["params"] if self.calls else {}
        return AWSResponse(None, 200, {}, None), self._responders[key](params)

    def recorded_calls(self) -> list[dict[str, Any]]:
        """The calls, with JSON string payloads decoded so they diff line by line."""
        calls = copy.deepcopy(self.calls)
        for call in calls:
            params = call["params"]
            for event in params.get("logEvents", []):
                event["message"] = json.loads(event["message"])
            if call["operation"] == "PutObject":
                params["Body"] = json.loads(params["Body"])
        return calls


@pytest.fixture
def aws_stub(monkeypatch: pytest.MonkeyPatch) -> AwsStub:
    """Route every AWS reporter's boto3 through :class:`AwsStub`."""
    import importlib

    for name in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"):
        monkeypatch.setenv(name, "/nonexistent/snapshot-aws-config")
    for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        monkeypatch.delenv(name, raising=False)

    stub = AwsStub()

    class _Boto3:
        client = staticmethod(stub.client)
        Session = staticmethod(stub.session)

    for module in (
        "security_hub_reporter",
        "cloudwatch_logs_reporter",
        "s3_reporter",
        "bedrock_summary_reporter",
    ):
        reporter_module = importlib.import_module(
            f"automated_security_helper.plugin_modules.ash_aws_plugins.{module}"
        )
        monkeypatch.setattr(reporter_module, "boto3", _Boto3)
    return stub


def _pinned_config(name: str):
    """Each reporter's config with every environment-derived option set explicitly."""
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        bedrock_summary_reporter as bedrock,
    )
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        cloudwatch_logs_reporter as cwlogs,
    )
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        s3_reporter as s3,
    )
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        security_hub_reporter as securityhub,
    )

    if name == "aws-security-hub":
        return securityhub.SecurityHubReporterConfig(
            options=securityhub.SecurityHubReporterConfigOptions(
                aws_region=REGION, aws_profile=None, account_id="123456789012"
            )
        )
    if name == "cloudwatch-logs":
        return cwlogs.CloudWatchLogsReporterConfig(
            options=cwlogs.CloudWatchLogsReporterConfigOptions(
                aws_region=REGION, log_group_name="/ash/snapshot-fixture"
            )
        )
    if name == "s3":
        return s3.S3ReporterConfig(
            options=s3.S3ReporterConfigOptions(
                aws_region=REGION,
                aws_profile=None,
                bucket_name="snapshot-fixture-reports",
            )
        )
    if name == "bedrock-summary-reporter":
        return bedrock.BedrockSummaryReporterConfig(
            options=bedrock.BedrockSummaryReporterConfigOptions(
                aws_region=REGION,
                aws_profile=None,
                model_id="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
                temperature=0.5,
                max_tokens=4000,
            )
        )
    raise KeyError(name)


@pytest.mark.parametrize("variant", MODEL_VARIANTS)
@pytest.mark.parametrize("reporter_name", AWS_REPORTER_NAMES)
def test_aws_reporter_output_and_payload(
    reporter_name, variant, fixture_variant, aws_stub, text_snapshot, snapshot
):
    model, context = fixture_variant(variant)
    reporter = reporter_classes()[reporter_name](
        context=context, config=_pinned_config(reporter_name)
    )

    document = reporter.report(model)

    assert document == text_snapshot(snapshot_extension(reporter))
    assert aws_stub.recorded_calls() == snapshot(name="aws_calls")


@pytest.mark.parametrize("variant", MODEL_VARIANTS)
def test_bedrock_summary_markdown_files(
    variant, fixture_variant, aws_stub, text_snapshot
):
    """The markdown files the Bedrock reporter writes beside its returned summary."""
    model, context = fixture_variant(variant)
    reporter = reporter_classes()["bedrock-summary-reporter"](
        context=context, config=_pinned_config("bedrock-summary-reporter")
    )
    reporter.report(model)

    options = reporter.config.options
    reports_dir = context.output_dir / "reports"
    for filename in (options.output_executive_file, options.output_technical_file):
        path = reports_dir / filename
        written = (
            path.read_text("utf-8") if path.is_file() else f"<not written: {filename}>"
        )
        assert written == text_snapshot("md")(name=filename.removesuffix(".md"))
