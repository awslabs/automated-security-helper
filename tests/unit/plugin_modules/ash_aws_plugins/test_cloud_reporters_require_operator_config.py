# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Reporters that contact AWS run, and check their dependencies, only when the operator enabled them.

The Security Hub, CloudWatch Logs, S3 and Bedrock summary reporters defaulted
to ``enabled: True`` (now ``False``). Once ``ash_aws_plugins`` is imported -- by
an earlier scan, by an MCP server that loaded it once, or by any test -- an
in-process scan builds each of them and calls ``validate_plugin_dependencies``,
and that already contacts AWS with whatever credentials the host has: Security
Hub calls ``DescribeHub``, the others call STS. Reporter destinations and
credentials are the operator's, so:

* a scan whose operator did not enable a cloud reporter creates no AWS session,
  client or request for it, and does not run it -- whether or not its module is
  loaded;
* the same holds when the report phase re-renders stored results;
* an operator config that enables one does reach it (the control).

Every test runs with no ``AWS_*`` credentials in the environment, a loopback
endpoint, and botocore's request method replaced by a recorder that refuses
every request it was not told to answer, so nothing here can reach AWS.
"""

import json

import boto3
import botocore.client
import botocore.exceptions
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    CloudWatchLogsReporter,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
)
from tests.utils.secret_bearing_scan import isolate_from_aws

# The scans here run detect-secrets, whose dependency check asked uv for its version
# (``uv tool run detect-secrets --version``) and so started the tool. These tests are
# about the reporters, so the probes answer without a process (tests/unit/conftest.py).
pytestmark = pytest.mark.usefixtures("no_tool_probes")

AWS_PLUGIN_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"

CLOUD_REPORTERS = (
    SecurityHubReporter,
    CloudWatchLogsReporter,
    S3Reporter,
    BedrockSummaryReporter,
)

ENABLE_SECURITY_HUB_ONLY = f"""
ash_plugin_modules:
  - {AWS_PLUGIN_MODULE}
reporters:
  aws-security-hub:
    enabled: true
    options:
      aws_region: us-east-1
      aws_profile: null
      account_id: "123456789012"
      findings_scope: fixture-project
"""


#: Every option each cloud reporter's dependency check needs, and no ``enabled``,
#: so that only the reporters' default of ``enabled: false`` keeps them off.
COMPLETE_OPTIONS_NO_ENABLED = f"""
ash_plugin_modules:
  - {AWS_PLUGIN_MODULE}
reporters:
  aws-security-hub:
    options:
      aws_region: us-east-1
      account_id: "123456789012"
  cloudwatch-logs:
    options:
      aws_region: us-east-1
      log_group_name: g
      max_retries: 0
  s3:
    options:
      bucket_name: b
      aws_region: us-east-1
      max_retries: 0
  bedrock-summary-reporter:
    options:
      aws_region: us-east-1
"""


class CloudCalls:
    """What the reporters asked of boto3 and botocore."""

    def __init__(self):
        self.sessions = []
        self.clients = []
        self.requests = []
        self.answers = {}

    def any(self):
        return self.sessions or self.clients or self.requests

    def summary(self):
        return {
            "sessions": self.sessions,
            "clients": self.clients,
            "requests": self.requests,
        }


@pytest.fixture
def cloud(monkeypatch, tmp_path):
    """Record every boto3 session and client and every botocore request; refuse requests."""
    isolate_from_aws(monkeypatch, tmp_path)
    calls = CloudCalls()
    real_session = boto3.Session
    real_client = boto3.client

    def recording_session(*args, **kwargs):
        calls.sessions.append(kwargs)
        return real_session(*args, **kwargs)

    def recording_client(service_name, *args, **kwargs):
        calls.clients.append(service_name)
        return real_client(service_name, *args, **kwargs)

    def recording_request(client, operation_name, api_params):
        key = (client.meta.service_model.service_name, operation_name)
        calls.requests.append(key)
        if key in calls.answers:
            return calls.answers[key]
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "refused by the test"}},
            operation_name,
        )

    monkeypatch.setattr(boto3, "Session", recording_session)
    monkeypatch.setattr(boto3, "client", recording_client)
    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", recording_request)
    return calls


@pytest.fixture
def reports_run(monkeypatch):
    """Names of the cloud reporters whose report() ran."""
    ran = []
    for cls in CLOUD_REPORTERS:
        original = cls.report

        def recording_report(self, model, _original=original, _name=cls.__name__):
            ran.append(_name)
            return _original(self, model)

        monkeypatch.setattr(cls, "report", recording_report)
    return ran


@pytest.fixture
def constructed(monkeypatch):
    """Names of the cloud reporters the run built, whether or not it ran them.

    A check that a reporter contacted nothing passes vacuously if the run never
    built it, for example because the run's plugin modules left the AWS package
    out; a test asserts on this first.
    """
    built = []
    for cls in CLOUD_REPORTERS:
        original = cls.model_post_init

        def recording_post_init(self, context, _original=original, _name=cls.__name__):
            built.append(_name)
            return _original(self, context)

        monkeypatch.setattr(cls, "model_post_init", recording_post_init)
    return built


def _source_tree(root):
    source_dir = root / "src"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "app.py").write_text("value = 1\n", encoding="utf-8")
    return source_dir


def _scan(source_dir, output_dir, **kwargs):
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    run_ash_scan(
        source_dir=str(source_dir),
        output_dir=str(output_dir),
        scanners=["detect-secrets"],
        offline=True,
        progress=False,
        quiet=True,
        show_summary=False,
        fail_on_findings=False,
        color=False,
        **kwargs,
    )
    # The scan itself finished, so an empty record means the reporters were not
    # asked, not that the run stopped first.
    assert (output_dir / "ash_aggregated_results.json").exists()
    assert (output_dir / "reports" / "ash.sarif").exists()


class TestCloudReportersNeedTheOperator:
    @pytest.mark.integration
    def test_a_loaded_cloud_reporter_contacts_nothing_when_no_config_enables_it(
        self, tmp_path, cloud, reports_run
    ):
        _scan(_source_tree(tmp_path), tmp_path / "out")

        assert not cloud.any(), cloud.summary()
        assert reports_run == []

    @pytest.mark.integration
    def test_loading_the_aws_module_without_enabling_a_reporter_contacts_nothing(
        self, tmp_path, cloud, reports_run
    ):
        _scan(
            _source_tree(tmp_path),
            tmp_path / "out",
            ash_plugin_modules=[AWS_PLUGIN_MODULE],
        )

        assert not cloud.any(), cloud.summary()
        assert reports_run == []

    # integration: _rerender runs run_ash_scan, a path that can start reporters
    # and scanners whatever this call's arguments keep it from doing.
    @pytest.mark.integration
    def test_rerendering_stored_results_contacts_nothing(
        self, tmp_path, cloud, reports_run, constructed
    ):
        from tests.utils.helpers import results_of_a_scan

        output_dir, results_file, operator_config = self._stored(
            tmp_path, results_of_a_scan()
        )

        self._rerender(tmp_path, output_dir, results_file, operator_config)

        assert (output_dir / "reports" / "ash.sarif").exists()
        # Precondition: the run built every cloud reporter, so "contacted
        # nothing" is about reporters it had, not ones it never saw.
        assert set(constructed) == {cls.__name__ for cls in CLOUD_REPORTERS}
        assert not cloud.any(), cloud.summary()
        assert reports_run == []

    @pytest.mark.integration
    def test_rerendering_results_that_hold_no_scan_is_refused(
        self, tmp_path, cloud, reports_run
    ):
        """Results with no scanner entry and no finding read as a clean scan, so
        ``--use-existing`` refuses them before any reporter runs, with the exit code
        of an input ASH cannot use (3)."""
        from automated_security_helper.models.asharp_model import AshAggregatedResults

        output_dir, results_file, operator_config = self._stored(
            tmp_path, AshAggregatedResults()
        )

        with pytest.raises(SystemExit) as exited:
            self._rerender(tmp_path, output_dir, results_file, operator_config)

        assert exited.value.code == 3
        assert not (output_dir / "reports" / "ash.sarif").exists()
        assert not cloud.any(), cloud.summary()
        assert reports_run == []

    @staticmethod
    def _stored(tmp_path, stored):
        """An output directory holding ``stored``, and an operator config whose
        cloud reporter sections are complete but enable none of them."""
        from automated_security_helper.config.default_config import get_default_config

        output_dir = tmp_path / "out"
        output_dir.mkdir()
        stored.ash_config = get_default_config()
        results_file = output_dir / "ash_aggregated_results.json"
        results_file.write_text(stored.model_dump_json(by_alias=True), encoding="utf-8")
        operator_config = tmp_path / "operator" / "ash.yaml"
        operator_config.parent.mkdir()
        operator_config.write_text(COMPLETE_OPTIONS_NO_ENABLED, encoding="utf-8")
        return output_dir, results_file, operator_config

    @staticmethod
    def _rerender(tmp_path, output_dir, results_file, operator_config):
        from automated_security_helper.interactions.run_ash_scan import run_ash_scan

        run_ash_scan(
            source_dir=str(_source_tree(tmp_path)),
            output_dir=str(output_dir),
            existing_results=str(results_file),
            config=str(operator_config),
            offline=True,
            progress=False,
            quiet=True,
            show_summary=False,
            fail_on_findings=False,
            fail_on_incomplete_scanners=False,
            color=False,
            # Named, not left to whatever this process happened to import, so the
            # run builds the AWS reporters however the plugin registry is scoped.
            ash_plugin_modules=[AWS_PLUGIN_MODULE],
        )

    @pytest.mark.integration
    def test_an_operator_config_that_enables_a_cloud_reporter_reaches_it(
        self, tmp_path, cloud, reports_run
    ):
        """Control: the operator's own config still turns a cloud reporter on."""
        cloud.answers[("securityhub", "DescribeHub")] = {
            "HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default"
        }
        operator_config = tmp_path / "operator" / "ash.yaml"
        operator_config.parent.mkdir()
        operator_config.write_text(ENABLE_SECURITY_HUB_ONLY, encoding="utf-8")
        output_dir = tmp_path / "out"

        _scan(_source_tree(tmp_path), output_dir, config=str(operator_config))

        assert ("securityhub", "DescribeHub") in cloud.requests
        assert "SecurityHubReporter" in reports_run
        written = json.loads(
            (output_dir / "reports" / "ash.aws-security-hub.asff.json").read_text(
                encoding="utf-8"
            )
        )
        # The import receipt (SecurityHubReporter._receipt): no findings in the
        # fixture tree, so nothing was sent, and the receipt says so.
        assert written["imported"] == 0
        assert written["findings"] == []
