# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the CloudWatch Logs and S3 reporters send holds no value read from the
environment.

Both send the results' simple dict (AshAggregatedResults.to_simple_dict), the
configuration included, and the CloudWatch Logs reporter also logs it under
--verbose. Where the configuration read a value from the environment, what is
sent and logged keeps the reference as the file wrote it, as a results file
does. A stand-in client receives what would be sent.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import resolve_env_references
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
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

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e-0123456789"
VALUE = "${ASH_PROBE_VALUE}"
CLOUDWATCH = (
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter"
)
S3 = "automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter"


@pytest.fixture
def results(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AshAggregatedResults:
    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    # The control: the canary's variable is one a configuration reads.
    assert resolve_env_references(VALUE) == CANARY
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        f"project_name: {VALUE}\n"
        "reporters:\n"
        "  gitlab-cyclonedx:\n"
        "    options:\n"
        f"      language_override: {VALUE}\n",
        encoding="utf-8",
    )
    config = resolve_config(config_file)
    # The control: the run has the value.
    assert config.project_name == CANARY
    model = AshAggregatedResults(ash_config=config)
    model.metadata.project_name = config.project_name
    return model


def _context(tmp_path: Path, model: AshAggregatedResults) -> PluginContext:
    return PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=model.ash_config,
    )


def test_cloudwatch_logs_sends_and_logs_the_reference(tmp_path, results):
    client = MagicMock()
    reporter = CloudWatchLogsReporter(
        context=_context(tmp_path, results),
        config=CloudWatchLogsReporterConfig(
            options=CloudWatchLogsReporterConfigOptions(
                aws_region="us-west-2",
                log_group_name="group",
                log_stream_name="stream",
            )
        ),
    )
    with (
        patch(f"{CLOUDWATCH}.boto3.client", return_value=client),
        patch(f"{CLOUDWATCH}.ASH_LOGGER") as log,
    ):
        reporter.report(results)

    sent = " ".join(str(call) for call in client.put_log_events.mock_calls)
    logged = " ".join(str(call) for call in log.verbose.mock_calls)
    # The control: the event was sent and logged, with the reference.
    assert VALUE in sent, sent
    assert VALUE in logged, logged
    assert CANARY not in sent, sent
    assert CANARY not in logged, logged


def test_s3_uploads_the_reference(tmp_path, results):
    session = MagicMock()
    reporter = S3Reporter(
        context=_context(tmp_path, results),
        config=S3ReporterConfig(
            options=S3ReporterConfigOptions(
                aws_region="us-west-2", bucket_name="bucket", file_format="json"
            )
        ),
    )
    with patch(f"{S3}.boto3.Session", return_value=session):
        reporter.report(results)

    uploaded = " ".join(
        str(call) for call in session.client.return_value.put_object.mock_calls
    )
    # The control: the object was uploaded, with the reference.
    assert VALUE in uploaded, uploaded
    assert CANARY not in uploaded, uploaded
