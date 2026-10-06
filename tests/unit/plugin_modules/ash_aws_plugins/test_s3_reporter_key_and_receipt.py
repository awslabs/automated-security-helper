# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: the S3 object key names the scan, and ash.s3.json is JSON.

Two defects, both visible in a real scan's output:

* The key was ``ash-reports/ash-report-None.json`` for every scan. It was built
  from ``metadata.summary_stats.start``, which the engine assigns only after the
  report phase, so every upload overwrote the last.
* ``report()`` returned the bare ``s3://`` URL, and ``ReportPhase`` writes the
  return value to ``reports/ash.s3.json``: a ``.json`` file holding text that is
  not JSON. A failed upload wrote its error message there instead.

These use a real ``AshAggregatedResults`` rather than a ``MagicMock`` model,
because a mock answers any attribute with a truthy object and so cannot show
which field the key was read from.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
    S3ReporterConfig,
    S3ReporterConfigOptions,
)

BUCKET = "fixture-bucket"


@pytest.fixture
def reporter(tmp_path) -> S3Reporter:
    return S3Reporter(
        context=PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            config=AshConfig(),
        ),
        config=S3ReporterConfig(
            options=S3ReporterConfigOptions(bucket_name=BUCKET, aws_region="us-east-1")
        ),
    )


def _report(reporter, model, put_side_effect=None):
    captured = {}

    def _put(*args, **kwargs):
        if put_side_effect is not None:
            raise put_side_effect
        captured.update(kwargs)

    with patch("boto3.Session", MagicMock()):
        with patch.object(S3Reporter, "_put_object_with_retry", _put):
            result = reporter.report(model)
    return result, captured


def test_the_key_uses_the_scan_timestamp_not_none(reporter):
    model = AshAggregatedResults()
    assert model.metadata.summary_stats.start is None  # as during a real scan
    _, put = _report(reporter, model)
    assert put["Key"] == f"ash-reports/ash-report-{model.metadata.generated_at}.json"
    assert "None" not in put["Key"]


def test_two_scans_get_two_keys(reporter):
    first = AshAggregatedResults()
    first.metadata.generated_at = "2026-10-01T09:00:00+00:00"
    second = AshAggregatedResults()
    second.metadata.generated_at = "2026-10-01T09:00:01+00:00"
    assert _report(reporter, first)[1]["Key"] != _report(reporter, second)[1]["Key"]


def test_re_reporting_a_finished_scan_reuses_its_key(reporter):
    """``ashx report`` reads a model whose ``start`` is set; the key must not move."""
    during_scan = AshAggregatedResults()
    during_scan.metadata.generated_at = "2026-10-01T09:00:00+00:00"
    after_scan = AshAggregatedResults.model_validate_json(
        during_scan.model_dump_json(by_alias=True)
    )
    after_scan.metadata.summary_stats.start = "2026-10-01T09:00:00+00:00"
    after_scan.metadata.generated_at = during_scan.metadata.generated_at
    assert (
        _report(reporter, during_scan)[1]["Key"]
        == _report(reporter, after_scan)[1]["Key"]
    )


def test_the_returned_report_is_a_json_receipt(reporter, tmp_path):
    model = AshAggregatedResults()
    result, put = _report(reporter, model)

    receipt = json.loads(result)  # what ReportPhase writes to ash.s3.json
    assert receipt["bucket"] == BUCKET
    assert receipt["key"] == put["Key"]
    assert receipt["url"] == f"s3://{BUCKET}/{put['Key']}"
    assert receipt["file_format"] == "json"

    local_copy = tmp_path / "out" / "reports" / "s3-report.json"
    assert receipt["local_copy"] == local_copy.as_posix()
    assert local_copy.read_text(encoding="utf-8") == put["Body"]


def test_a_failed_upload_returns_none_rather_than_an_error_string(reporter):
    reporter._plugin_log = MagicMock()
    result, _ = _report(
        reporter, AshAggregatedResults(), put_side_effect=RuntimeError("denied")
    )
    assert result is None
    assert "denied" in reporter._plugin_log.call_args[0][0]
