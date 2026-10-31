# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The S3 object name follows ``key_prefix`` exactly as the operator wrote it.

The object name is ``<key_prefix>[<project>/]ash-report-<time>.<extension>``. The
prefix used to be joined to the file name with a ``/`` when it did not end in
one, which moved the objects an operator's notifications, lifecycle rules and
queries already match: ``scans/repo-`` wrote ``scans/repo-/ash-report-...`` where
it had always written ``scans/repo-ash-report-...``. The prefix is used as
written again, and one that does not end in ``/`` is warned about once per run,
because the name then runs on from it.

No test here calls AWS: boto3 is patched out of the module and the upload is a
stand-in for ``put_object``.
"""

import logging
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.options import reset_refused_tool_version_warnings
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
    S3ReporterConfig,
    S3ReporterConfigOptions,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

S3 = "automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter"

GENERATED_AT = "2026-01-15T12:00:00+00:00"


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_refused_tool_version_warnings()
    yield
    reset_refused_tool_version_warnings()


@pytest.fixture
def ash_log():
    """Capture ASH_LOGGER records; it does not propagate, so caplog sees nothing."""
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)


def _prefix_warnings(records) -> List[str]:
    return [
        record.getMessage()
        for record in records
        if record.levelno == logging.WARNING and "key_prefix" in record.getMessage()
    ]


def _model():
    model = MagicMock()
    model.to_simple_dict.return_value = {"a": 1}
    model.sarif = None
    model.metadata.generated_at = GENERATED_AT
    model.metadata.workspace_project = None
    model.workspace = None
    return model


def _upload_keys(tmp_path, key_prefix, reports=1) -> List[str]:
    """The object key of each of ``reports`` uploads made with ``key_prefix``."""
    reporter = S3Reporter(
        context=PluginContext(
            source_dir=tmp_path / "src",
            output_dir=tmp_path / "output",
            work_dir=tmp_path / "work",
        ),
        config=S3ReporterConfig(
            options=S3ReporterConfigOptions(
                aws_region="us-west-2", bucket_name="a-bucket", key_prefix=key_prefix
            )
        ),
    )
    keys: List[str] = []

    def _put(*args, **kwargs):
        keys.append(kwargs["Key"])

    with patch(f"{S3}.boto3"):
        with patch.object(S3Reporter, "_put_object_with_retry", _put):
            for _ in range(reports):
                assert reporter.report(_model()) is not None
    return keys


def test_a_prefix_ending_in_a_dash_names_the_object_as_written(tmp_path):
    keys = _upload_keys(tmp_path, "scans/repo-")

    assert keys == [f"scans/repo-ash-report-{GENERATED_AT}.json"]


@pytest.mark.parametrize("key_prefix", ["scans/repo/", "ash-reports/"])
def test_a_prefix_ending_in_a_slash_is_unchanged_and_not_warned_about(
    tmp_path, key_prefix, ash_log
):
    keys = _upload_keys(tmp_path, key_prefix)

    assert keys == [f"{key_prefix}ash-report-{GENERATED_AT}.json"]
    assert _prefix_warnings(ash_log) == []


def test_no_prefix_names_the_object_at_the_bucket_root(tmp_path, ash_log):
    keys = _upload_keys(tmp_path, "")

    assert keys == [f"ash-report-{GENERATED_AT}.json"]
    assert _prefix_warnings(ash_log) == []


def test_a_prefix_with_no_trailing_slash_is_warned_about_once_per_run(
    tmp_path, ash_log
):
    keys = _upload_keys(tmp_path, "scans/repo-", reports=2)

    assert len(keys) == 2
    messages = _prefix_warnings(ash_log)
    assert len(messages) == 1, messages


def test_the_warning_does_not_quote_the_prefix(tmp_path, ash_log):
    """A configured option can come from the environment, and the warning goes
    to the console and ash.log."""
    _upload_keys(tmp_path, "scans/private-name")

    (message,) = _prefix_warnings(ash_log)
    assert "private-name" not in message
