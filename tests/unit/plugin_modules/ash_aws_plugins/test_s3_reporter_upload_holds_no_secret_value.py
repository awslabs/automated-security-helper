# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The S3 upload carries the SARIF report, and the SARIF report is masked.

The S3 reporter uploads the findings (``model.sarif``) beside the record that
``to_simple_dict()`` holds. A password a bandit rule quotes in its message, and
the source lines at the place a secret finding reports, must not reach the
bucket. The reporter does not mask anything itself: it relies on the results
model, which masks every secret finding as it is built from a stored results
file (``ash report`` reads one) and again when a scan saves its results, so what
the reporter is handed is already masked. These tests pin that reliance on the
path ``ash report`` takes, so a change that gives the upload a SARIF dump that
does not pass through the model's masking fails here.

No test here calls AWS: the upload is a stand-in for ``put_object``.
"""

import importlib
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
from tests.utils.secret_bearing_scan import (
    SECRETS,
    bandit_sarif,
    scanner_shaped_report,
)

pytestmark = pytest.mark.unit

#: A source line a bandit finding with no secret in it reports.
NON_SECRET_LINE = "subprocess.call(cmd, shell=True)"


@pytest.fixture
def reporter(tmp_path) -> S3Reporter:
    return S3Reporter(
        context=PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            config=AshConfig(),
        ),
        config=S3ReporterConfig(
            options=S3ReporterConfigOptions(
                bucket_name="fixture-bucket", aws_region="us-east-1"
            )
        ),
    )


def _unmasked_results_file() -> str:
    """A results file as an older producer wrote it: bandit's findings merged
    with no masking, the passwords still in their messages and snippets."""
    importlib.import_module(
        "automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner"
    )
    model = AshAggregatedResults()
    model.sarif.merge_sarif_report(
        scanner_shaped_report("bandit", bandit_sarif()["runs"][0]["results"])
    )
    return model.model_dump_json(by_alias=True)


def _upload_body(reporter, model) -> str:
    captured = {}

    def _put(*args, **kwargs):
        captured.update(kwargs)

    with patch("boto3.Session", MagicMock()):
        with patch.object(S3Reporter, "_put_object_with_retry", _put):
            assert reporter.report(model) is not None
    return captured["Body"]


def test_the_precondition_the_file_holds_the_values_before_it_is_read():
    """The control: the stored file holds every password, so a body without
    them was masked on the way and not simply built from a file that had none."""
    stored = _unmasked_results_file()

    assert SECRETS.found_in(stored) != [], "the fixture file was masked already"
    assert NON_SECRET_LINE in stored


def test_the_upload_body_holds_no_password_a_finding_quotes(reporter):
    """A model read back from the stored file is masked as it is built, and the
    upload is made from it: no password a bandit rule quotes is in the body."""
    model = AshAggregatedResults.model_validate_json(_unmasked_results_file())

    body = _upload_body(reporter, model)

    assert SECRETS.found_in(body) == []
    # The message is still there, with the value masked.
    assert "Possible hardcoded password: " in body


def test_the_upload_body_still_carries_the_source_line_of_a_finding_with_no_secret(
    reporter,
):
    """The control: the masking leaves a snippet that is not at a secret
    finding's place alone, so the upload still holds the findings it is
    documented to hold."""
    model = AshAggregatedResults.model_validate_json(_unmasked_results_file())

    body = _upload_body(reporter, model)

    assert NON_SECRET_LINE in body
