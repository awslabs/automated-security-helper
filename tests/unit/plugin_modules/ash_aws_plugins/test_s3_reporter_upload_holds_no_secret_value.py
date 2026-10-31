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

The stored file is built the way a scan builds one: the canned bandit report and
a real detect-secrets report, merged and not masked
(``results_without_masking``). The detect-secrets report is part of the setup,
not an extra. The model masks a source line by value, where a secret finding
quoted the value in its message, and by place, where a secret finding reports
the line. The access key id of the fixture is in no message, so only its place
covers it: detect-secrets reports the line, and the bandit finding on the next
line, whose context region shows the key, is masked because of that. A bandit
report merged alone has no secret finding at that line, so the model has nothing
to anchor the masking on and leaves the line as the scanner wrote it; a file
built that way would fail here for a reason that has nothing to do with the
upload.

No test here calls AWS: the upload is a stand-in for ``put_object``.
"""

import importlib
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
from tests.utils.secret_bearing_scan import (
    SECRETS,
    results_without_masking,
    sarif_results,
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


def _unmasked_results_file(tmp_path) -> str:
    """A results file as an older producer wrote it: the findings of bandit and
    of detect-secrets merged with no masking, the values still in their messages
    and snippets."""
    importlib.import_module(
        "automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner"
    )
    model = results_without_masking(tmp_path / "src", tmp_path / "scanner-output")
    return model.model_dump_json(by_alias=True)


def _upload_body(reporter, model) -> str:
    captured = {}

    def _put(*args, **kwargs):
        captured.update(kwargs)

    with patch("boto3.Session", MagicMock()):
        with patch.object(S3Reporter, "_put_object_with_retry", _put):
            assert reporter.report(model) is not None
    return captured["Body"]


def test_the_precondition_the_file_holds_the_values_before_it_is_read(tmp_path):
    """The control: the stored file holds every value, so a body without them
    was masked on the way and not simply built from a file that had none."""
    stored = _unmasked_results_file(tmp_path)

    assert SECRETS.found_in(stored) == SECRETS.names(), (
        "the fixture file was masked already, or lost a value"
    )
    assert NON_SECRET_LINE in stored


def test_the_precondition_a_secret_finding_reports_the_access_key_line(tmp_path):
    """The control for the access key id: no message holds it, so it is masked
    only at the place a secret finding reports. The stored file holds that
    finding, the one detect-secrets makes on line 3 of settings.py."""
    stored = json.loads(_unmasked_results_file(tmp_path))

    reported = set()
    for result in sarif_results(stored["sarif"]):
        if (result.get("properties") or {}).get("scanner_name") != "detect-secrets":
            continue
        physical = result["locations"][0]["physicalLocation"]
        reported.add(
            (
                physical["artifactLocation"]["uri"].rsplit("/", 1)[-1],
                physical["region"]["startLine"],
            )
        )

    assert ("settings.py", 3) in reported


def test_the_upload_body_holds_no_password_a_finding_quotes(reporter, tmp_path):
    """A model read back from the stored file is masked as it is built, and the
    upload is made from it: no value a secret finding quotes or reports is in the
    body, the access key id at the place detect-secrets reports it included."""
    model = AshAggregatedResults.model_validate_json(_unmasked_results_file(tmp_path))

    body = _upload_body(reporter, model)

    assert SECRETS.found_in(body) == []
    # The message is still there, with the value masked.
    assert "Possible hardcoded password: " in body


def test_the_upload_body_still_carries_the_source_line_of_a_finding_with_no_secret(
    reporter, tmp_path
):
    """The control: the masking leaves a snippet that is not at a secret
    finding's place alone, so the upload still holds the findings it is
    documented to hold."""
    model = AshAggregatedResults.model_validate_json(_unmasked_results_file(tmp_path))

    body = _upload_body(reporter, model)

    assert NON_SECRET_LINE in body
