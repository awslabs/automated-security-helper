# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report`` on a JSON format fails when the reporter returns no JSON document.

A reporter whose report is a JSON document returns its error text in its place
when it could not produce one: the cloudwatch-logs reporter does, after a
publish that failed its retries. The command took any text as the report, so
off a terminal the error text went to stdout as the document and the exit was
0, and on a terminal the JSON re-indenting failed and a decode error stood in
for the reporter's reason. The text is the reason: it is printed as the error,
to stderr, and the exit says the report was not produced.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

SARIF_REPORT = (
    "automated_security_helper.plugin_modules.ash_builtin.reporters."
    "SarifReporter.report"
)
REASON = "publishing failed after retries: the endpoint answered 403"


@pytest.fixture
def results_dir(tmp_path: Path) -> Path:
    output = tmp_path / "out"
    output.mkdir()
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    (output / "ash_aggregated_results.json").write_text(
        model.model_dump_json(by_alias=True), encoding="utf-8"
    )
    return output


def _report(output_dir: Path, *extra: str):
    return CliRunner().invoke(
        app, ["report", "--format", "sarif", "--output-dir", str(output_dir), *extra]
    )


@pytest.mark.parametrize("extra", [[], ["--no-color"]], ids=["default", "no-color"])
def test_error_text_in_place_of_a_json_document_is_the_error_not_the_report(
    results_dir, extra
):
    with patch(SARIF_REPORT, return_value=REASON):
        result = _report(results_dir, *extra)

    assert result.exit_code == 1, result.output
    assert result.stdout == ""
    assert "did not produce a JSON document" in result.stderr
    assert REASON in result.stderr
    assert "'sarif'" in result.stderr


def test_a_json_document_is_still_written_as_the_report(results_dir):
    document = json.dumps({"version": "2.1.0", "runs": []})
    with patch(SARIF_REPORT, return_value=document):
        result = _report(results_dir)

    assert result.exit_code == 0, result.output
    assert result.stdout == document
