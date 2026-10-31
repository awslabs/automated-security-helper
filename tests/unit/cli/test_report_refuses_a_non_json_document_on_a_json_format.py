# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report`` on a JSON format fails when the reporter returns no JSON document.

A reporter whose report is a JSON document may return its error text in its
place when it could not produce one (the cloudwatch-logs reporter did, after a
publish that failed its retries, before it returned None). The command took any
text as the report, so off a terminal the error text went to stdout as the
document and the exit was 0, and on a terminal the JSON re-indenting failed and
a decode error stood in for the reporter's reason. The text is the reason: it
is printed as the error, to stderr, and the exit says the report was not
produced. Content that is long, on more than one line, or shaped like a JSON
document is a report, which can hold detected secrets, and is described by its
decode error and its length, never quoted.
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


@pytest.mark.parametrize("returned", ["", " \n\t "], ids=["empty", "white-space"])
def test_a_reporter_that_returns_no_text_is_named_in_the_error(results_dir, returned):
    """Empty or blank output has no reason to quote; the error ended in a colon
    with nothing after it."""
    with patch(SARIF_REPORT, return_value=returned):
        result = _report(results_dir)

    assert result.exit_code == 1, result.output
    assert result.stdout == ""
    assert (
        "did not produce a JSON document: the reporter returned no text"
        in result.stderr
    )


PLANTED_SNIPPET = "finding-snippet-planted-for-this-test"


def test_a_multi_line_non_json_report_is_described_not_quoted(results_dir):
    """A report that is not JSON (here, YAML) holds finding snippets, which can
    hold detected secrets; the error names the decode error and the length and
    carries none of the content to stderr, the CI log."""
    document = f"version: 2.1.0\nruns:\n  - snippet: {PLANTED_SNIPPET}\n"
    with patch(SARIF_REPORT, return_value=document):
        result = _report(results_dir)

    assert result.exit_code == 1, result.output
    assert result.stdout == ""
    assert "did not produce a JSON document" in result.stderr
    assert PLANTED_SNIPPET not in result.stderr
    assert "line 1 column 1" in result.stderr
    assert f"{len(document)} characters" in result.stderr


def test_a_long_one_line_non_json_report_is_described_not_quoted(results_dir):
    document = "not json " * 40 + PLANTED_SNIPPET
    with patch(SARIF_REPORT, return_value=document):
        result = _report(results_dir)

    assert result.exit_code == 1, result.output
    assert PLANTED_SNIPPET not in result.stderr
    assert f"{len(document)} characters" in result.stderr


def test_a_short_one_line_malformed_json_document_is_described_not_quoted(
    results_dir,
):
    """Minified reporter output is one line and can be short; a reporter's error
    text never starts a JSON document, so content that does is a report whose
    findings must not reach stderr however short it is."""
    document = f'{{"runs":[{{"snippet":"{PLANTED_SNIPPET}"'
    assert len(document) <= 200
    with patch(SARIF_REPORT, return_value=document):
        result = _report(results_dir)

    assert result.exit_code == 1, result.output
    assert PLANTED_SNIPPET not in result.stderr
    assert f"{len(document)} characters" in result.stderr


def test_a_json_document_is_still_written_as_the_report(results_dir):
    document = json.dumps({"version": "2.1.0", "runs": []})
    with patch(SARIF_REPORT, return_value=document):
        result = _report(results_dir)

    assert result.exit_code == 0, result.output
    assert result.stdout == document
