# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report`` knows from the reporter's configuration whether its report is JSON.

The unused-suppressions reporter writes JSON by default and markdown under
``output_format: markdown``. The command classed its report by the first
character of the content: markdown that began with ``[`` (a link reference) was
refused as a JSON document that did not parse, and the error text a reporter
returned in JSON mode, which does not begin with ``{``, was written as the report
with exit 0. Now the configuration says which it is: a JSON report is checked as
one, a markdown report is written as it is. A JSON report is parsed once, and the
terminal's indenting reuses the document.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import report as report_module
from automated_security_helper.cli.main import app
from automated_security_helper.cli.report import _report_is_json
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("own_environment")]

REPORTERS = "automated_security_helper.plugin_modules.ash_builtin.reporters."
UNUSED_REPORT = REPORTERS + "UnusedSuppressionsReporter.report"
SARIF_REPORT = REPORTERS + "SarifReporter.report"
MARKDOWN_MODE = [
    "--config-overrides",
    "reporters.unused-suppressions.options.output_format=markdown",
]
REASON = "the results could not be read: the endpoint answered 403"
PLANTED_SNIPPET = "finding-snippet-planted-for-this-test"


class _Terminal(io.StringIO):
    def isatty(self):
        return True


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


def _report(output_dir: Path, report_format: str, *extra: str):
    return CliRunner().invoke(
        app,
        ["report", "--format", report_format, "--output-dir", str(output_dir), *extra],
    )


def _reporter(output_format: str) -> SimpleNamespace:
    options = SimpleNamespace(output_format=output_format)
    return SimpleNamespace(config=SimpleNamespace(options=options))


@pytest.mark.parametrize("mode", ["json", "both"])
def test_unused_suppressions_is_json_unless_its_configuration_says_markdown(mode):
    assert _report_is_json("unused-suppressions", _reporter(mode)) is True
    assert _report_is_json("unused-suppressions", _reporter("markdown")) is False


def test_a_format_that_writes_no_text_by_design_is_json_whatever_its_options():
    assert _report_is_json("sarif", _reporter("markdown")) is True
    assert _report_is_json("SARIF", SimpleNamespace()) is True
    assert _report_is_json("markdown", _reporter("json")) is False


@pytest.mark.parametrize(
    "content",
    [
        "[docs]: https://example.invalid/docs\n\n# Unused suppressions\n",
        "# Unused suppressions\n\nNothing is unused.\n",
    ],
    ids=["begins-with-a-link-reference", "begins-with-a-heading"],
)
def test_a_markdown_report_is_written_as_it_is(results_dir, content):
    with patch(UNUSED_REPORT, return_value=content):
        result = _report(results_dir, "unused-suppressions", *MARKDOWN_MODE)

    assert result.exit_code == 0, result.output
    assert result.stdout == content
    assert "did not produce a JSON document" not in result.stderr


def test_error_text_in_json_mode_is_the_error_not_the_report(results_dir):
    with patch(UNUSED_REPORT, return_value=REASON):
        result = _report(results_dir, "unused-suppressions")

    assert result.exit_code == 1, result.output
    assert result.stdout == ""
    assert "did not produce a JSON document" in result.stderr
    assert REASON in result.stderr


def test_a_truncated_json_document_is_described_not_quoted(results_dir):
    document = f'{{"unused": [{{"snippet": "{PLANTED_SNIPPET}"'
    with patch(UNUSED_REPORT, return_value=document):
        result = _report(results_dir, "unused-suppressions")

    assert result.exit_code == 1, result.output
    assert result.stdout == ""
    assert PLANTED_SNIPPET not in result.stderr
    assert f"{len(document)} characters" in result.stderr


def test_a_json_document_in_json_mode_is_written_as_the_report(results_dir):
    document = json.dumps({"unused_suppressions": []})
    with patch(UNUSED_REPORT, return_value=document):
        result = _report(results_dir, "unused-suppressions")

    assert result.exit_code == 0, result.output
    assert result.stdout == document


def test_a_json_report_is_parsed_once_for_a_terminal(results_dir, monkeypatch):
    """The check parsed the report, and the terminal's indenting parsed it again;
    on a report of tens of megabytes the second parse is wasted work."""
    document = json.dumps({"version": "2.1.0", "runs": []})
    terminal = _Terminal()
    original = report_module._write_report

    def on_a_terminal(content, report_format, **kwargs):
        original(content, report_format, stream=terminal, **kwargs)

    monkeypatch.setattr(report_module, "_write_report", on_a_terminal)
    # The command hands the document over only when its stdout is a terminal;
    # the runner's is not, and the writer above stands in for the real stream.
    monkeypatch.setattr(report_module, "_stdout_is_terminal", lambda: True)
    monkeypatch.delenv("NO_COLOR", raising=False)
    parses: list = []
    real_loads = json.loads

    def counting(text, *args, **kwargs):
        if text == document:
            parses.append(text)
        return real_loads(text, *args, **kwargs)

    monkeypatch.setattr(json, "loads", counting)

    with patch(SARIF_REPORT, return_value=document):
        result = _report(results_dir, "sarif")

    assert result.exit_code == 0, result.output
    assert "runs" in terminal.getvalue(), terminal.getvalue()
    assert len(parses) == 1, parses


@pytest.mark.parametrize(
    ("on_a_terminal", "extra", "handed_over"),
    [(False, [], False), (True, ["--no-color"], False), (True, [], True)],
    ids=["a-pipe", "a-terminal-without-color", "a-terminal-with-color"],
)
def test_the_parsed_document_is_handed_over_only_to_indent_on_a_terminal(
    results_dir, monkeypatch, on_a_terminal, extra, handed_over
):
    """Only the indenting on an interactive terminal reads the parsed document.
    Handed over anywhere else, the tree of a report of tens of megabytes stays
    alive beside the report text for the whole write."""
    seen: list = []

    def recorder(content, report_format, **kwargs):
        seen.append(kwargs["parsed"])

    monkeypatch.setattr(report_module, "_write_report", recorder)
    monkeypatch.setattr(report_module, "_stdout_is_terminal", lambda: on_a_terminal)
    monkeypatch.delenv("NO_COLOR", raising=False)
    document = json.dumps({"version": "2.1.0", "runs": []})

    with patch(SARIF_REPORT, return_value=document):
        result = _report(results_dir, "sarif", *extra)

    assert result.exit_code == 0, result.output
    assert len(seen) == 1, seen
    assert (seen[0] is not report_module._NOT_PARSED) is handed_over, seen
