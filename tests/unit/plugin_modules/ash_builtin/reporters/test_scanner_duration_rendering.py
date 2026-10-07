# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: the scanner table shows each scanner's real duration.

The text and html reporters render a Duration column with
``format_duration(result.get("duration", 0))`` over the rows from
``ReportContentEmitter.get_scanner_results()``. Those rows had no ``duration``
key, so the default of 0 applied and every scanner read ``<1ms`` however long it
ran. ``ScannerMetrics.duration`` already held the real value; the row dict just
did not carry it.

The markdown reporter's legend documented a "Duration (Time)" column that its
table has never had. The table's ten-column shape is parsed positionally, so the
legend entry is removed rather than a column added.
"""

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)

BANDIT_SECONDS = 90.0
BANDIT_RENDERED = "1m 30s"
SEMGREP_SECONDS = 2.5
SEMGREP_RENDERED = "2.5s"


@pytest.fixture
def model() -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.scanner_results["bandit"] = ScannerTargetStatusInfo(duration=BANDIT_SECONDS)
    model.scanner_results["semgrep"] = ScannerTargetStatusInfo(duration=SEMGREP_SECONDS)
    return model


@pytest.fixture
def context(tmp_path) -> PluginContext:
    return PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        config=get_default_config(),
    )


def _row(lines, scanner):
    matching = [line for line in lines if scanner in line]
    assert matching, f"no table row for {scanner}"
    return matching[0]


def test_emitter_rows_carry_the_duration(model):
    rows = {
        r["scanner_name"]: r for r in ReportContentEmitter(model).get_scanner_results()
    }
    assert rows["bandit"]["duration"] == BANDIT_SECONDS
    assert rows["semgrep"]["duration"] == SEMGREP_SECONDS


def test_text_report_renders_each_scanners_duration(model, context):
    lines = TextReporter(context=context).report(model).splitlines()
    bandit = _row([line for line in lines if line.startswith("bandit")], "bandit")
    semgrep = _row([line for line in lines if line.startswith("semgrep")], "semgrep")
    assert BANDIT_RENDERED in bandit
    assert SEMGREP_RENDERED in semgrep
    assert "<1ms" not in bandit and "<1ms" not in semgrep


def test_html_report_renders_each_scanners_duration(model, context):
    html = HtmlReporter(context=context).report(model)
    assert f"<td>{BANDIT_RENDERED}</td>" in html
    assert f"<td>{SEMGREP_RENDERED}</td>" in html
    assert "<td>&lt;1ms</td>" not in html and "<td><1ms</td>" not in html


def test_markdown_legend_documents_only_columns_the_table_has(model, context):
    markdown = MarkdownReporter(context=context).report(model)
    header = next(
        line for line in markdown.splitlines() if line.startswith("| Scanner |")
    )
    columns = [c.strip() for c in header.strip("|").split("|")]
    assert "Duration" not in columns
    assert "Duration" not in markdown, (
        "the markdown legend describes a Duration column the table does not render"
    )
