# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The results table and the coverage notice show a scanner's name as text.

Why this exists
---------------
A scanner's name comes from the results the table is built from, and ``ash
report`` builds it from a results file on disk, whose keys and status strings are
that file's data. Were the table's name cell, the status cell for a status it does
not know, or the "Incomplete coverage" line Rich markup, a "[/x]" in
a name would raise MarkupError, and a "[bold]x[/bold]" be taken as a style and
lost. Each is text, or escaped once.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from automated_security_helper.core import metrics_table
from automated_security_helper.core.unified_metrics import ScannerMetrics
from automated_security_helper.models.asharp_model import AshAggregatedResults

#: A closing tag with no opener, and a whole style tag around a word.
NAMES = ["a[/x]", "[bold]x[/bold]"]


def _console() -> Console:
    return Console(file=io.StringIO(), width=300, color_system=None)


def _written(console: Console) -> str:
    return console.file.getvalue()


@pytest.fixture
def metrics(monkeypatch):
    rows = [
        ScannerMetrics(scanner_name=name, status=name, threshold="MEDIUM")
        for name in NAMES
    ]
    monkeypatch.setattr(metrics_table, "get_unified_scanner_metrics", lambda _: rows)
    return rows


def test_the_table_shows_each_name_and_status_as_text(metrics):
    console = _console()

    table = metrics_table.generate_metrics_table_from_unified_data(
        AshAggregatedResults(), source_dir="src", output_dir="out", console=console
    )
    console.print(table)

    written = _written(console)
    for name in NAMES:
        # Once as the name, once as the status this table does not know.
        assert written.count(name) == 2, written
    assert "\\[" not in written, written


def test_the_coverage_notice_shows_each_name_as_text(monkeypatch):
    monkeypatch.setattr(
        metrics_table,
        "coverage_shortfalls",
        lambda _: [(name, 2, 1) for name in NAMES],
    )
    console = _console()

    metrics_table.print_coverage_shortfalls(AshAggregatedResults(), console)

    written = _written(console)
    for name in NAMES:
        assert written.count(f"Incomplete coverage: {name} evaluated 1 of 2") == 1, (
            written
        )
    assert "\\[" not in written, written
