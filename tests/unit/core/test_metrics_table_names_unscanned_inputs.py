# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The table printed at the end of ``ash scan`` names each input a scanner skipped.

ash.summary.md and ash.summary.txt list inputs not scanned (an offline
npm-audit's lockfiles), and their tests read those files. The console table is
what someone watching the terminal reads, and it is printed by
``display_metrics_table``, which calls ``print_inputs_not_scanned`` after the
table. Nothing ran that call, so removing it, or the function's import, left every
test green. This test goes through ``display_metrics_table`` itself, with a
recording console and the table stubbed, so only the lines after the table are
under test.
"""

from __future__ import annotations

import pytest
from rich.console import Console
from rich.table import Table

from automated_security_helper.core import metrics_table
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


def _render(model: AshAggregatedResults) -> str:
    made = []

    def recording_console(**kwargs):
        kwargs.pop("file", None)
        console = Console(record=True, width=200, **kwargs)
        made.append(console)
        return console

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(metrics_table, "ash_console", recording_console)
        patch.setattr(
            metrics_table,
            "generate_metrics_table_from_unified_data",
            lambda **kwargs: Table(),
        )
        metrics_table.display_metrics_table(model, use_color=False)
    return "".join(console.export_text() for console in made)


def _model(entries) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.additional_reports = {
        "npm-audit": {"source": {"inputs_not_scanned": entries}}
    }
    return model


def test_the_console_summary_names_each_unscanned_input():
    text = _render(
        _model(
            [
                {"path": "web/package-lock.json", "reason": "ASH is offline"},
                {"path": "app/pnpm-lock.yaml", "reason": "ASH is offline"},
            ]
        )
    )

    assert "Not scanned: npm-audit did not scan web/package-lock.json" in text, text
    assert "Not scanned: npm-audit did not scan app/pnpm-lock.yaml" in text, text


def test_control_nothing_is_printed_when_every_input_was_scanned():
    text = _render(_model([]))

    assert "Not scanned" not in text, text
