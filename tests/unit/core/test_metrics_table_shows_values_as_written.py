# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The metrics table shows a results file's values; it does not obey them.

- The threshold column writes a control character as an escape, like every other
  column built from the results file.
- A path with a control character in a "Not scanned" line is shown once, not
  escaped twice, and a newline in it is written as an escape so the line stays one.
- The help text names the SKIPPED row's second meaning and the (u)navailable
  threshold source the narrow table prints.
- NO_COLOR is honored by the summary console: no color is emitted (bold and the
  other non-color styles stay, as Rich reads the convention).
- One notice printer that raises does not stop the later notices.
"""

from __future__ import annotations

import re

import pytest
from rich.console import Console

from automated_security_helper.core import metrics_table
from automated_security_helper.core.metrics_table import (
    METRICS_HELP_TEXT,
    display_metrics_table,
    generate_metrics_table_from_unified_data,
    not_scanned_line,
)
from automated_security_helper.core.unified_metrics import ScannerMetrics
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

ESC = "\x1b"


def _render(table, width=200) -> str:
    console = Console(width=width, record=True, force_terminal=False, color_system=None)
    console.print(table)
    return console.export_text()


class TestTheCells:
    # The narrow table shows the threshold's first four characters, so its
    # control character sits inside them; the wide table shows the whole text.
    @pytest.mark.parametrize(
        "width,threshold",
        [(200, f"HIGH{ESC}[31m"), (80, f"{ESC}HIGH")],
        ids=["wide", "narrow"],
    )
    def test_the_threshold_cell_shows_a_control_character_as_an_escape(
        self, monkeypatch, width, threshold
    ):
        monkeypatch.setattr(
            metrics_table,
            "get_unified_scanner_metrics",
            lambda model: [
                ScannerMetrics(
                    scanner_name="tool",
                    status="PASSED",
                    threshold=threshold,
                    threshold_source=f"config{ESC}[0m",
                )
            ],
        )
        console = Console(width=width, force_terminal=False, color_system=None)

        table = generate_metrics_table_from_unified_data(
            AshAggregatedResults(), console=console
        )
        text = _render(table, width)

        assert ESC not in text, repr(text)
        assert "\\x1b" in text, repr(text)

    def test_a_not_scanned_path_is_shown_once(self):
        line = not_scanned_line("npm-audit", f"a{ESC}b.lock", "offline")

        assert ESC not in line
        assert line.count("\\x1b") == 1, line
        assert "\\\\x1b" not in line, line

    def test_a_not_scanned_path_stays_on_one_line(self):
        """A newline in the path is written as the console's escape, so the path
        cannot start a line of its own; the escape sequence beside it is still
        shown once."""
        line = not_scanned_line("npm-audit", f"web\n## heading{ESC}[31m/a.lock", "x")

        assert "\n" not in line, line
        assert "\\x0a## heading" in line, line
        assert line.count("\\x1b") == 1, line


class TestTheHelpText:
    def test_the_skipped_line_names_both_meanings(self):
        (line,) = [l for l in METRICS_HELP_TEXT.splitlines() if "SKIPPED" in l]

        assert "found nothing it scans" in line, line
        assert "explicitly disabled" not in line, line

    def test_the_source_legend_explains_the_unavailable_source(self):
        (line,) = [l for l in METRICS_HELP_TEXT.splitlines() if "(g)lobal" in l]

        assert "(u)navailable" in line, line


#: An SGR sequence that sets a foreground or background color (16-color,
#: bright, 256-color or truecolor). Rich keeps bold and the other non-color
#: styles under NO_COLOR, so those sequences are not colors.
COLOR_SEQUENCE = re.compile(
    r"\x1b\[(?:[0-9;]*;)?(?:3[0-7]|9[0-7]|10[0-7]|38|48)(?:;[0-9;]*)?m"
)


class TestTheDisplay:
    def test_no_color_is_honored(self, monkeypatch, capsys):
        # The control: with color asked for and NO_COLOR unset, the table is
        # printed in color, so the assertion below is reading a real difference.
        monkeypatch.delenv("NO_COLOR", raising=False)
        display_metrics_table(AshAggregatedResults(), use_color=True)
        colored = capsys.readouterr().out
        assert COLOR_SEQUENCE.search(colored), repr(colored[:300])

        monkeypatch.setenv("NO_COLOR", "1")
        display_metrics_table(AshAggregatedResults(), use_color=True)

        out = capsys.readouterr().out
        assert "ASH Scan Results Summary" in out
        assert not COLOR_SEQUENCE.search(out), repr(out[:300])

    def test_a_notice_printer_that_raises_does_not_stop_the_later_notices(
        self, monkeypatch, capsys
    ):
        printed = []

        def _raises(model, console):
            raise ValueError("a shape this printer cannot read")

        # The warning names the printer by its __name__, as the live one is named.
        _raises.__name__ = "print_coverage_shortfalls"

        def _prints(model, console):
            printed.append("later")
            console.print("later notice")

        monkeypatch.setattr(metrics_table, "print_coverage_shortfalls", _raises)
        monkeypatch.setattr(metrics_table, "print_inputs_not_scanned", _prints)
        monkeypatch.setattr(metrics_table, "print_stale_content_databases", _prints)
        monkeypatch.setattr(metrics_table, "print_converter_refusals", _prints)
        warnings = []
        monkeypatch.setattr(
            metrics_table.ASH_LOGGER,
            "warning",
            lambda message, *args, **kwargs: warnings.append(str(message)),
        )

        display_metrics_table(AshAggregatedResults(), use_color=False)

        assert printed == ["later"] * 3, printed
        assert "later notice" in capsys.readouterr().out
        assert any("print_coverage_shortfalls" in line for line in warnings), warnings

    def test_a_closed_stream_ends_the_notices_with_one_warning(self, monkeypatch):
        """Red at the base: a closed stream raises ValueError, which was read as a
        printer's own failure, so each of the four notices warned in turn."""
        attempted = []

        def _closed(model, console):
            attempted.append("first")
            raise ValueError("I/O operation on closed file.")

        def _later(model, console):
            attempted.append("later")

        monkeypatch.setattr(metrics_table, "print_coverage_shortfalls", _closed)
        monkeypatch.setattr(metrics_table, "print_inputs_not_scanned", _later)
        monkeypatch.setattr(metrics_table, "print_stale_content_databases", _later)
        monkeypatch.setattr(metrics_table, "print_converter_refusals", _later)
        warnings = []
        monkeypatch.setattr(
            metrics_table.ASH_LOGGER,
            "warning",
            lambda message, *args, **kwargs: warnings.append(str(message)),
        )

        display_metrics_table(AshAggregatedResults(), use_color=False)

        assert attempted == ["first"], attempted
        notice_warnings = [line for line in warnings if "notice" in line]
        assert len(notice_warnings) == 1, warnings
        assert notice_warnings[0].startswith("Could not write a notice to the console")
