# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The live progress display as it is left on screen when a scan finishes.

Each phase adds one summary row when it ends (``EnginePhase.add_summary``), and the last
frame the ``Live`` display draws is what stays in the operator's scrollback. That frame is
rendered here once, into a console of fixed size, with the three rows the convert, scan and
report phases add plus a failed scan row.

Made deterministic by pinning two things and nothing else:

- the progress clock. ``Progress`` takes ``get_time`` as a public constructor argument and
  hands it to each task, and every time-dependent column reads it: the spinner frame, the
  elapsed and the remaining time. The summary rows are added with ``completed=100`` but are
  never marked finished, so the spinner keeps animating and would otherwise draw whichever
  frame the wall clock landed on. Assigning the attribute before any row is added gives
  every task the pinned clock.
- the console. ``LiveProgressDisplay`` builds one that reads the terminal; the layout is
  rendered into a recording console of fixed width and height instead.

The ``Live`` context itself is not entered. It only decides when frames are drawn, and
entering it would start a refresh thread and redirect stdout.

The display also attaches a handler to ``ASH_LOGGER`` on construction; it is removed again
so later tests in the same worker do not log into a panel nobody renders.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.utils.log import ASH_LOGGER
from tests.snapshot.console.console_inputs import NARROW, recording_console, rendered

PINNED_PROGRESS_TIME = 5_000.0


@pytest.fixture
def display():
    display = LiveProgressDisplay(show_progress=True, color_system=None)
    display.progress.get_time = lambda: PINNED_PROGRESS_TIME
    try:
        yield display
    finally:
        ASH_LOGGER.removeHandler(display.log_handler)


def test_final_progress_frame(display, text_snapshot):
    display.add_summary_row("convert", "Complete", "Converted 3 paths")
    display.add_summary_row("scan", "Complete", "Executed 9 scanners")
    display.add_summary_row("scan", "Failed", "Error: grype exited 2")
    display.add_summary_row("report", "Complete", "Generated 11 reports")
    console = recording_console(NARROW, height=24)

    console.print(display.layout)

    assert rendered(console) == text_snapshot("txt")
