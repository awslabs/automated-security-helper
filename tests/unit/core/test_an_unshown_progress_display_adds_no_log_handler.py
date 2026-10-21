# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A progress display that will never be shown puts no handler on the logger.

The display's panel exists to be drawn. Built with ``show_progress=False`` --
as every scan the MCP server runs builds it, and as ``ash merge`` does -- it
is never drawn, so a log handler feeding it shows nobody anything. On the
logger it is worse than useless: the server's workspace scans build one per
project on a plain pool thread, where it joins the logger without a run's
scope, takes every session's records into the invisible panel, and counts as
a home for them, so the last resort never shows what nothing else will.
"""

import logging
import threading

from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.utils import log as ash_log
from automated_security_helper.utils.log import ASH_LOGGER


class _Recording(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.records = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())


def _without(display: LiveProgressDisplay) -> None:
    if display.log_handler in ASH_LOGGER.handlers:
        ASH_LOGGER.removeHandler(display.log_handler)


def test_an_unshown_display_leaves_the_loggers_handlers_alone():
    before = list(ASH_LOGGER.handlers)
    display = LiveProgressDisplay(show_progress=False)
    try:
        assert ASH_LOGGER.handlers == before, (
            "a display that will never be shown put a handler on the logger"
        )
    finally:
        _without(display)


def test_an_unshown_display_does_not_swallow_a_line_no_scan_owns(monkeypatch):
    """While the server hosts a scan, a line of no run's goes to the last
    resort. A workspace scan builds one display per project on a pool thread
    with no scope; its handler must not count as that line's home."""
    last_resort = _Recording()
    monkeypatch.setattr(ash_log, "_LAST_RESORT", last_resort)
    # Only this test's handlers, so the last resort's verdict is about the
    # display built here and not about what an earlier test left on the
    # process-wide logger.
    held_back = list(ASH_LOGGER.handlers)
    for handler in held_back:
        ASH_LOGGER.removeHandler(handler)
    monkeypatch.setattr(ASH_LOGGER, "propagate", False)
    scope, token = ash_log.open_run_log_scope()
    displays = []

    def a_pool_worker_builds_the_projects_display() -> None:
        # A plain pool thread: no run's context, as workspace project workers
        # run (workspace/execution.py).
        displays.append(LiveProgressDisplay(show_progress=False))

    try:
        worker = threading.Thread(target=a_pool_worker_builds_the_projects_display)
        worker.start()
        worker.join(30)
        if not displays:
            raise RuntimeError("control: the pool worker built no display")

        def a_line_no_scan_owns() -> None:
            ASH_LOGGER.warning("an unshown-display marker no scan owns")

        outside = threading.Thread(target=a_line_no_scan_owns)
        outside.start()
        outside.join(30)
    finally:
        for display in displays:
            _without(display)
        ash_log.end_run_log_scope(scope, token)
        for handler in held_back:
            if handler not in ASH_LOGGER.handlers:
                ASH_LOGGER.addHandler(handler)

    assert any("unshown-display marker" in text for text in last_resort.records), (
        "the line no scan owns never reached the last resort"
    )


def test_a_shown_display_still_feeds_its_panel_from_the_logger():
    """The handler is the panel's only feed, so a display that will be shown
    keeps it; stop() takes it off."""
    display = LiveProgressDisplay(show_progress=True)
    try:
        assert display.log_handler in ASH_LOGGER.handlers, (
            "the shown display's panel has no feed"
        )
    finally:
        _without(display)
