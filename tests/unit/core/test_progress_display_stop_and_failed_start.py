# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Edges of ``LiveProgressDisplay`` start, stop and update_task.

* A ``Live`` whose ``__enter__`` raised may be half started; start() kept it in
  ``self.live`` and stop(), which acts only on a shown display, never exited it.
* stop() took the log handler off only for a shown display, so the console sink
  a failed start() installed in the panel's place was never removed by it.
* Once a shown display stopped, the logger had no console handler in progress
  mode, so the lines logged after it ended reached no terminal.
* update_task stopped a task's timer at a literal 100 and not at the task's own
  total.
"""

from __future__ import annotations

import io
import logging
import sys

import pytest
from rich.console import Console

import automated_security_helper.core.progress as progress_module
from automated_security_helper.core.enums import ExecutionPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit


@pytest.fixture
def restore_handlers():
    original = list(ASH_LOGGER.handlers)
    yield
    ASH_LOGGER.handlers = original


class _HalfStartedLive:
    """A Live that takes the console and then fails to finish starting."""

    instances: list["_HalfStartedLive"] = []

    def __init__(self, *args, **kwargs):
        self.stopped = 0
        _HalfStartedLive.instances.append(self)

    def __enter__(self):
        raise RuntimeError("the terminal went away after the cursor was hidden")

    def __exit__(self, *exc_info):
        self.stop()

    def stop(self):
        self.stopped += 1


class _WorkingLive:
    def __init__(self, *args, **kwargs):
        self.exited = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.exited += 1

    def stop(self):
        self.exited += 1


def _display() -> LiveProgressDisplay:
    display = LiveProgressDisplay(show_progress=True)
    display.console = Console(file=io.StringIO(), width=120)
    return display


def test_a_live_that_failed_to_enter_is_stopped_and_forgotten(
    monkeypatch, restore_handlers
):
    _HalfStartedLive.instances = []
    monkeypatch.setattr(progress_module, "Live", _HalfStartedLive)
    display = _display()

    display.start()

    assert len(_HalfStartedLive.instances) == 1
    # Red at the base: the half-started Live stayed in self.live, never stopped.
    assert _HalfStartedLive.instances[0].stopped == 1
    assert display.live is None


def test_stop_after_a_failed_start_removes_the_console_sink(
    monkeypatch, restore_handlers
):
    _HalfStartedLive.instances = []
    monkeypatch.setattr(progress_module, "Live", _HalfStartedLive)
    display = _display()
    display.start()
    sink = display.log_handler
    assert sink in ASH_LOGGER.handlers

    display.stop()

    # Red at the base: stop() returned early because show_progress was False.
    assert sink not in ASH_LOGGER.handlers


def test_lines_logged_after_a_shown_display_stops_still_reach_a_console(
    monkeypatch, restore_handlers, capsys
):
    monkeypatch.setattr(progress_module, "Live", _WorkingLive)
    display = _display()
    display.start()
    panel_handler = display.log_handler
    before = list(ASH_LOGGER.handlers)

    display.stop()

    assert panel_handler not in ASH_LOGGER.handlers
    added = [h for h in ASH_LOGGER.handlers if h not in before]
    # Red at the base: nothing took the panel handler's place.
    assert len(added) == 1
    sink = added[0]
    assert isinstance(sink, logging.StreamHandler)
    assert sink.stream is sys.stderr
    assert sink.level == panel_handler.level
    record = logging.LogRecord(
        "ash",
        logging.WARNING,
        __file__,
        1,
        "a line after the display ended",
        None,
        None,
    )
    sink.handle(record)
    assert "a line after the display ended" in capsys.readouterr().err


def test_update_task_stops_the_timer_at_the_tasks_own_total(restore_handlers):
    display = _display()
    task_id = display.add_task(ExecutionPhase.SCAN, "bandit", total=10)

    display.update_task(ExecutionPhase.SCAN, task_id, completed=4)
    assert display.progress.tasks[0].stop_time is None

    display.update_task(ExecutionPhase.SCAN, task_id, completed=10)

    # Red at the base: only a literal 100 stopped the timer.
    assert display.progress.tasks[0].stop_time is not None
