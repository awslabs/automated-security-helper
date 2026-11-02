# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A display that stops and starts again keeps one log destination, not two.

Why these tests exist
---------------------
When a shown display ends, its closing call takes the panel's log handler off and
puts a console sink in its place, so the lines logged after the display (the
completion banner, a later warning) still reach a terminal. It did not keep track
of that sink. A display that started again built a new ``Live`` over the same
panel but never put the panel's handler back, so the new panel showed no log
lines; the sink, holding the standard error it had captured before the new
``Live`` redirected the streams, stayed on the logger and mixed its lines into the
redraws; and the next closing call added a second sink, so every later line was
printed twice.

``start()`` now takes the sink off and puts the panel's handler back, and the
closing call replaces the sink it put before instead of adding another.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

import automated_security_helper.core.progress as progress_module
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.rich_log_handler import LiveDisplayLogHandler

pytestmark = pytest.mark.unit


@pytest.fixture
def restore_handlers():
    original = list(ASH_LOGGER.handlers)
    yield
    ASH_LOGGER.handlers = original


class _WorkingLive:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return None

    def stop(self):
        return None


@pytest.fixture
def display(monkeypatch, restore_handlers) -> LiveProgressDisplay:
    monkeypatch.setattr(progress_module, "Live", _WorkingLive)
    shown = LiveProgressDisplay(show_progress=True)
    shown.console = Console(file=io.StringIO(), width=120)
    return shown


def _sinks() -> list:
    return [
        h for h in ASH_LOGGER.handlers if isinstance(h, progress_module._ConsoleSink)
    ]


def _panel_handlers() -> list:
    return [h for h in ASH_LOGGER.handlers if isinstance(h, LiveDisplayLogHandler)]


def test_starting_again_puts_the_panel_handler_back_and_takes_the_sink_off(display):
    display.start()
    display.stop()
    assert len(_sinks()) == 1
    assert _panel_handlers() == []

    display.start()

    # Red at the base: the sink stayed and the panel had no handler.
    assert _sinks() == []
    assert _panel_handlers() == [display.log_handler]


def test_a_second_shown_stop_leaves_one_sink(display):
    display.start()
    display.stop()
    display.start()
    display.stop()

    # Red at the base: two sinks, so every later line printed twice.
    assert len(_sinks()) == 1
    assert _panel_handlers() == []


def test_a_stop_that_finds_nothing_shown_keeps_the_sink(display):
    """The control: a second closing call with no display showing removes nothing."""
    display.start()
    display.stop()
    sink = _sinks()[0]

    display.stop()

    assert _sinks() == [sink]


def test_a_display_that_never_stopped_is_not_changed_by_starting_again(display):
    """The control: start() on a running display adds no handler."""
    display.start()
    before = list(ASH_LOGGER.handlers)

    display.start()

    assert ASH_LOGGER.handlers == before
