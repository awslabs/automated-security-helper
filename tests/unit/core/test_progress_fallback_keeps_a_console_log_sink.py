# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""When the live display cannot start, the log lines still reach a console.

``LiveProgressDisplay.__init__`` attaches a handler that feeds the log panel,
and ``get_logger`` adds no console handler while ``show_progress`` is on. When
``start()`` could not build the ``Live`` display it fell back to "non-progress
mode" by clearing the flag and nothing else, so every later log line went to a
panel that was never rendered, and nowhere else. The fallback now swaps the
panel handler for a console sink at the same level.
"""

from __future__ import annotations

import io
import logging

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


def test_a_failed_live_start_swaps_the_panel_handler_for_a_console_sink(
    monkeypatch, restore_handlers, capsys
):
    def live_cannot_start(*args, **kwargs):
        raise RuntimeError("no terminal")

    monkeypatch.setattr(progress_module, "Live", live_cannot_start)
    display = LiveProgressDisplay(show_progress=True)
    display.console = Console(file=io.StringIO(), width=120)
    panel_handler = display.log_handler
    assert isinstance(panel_handler, LiveDisplayLogHandler)
    assert panel_handler in ASH_LOGGER.handlers

    display.start()

    assert display.show_progress is False
    # Red at the base: the panel handler stayed and no console handler came.
    assert panel_handler not in ASH_LOGGER.handlers
    assert isinstance(display.log_handler, logging.StreamHandler)
    assert display.log_handler in ASH_LOGGER.handlers
    assert display.log_handler.level == panel_handler.level

    display.stop()
    assert display.log_handler not in ASH_LOGGER.handlers
