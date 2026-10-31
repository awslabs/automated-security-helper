# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``notify`` calls every admitted subscriber even when one of them raises.

The callback loop had no guard, so the first raising subscriber ended the
notification and every subscriber after it in the list never saw the event.
Now each callback runs under a guard: a raising one is logged at WARNING by
name, the rest are still called, and the first exception is re-raised once
they have run, so a caller that reads a handler's failure as its own (a
*_PHASE_START notification ends the run with what the handler raised) still
does, and a caller that logs and moves on still logs the same error.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.plugins.plugin_manager import (
    AshPluginLibrary,
    AshPluginManager,
)

pytestmark = pytest.mark.unit

_LOGGER = "automated_security_helper.plugins.plugin_manager.ASH_LOGGER"


def _manager_with(*callbacks):
    manager = AshPluginManager(plugin_library=AshPluginLibrary(event_handlers={}))
    for callback in callbacks:
        manager.subscribe(AshEventType.SCAN_COMPLETE, callback)
    return manager


def test_the_subscribers_after_a_raising_one_are_still_called():
    """Red before the fix: the second callback was never reached."""
    seen: list = []

    def first_raises(**kwargs):
        raise RuntimeError("first subscriber broke")

    def second_records(**kwargs):
        seen.append(kwargs.get("scanner"))
        return "second"

    manager = _manager_with(first_raises, second_records)
    with patch(_LOGGER) as logger:
        with pytest.raises(RuntimeError, match="first subscriber broke"):
            manager.notify(AshEventType.SCAN_COMPLETE, scanner="bandit")

    assert seen == ["bandit"]
    warning_text = " ".join(str(call) for call in logger.warning.call_args_list)
    assert "first_raises" in warning_text
    assert "remaining subscribers are still notified" in warning_text


def test_the_first_exception_is_the_one_re_raised():
    """Two raising subscribers: both are logged, the first one's error is the
    notification's, and the subscriber between them still runs."""
    calls: list = []

    def first(**kwargs):
        raise ValueError("first")

    def middle(**kwargs):
        calls.append("middle")

    def last(**kwargs):
        raise KeyError("last")

    manager = _manager_with(first, middle, last)
    with patch(_LOGGER) as logger:
        with pytest.raises(ValueError, match="first"):
            manager.notify(AshEventType.SCAN_COMPLETE)

    assert calls == ["middle"]
    assert logger.warning.call_count == 2


def test_no_raise_means_no_warning_and_every_result():
    """Control: the happy path returns each subscriber's result and logs no
    warning."""
    manager = _manager_with(lambda **kwargs: "a", lambda **kwargs: "b")
    with patch(_LOGGER) as logger:
        results = manager.notify(AshEventType.SCAN_COMPLETE)

    assert results == ["a", "b"]
    logger.warning.assert_not_called()
