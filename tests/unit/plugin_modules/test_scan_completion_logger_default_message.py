# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``handle_scan_completion_logging`` builds its default message only when the
emitter gave none.

The default was built as the default argument of ``kwargs.get``, so the join
over ``remaining_scanners`` ran on every event, and a None or non-list payload
raised TypeError beside an explicit message the join never reached.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.plugin_modules.ash_builtin.event_handlers import (
    scan_completion_logger,
)

pytestmark = pytest.mark.unit

_LOGGER = (
    "automated_security_helper.plugin_modules.ash_builtin.event_handlers."
    "scan_completion_logger.ASH_LOGGER"
)


def test_an_explicit_message_is_logged_whatever_remaining_scanners_holds():
    """Red before the fix: ','.join(None) raised TypeError before the message
    the emitter supplied was read."""
    with patch(_LOGGER) as logger:
        assert scan_completion_logger.handle_scan_completion_logging(
            remaining_count=2, remaining_scanners=None, message="two remain"
        )

    logger.info.assert_called_once_with("two remain")


def test_the_default_message_names_the_remaining_scanners():
    """Control: with no message the default is built as before."""
    with patch(_LOGGER) as logger:
        scan_completion_logger.handle_scan_completion_logging(
            remaining_count=2, remaining_scanners=["bandit", "semgrep"]
        )

    logger.info.assert_called_once_with("Remaining scanners (2): bandit,semgrep")


def test_nothing_remaining_logs_the_completion_line():
    """Control: the all-done line is unchanged."""
    with patch(_LOGGER) as logger:
        scan_completion_logger.handle_scan_completion_logging(
            remaining_count=0, remaining_scanners=[]
        )

    logger.info.assert_called_once_with("All scanners completed!")


def test_a_failed_last_turn_is_named_in_the_completion_line():
    """Red before the fix: SCAN_COMPLETE is announced for a recorded turn that
    ended in a failure container too, and the last such event logged "All
    scanners completed!" as if every scanner had succeeded."""
    with patch(_LOGGER) as logger:
        scan_completion_logger.handle_scan_completion_logging(
            scanner="bandit",
            remaining_count=0,
            remaining_scanners=[],
            succeeded=False,
        )

    logger.info.assert_called_once_with(
        "All scanners completed; the last, bandit, ended with a failure."
    )


def test_a_succeeded_or_unstated_last_turn_keeps_the_all_done_line():
    """Control: an emitter that says the turn succeeded, or says nothing, gets
    the unchanged line; a failure with scanners still remaining logs the
    remaining-scanners message, not the all-done line."""
    with patch(_LOGGER) as logger:
        scan_completion_logger.handle_scan_completion_logging(
            scanner="bandit", remaining_count=0, remaining_scanners=[], succeeded=True
        )
    logger.info.assert_called_once_with("All scanners completed!")

    with patch(_LOGGER) as logger:
        scan_completion_logger.handle_scan_completion_logging(
            scanner="bandit",
            remaining_count=1,
            remaining_scanners=["semgrep"],
            succeeded=False,
        )
    logger.info.assert_called_once_with("Remaining scanners (1): semgrep")
