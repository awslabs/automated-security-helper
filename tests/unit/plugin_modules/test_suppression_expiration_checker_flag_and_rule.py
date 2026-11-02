# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The expiry checker under ``--ignore-suppressions`` and its rule-id spelling.

Before the fix, the checker warned about expiring global ignore paths under the
flag although the flag lifts every global ignore path for the run (a scanner's
own option list is not lifted and is still checked, in
tests/unit/utils/test_ignore_path_expiration.py), and the 30-day
suppression warning printed Rule 'None' where the expired-entries warning
printed ``*`` for the same entry.
"""

from __future__ import annotations

from datetime import date, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import (
    AshSuppression,
    IgnorePathWithReason,
)
from automated_security_helper.plugin_modules.ash_builtin.event_handlers import (
    suppression_expiration_checker,
)

pytestmark = pytest.mark.unit

_LOGGER = (
    "automated_security_helper.plugin_modules.ash_builtin.event_handlers."
    "suppression_expiration_checker.ASH_LOGGER"
)


def _in_days(days: int) -> str:
    return (date.today() + timedelta(days=days)).strftime("%Y-%m-%d")


def _context(ignore_suppressions: bool):
    config = AshConfig(project_name="expiry")
    config.global_settings.ignore_paths = [
        IgnorePathWithReason(
            path="vendor/", reason="third party", expiration=_in_days(5)
        )
    ]
    config.global_settings.suppressions = [
        AshSuppression(path="src/app.py", reason="accepted", expiration=_in_days(5))
    ]
    return SimpleNamespace(config=config, ignore_suppressions=ignore_suppressions)


def test_nothing_is_warned_about_under_ignore_suppressions():
    """Red before the fix: the expiring global ignore path was warned about
    although the flag lifts every global ignore path for the run."""
    with patch(_LOGGER) as logger:
        suppression_expiration_checker.handle_suppression_expiration_check(
            plugin_context=_context(ignore_suppressions=True)
        )

    assert logger.warning.call_args_list == []


def test_the_expiring_entries_are_warned_about_when_they_apply():
    """Control: without the flag both the ignore path and the suppression warn."""
    with patch(_LOGGER) as logger:
        suppression_expiration_checker.handle_suppression_expiration_check(
            plugin_context=_context(ignore_suppressions=False)
        )

    warnings = " ".join(str(c.args[0]) for c in logger.warning.call_args_list)
    assert "ignore paths will expire" in warnings
    assert "suppressions will expire" in warnings


def test_a_suppression_without_a_rule_is_shown_as_every_rule():
    """Red before the fix: the 30-day warning printed Rule 'None'."""
    with patch(_LOGGER) as logger:
        suppression_expiration_checker.handle_suppression_expiration_check(
            plugin_context=_context(ignore_suppressions=False)
        )

    warnings = " ".join(str(c.args[0]) for c in logger.warning.call_args_list)
    assert "Rule '*' for 'src/app.py'" in warnings
    assert "Rule 'None'" not in warnings
