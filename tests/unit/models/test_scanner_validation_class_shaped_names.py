# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A configured scanner name ending in 'Scanner' is tracked, not refused.

``ScannerStateTracker`` refuses a class name passed in place of a scanner's
configured name, because every row the phase records has to carry the
configured name. The heuristic is the suffix 'Scanner', and a valid configured
name may end in it too. ``validate_registered_scanners`` hands the tracker every
registered instance's name with its class, so for a registered scanner the
heuristic is a warning and the name is tracked as given; the class name itself,
and a bare class-shaped name with no class to compare it with, are still refused.
A scanner whose config carries no name is tracked under the lowercased class
name the phase records its rows under, instead of being refused as empty.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from automated_security_helper.models.scanner_validation import (
    ScannerStateTracker,
    ScannerValidationManager,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def manager():
    context = MagicMock()
    context.config = MagicMock()
    return ScannerValidationManager(context)


def _instance(name, class_name):
    instance = MagicMock()
    instance.config.name = name
    instance.__class__.__name__ = class_name
    return instance


def test_a_registered_scanners_configured_name_may_end_in_scanner(manager):
    """Red before the fix: validate_registered_scanners raised ValueError and the
    scan phase ended for a valid configuration."""
    checkpoint = manager.validate_registered_scanners(
        [_instance("MyScanner", "MyScannerPlugin")]
    )

    assert checkpoint.expected_scanners == ["MyScanner"]
    assert manager.scanner_states["MyScanner"].registration_status == "registered"


def test_the_tracked_name_is_a_scanner_in_the_summaries(manager):
    manager.validate_registered_scanners([_instance("MyScanner", "MyScannerPlugin")])
    manager.update_scanner_state(
        "MyScanner", enablement_status="enabled", execution_completed=True
    )

    summary = manager._get_scanner_state_summary()

    assert "MyScanner" in summary["completed"]


def test_the_class_name_itself_is_still_refused():
    tracker = ScannerStateTracker()

    with pytest.raises(ValueError, match="looks like a class name"):
        tracker.update_scanner_state(
            "BanditScanner", plugin_class=type("BanditScanner", (), {})
        )


def test_a_bare_class_shaped_name_is_still_refused():
    tracker = ScannerStateTracker()

    with pytest.raises(ValueError, match="looks like a class name"):
        tracker.update_scanner_state("BanditScanner")


def test_a_legacy_class_name_entry_is_still_left_out_of_the_summary(manager):
    from automated_security_helper.models.scanner_validation import (
        ScannerValidationState,
    )

    manager.scanner_states["BanditScanner"] = ScannerValidationState(
        name="BanditScanner", registration_status="registered"
    )

    names = [
        n for names in manager._get_scanner_state_summary().values() for n in names
    ]
    assert "BanditScanner" not in names


def test_a_scanner_with_no_configured_name_is_tracked_under_its_class_name(manager):
    """Red before the fix: config.name of None was refused as an empty name."""
    checkpoint = manager.validate_registered_scanners(
        [_instance(None, "BanditScanner")]
    )

    assert checkpoint.expected_scanners == ["banditscanner"]
    assert "banditscanner" in manager.scanner_states
