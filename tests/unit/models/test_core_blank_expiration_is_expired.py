# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An entry kept with an empty-string expiration never applies.

A config refuses an expiration that is not a YYYY-MM-DD date; a results file
read under ``TOLERATE_STORED_CONFIG`` keeps one and records it as unreadable.
``is_expired`` read an empty string as "no expiration" (it is false), so such a
suppression or ignore path applied permanently while the load warning said it
did not apply. Only None is no expiration.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.core import (
    UNREADABLE_EXPIRATION_NOTE,
    AshSuppression,
    IgnorePathWithReason,
)
from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

pytestmark = pytest.mark.unit


def _kept(model, data):
    notes: list[str] = []
    entry = model.model_validate(data, context={TOLERATE_STORED_CONFIG: notes})
    assert UNREADABLE_EXPIRATION_NOTE in notes, notes
    return entry


@pytest.mark.parametrize("blank", ["", "   "], ids=["empty", "spaces"])
def test_a_kept_blank_expiration_reads_as_expired(blank):
    entry = _kept(
        IgnorePathWithReason, {"path": "x", "reason": "r", "expiration": blank}
    )

    assert entry.is_expired is True
    # An unreadable date has no day count, and asking for one does not raise:
    # a report that shows the days left reads it as "none".
    assert entry.days_until_expiry is None


@pytest.mark.parametrize("blank", ["", "   "], ids=["empty", "spaces"])
def test_a_kept_blank_expiration_stops_a_suppression_from_matching(blank):
    from automated_security_helper.models.flat_vulnerability import FlatVulnerability

    suppression = _kept(
        AshSuppression,
        {"path": "app.py", "reason": "r", "rule_id": "B101", "expiration": blank},
    )
    finding = FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="HIGH",
        scanner="bandit",
        scanner_type="SAST",
        rule_id="B101",
        file_path="app.py",
    )
    # The control: the same entry with no expiration matches this finding, so
    # the False below comes from the kept blank expiration alone.
    unexpiring = AshSuppression.model_validate(
        {"path": "app.py", "reason": "r", "rule_id": "B101"}
    )

    assert unexpiring.matches(finding) is True
    assert suppression.matches(finding) is False


def test_no_expiration_is_still_not_expired():
    entry = IgnorePathWithReason(path="x", reason="r")

    assert entry.is_expired is False
    assert entry.days_until_expiry is None
