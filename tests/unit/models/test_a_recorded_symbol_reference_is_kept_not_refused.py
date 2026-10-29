# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression symbol recorded as an environment reference loads, and never applies.

A results file records a value the scan read from the environment as the
reference its config wrote (``${VAR}``). ``validate_symbol`` refused that text
whatever the context, so a suppression whose symbol came from the environment
made the scan's own results file unreadable. Under TOLERATE_STORED_CONFIG the
reference is kept with a note, like an unreadable expiration, and ``matches``
never applies the entry. A config file is still refused.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.models.core import (
    UNREADABLE_SYMBOL_NOTE,
    AshSuppression,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

pytestmark = pytest.mark.unit

RECORDED = {"path": "app.py", "reason": "r", "rule_id": "B101", "symbol": "${SYM}"}


def test_a_recorded_reference_is_kept_with_a_note():
    notes: list[str] = []

    kept = AshSuppression.model_validate(
        RECORDED, context={TOLERATE_STORED_CONFIG: notes}
    )

    assert kept.symbol == "${SYM}"
    assert UNREADABLE_SYMBOL_NOTE in notes, notes


def test_a_kept_reference_never_applies():
    kept = AshSuppression.model_validate(RECORDED, context={TOLERATE_STORED_CONFIG: []})
    finding = FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="HIGH",
        scanner="bandit",
        scanner_type="SAST",
        rule_id="B101",
        file_path="app.py",
        line_start=3,
    )

    assert kept.matches(finding, symbol_resolver=None) is False


def test_a_config_file_still_refuses_the_reference_text():
    with pytest.raises(ValidationError):
        AshSuppression.model_validate(RECORDED)


def test_a_malformed_symbol_is_still_refused_under_the_tolerance():
    with pytest.raises(ValidationError):
        AshSuppression.model_validate(
            {**RECORDED, "symbol": "not a symbol()"},
            context={TOLERATE_STORED_CONFIG: []},
        )
