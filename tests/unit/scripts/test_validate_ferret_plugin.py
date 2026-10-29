# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/validate_ferret_plugin.py: an expired suppression covers nothing.

The validator parsed each suppression's ``expiration`` and never read it, so it
kept treating a suppression as active after ASH had stopped applying it (ASH's
rule: a YYYY-MM-DD date, expired from the start of that day; an unreadable date
is refused, so it never applies either).
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def validator(script_loader):
    return script_loader("validate_ferret_plugin")


def _entry(**fields):
    entry = {"rule_id": "SECRET-SECRET-KEYWORD", "path": "docs/*.md"}
    entry.update(fields)
    return entry


class TestExpiration:
    def test_an_entry_without_expiration_covers(self, validator):
        assert validator.suppression_covers(
            _entry(), "docs/a.md", 3, "SECRET-SECRET-KEYWORD"
        )

    def test_a_future_expiration_still_covers(self, validator):
        tomorrow = (date.today() + timedelta(days=1)).isoformat()
        assert validator.suppression_covers(
            _entry(expiration=tomorrow), "docs/a.md", 3, "SECRET-SECRET-KEYWORD"
        )

    def test_a_past_expiration_covers_nothing(self, validator):
        assert not validator.suppression_covers(
            _entry(expiration="2000-01-01"), "docs/a.md", 3, "SECRET-SECRET-KEYWORD"
        )

    def test_the_expiration_date_itself_has_already_expired(self, validator):
        assert validator.suppression_has_expired(date.today().isoformat())

    def test_an_unreadable_date_counts_as_expired(self, validator):
        assert validator.suppression_has_expired("next week")
        assert not validator.suppression_covers(
            _entry(expiration="31/12/2099"), "docs/a.md", 3, "SECRET-SECRET-KEYWORD"
        )
