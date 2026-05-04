# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression test for #171: past expiration date should warn, not crash.

Before the fix, validate_expiration_date raised ValueError for past dates,
which caused the entire config file to fail parsing when any suppression
had an expired date. The fix changed it to warn and return None so that
scanning continues and the suppression is simply ignored.
"""
import warnings

from automated_security_helper.models.core import AshSuppression


def test_past_expiration_warns_instead_of_raising():
    """A suppression with a past expiration date should not crash config parsing."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        s = AshSuppression(
            path="test.py",
            rule_id="TEST-001",
            reason="test",
            expiration="2020-01-01",
        )
        assert s.expiration is None
        assert len(w) == 1
        assert "past" in str(w[0].message).lower()


def test_future_expiration_accepted():
    """A future expiration date should work as before."""
    s = AshSuppression(
        path="test.py",
        rule_id="TEST-001",
        reason="test",
        expiration="2099-12-31",
    )
    assert s.expiration == "2099-12-31"


def test_none_expiration_accepted():
    """No expiration should work as before."""
    s = AshSuppression(
        path="test.py",
        rule_id="TEST-001",
        reason="test",
        expiration=None,
    )
    assert s.expiration is None
