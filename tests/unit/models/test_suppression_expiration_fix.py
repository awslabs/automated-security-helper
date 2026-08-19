# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for #171: past expiration date must be accepted, not discarded.

After the fix the validator checks format only; past dates are preserved so
that is_expired can return True at runtime. The old behaviour (warn + return
None) was removed.
"""

from automated_security_helper.models.core import AshSuppression


def test_past_expiration_accepted_not_discarded():
    """A past expiration date must be stored, not silently set to None."""
    s = AshSuppression(
        path="test.py",
        rule_id="TEST-001",
        reason="test",
        expiration="2020-01-01",
    )
    assert s.expiration == "2020-01-01"
    assert s.is_expired is True


def test_future_expiration_accepted():
    """A future expiration date should work as before."""
    s = AshSuppression(
        path="test.py",
        rule_id="TEST-001",
        reason="test",
        expiration="2099-12-31",
    )
    assert s.expiration == "2099-12-31"
    assert s.is_expired is False


def test_none_expiration_accepted():
    """No expiration should work as before."""
    s = AshSuppression(
        path="test.py",
        rule_id="TEST-001",
        reason="test",
        expiration=None,
    )
    assert s.expiration is None
    assert s.is_expired is False
