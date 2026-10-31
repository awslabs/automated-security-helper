# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--fix-unused`` refuses an edit that rewrites an entry it keeps.

Why this file exists
--------------------
After it comments entries out, the fixer composes the edited text and checks
that the list holds the number of entries that should remain. A line of a
commented-out entry that stays active (its ``reason:``, say) joins the kept
entry above it as a repeated key, and the last value wins: the list has the
expected number of entries, one of them with another entry's reason. The check
now also compares every remaining entry with the entry of the original at its
place.
"""

import pytest

from automated_security_helper.config.config_linter import (
    ConfigLinter,
    UnusedSuppressionsNotEditable,
)

pytestmark = pytest.mark.unit

ORIGINAL = (
    "global_settings:\n"
    "  suppressions:\n"
    "    - path: a.py\n"
    "      rule_id: B101\n"
    "      reason: first\n"
    "    - path: b.py\n"
    "      rule_id: B102\n"
    "      reason: second\n"
)

# The second entry commented out except its last line, which stays active at
# the first entry's key column and so joins the first entry.
HALF_COMMENTED = (
    "global_settings:\n"
    "  suppressions:\n"
    "    - path: a.py\n"
    "      rule_id: B101\n"
    "      reason: first\n"
    "    # - path: b.py\n"
    "    #   rule_id: B102\n"
    "      reason: second\n"
)


def test_a_half_commented_entry_that_rewrites_a_kept_one_is_refused():
    """Red at the base: the function took no original text, and its count check
    alone passes this text (one entry remains, as expected)."""
    with pytest.raises(UnusedSuppressionsNotEditable):
        ConfigLinter._refuse_an_edit_that_misreads_the_list(
            HALF_COMMENTED, 1, original=ORIGINAL, commented={1}
        )


def test_an_edit_that_leaves_the_kept_entry_alone_is_not_refused():
    """The positive control: the edit the fixer makes for the same entry."""
    fixed, commented = ConfigLinter._comment_out_suppressions(
        ORIGINAL, {1}, "2026-01-01"
    )

    assert commented == {1}
    ConfigLinter._refuse_an_edit_that_misreads_the_list(
        fixed, 1, original=ORIGINAL, commented=commented
    )
    assert "reason: first" in fixed
    assert "# - path: b.py" in fixed


def test_commenting_out_every_entry_is_not_refused():
    fixed, commented = ConfigLinter._comment_out_suppressions(
        ORIGINAL, {0, 1}, "2026-01-01"
    )

    assert commented == {0, 1}
    ConfigLinter._refuse_an_edit_that_misreads_the_list(
        fixed, 0, original=ORIGINAL, commented=commented
    )
