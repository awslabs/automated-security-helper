# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""joined_membership and the mixed head agree on one closing.

The mixed membership sentence carries its own parenthetical dash, so the
join adds no comma after it; every other head takes one. Both sides key on
the same constant, and these cells hold the two together: a rewording of
the mixed sentence that drops the closing turns the join into a comma'd
sentence here, loudly, instead of silently double-punctuating or running
the halves together.
"""

from automated_security_helper.config.sandbox_grants import (
    _MIXED_HEAD_CLOSING,
    joined_membership,
    membership_clause,
)


def test_the_mixed_head_ends_with_the_shared_closing():
    head = membership_clause(checkout_membership=False, mixed=True, given_root=True)
    assert head.endswith(_MIXED_HEAD_CLOSING), head


def test_a_mixed_head_joins_with_a_space_and_no_comma():
    head = membership_clause(checkout_membership=False, mixed=True, given_root=True)
    joined = joined_membership(head, "so the tail follows")
    assert joined == f"{head} so the tail follows"
    assert f"{_MIXED_HEAD_CLOSING}," not in joined


def test_a_plain_head_joins_with_a_comma():
    head = membership_clause(checkout_membership=False, mixed=False, given_root=True)
    assert joined_membership(head, "so the tail follows") == (
        f"{head}, so the tail follows"
    )
