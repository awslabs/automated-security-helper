# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``match_findings`` on line numbers a 64-bit frame column cannot hold.

``FlatVulnerability.line_start`` is an unbounded ``Optional[int]``; the matcher
used to sort plain tuples and handled any of them. One corrupt finding must not
crash the whole diff.
"""

import pytest

from automated_security_helper.utils.finding_diff import match_findings
from tests.unit.utils.test_finding_diff_characterization import build, spec

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("big", [10**30, 2**63])
def test_a_huge_line_number_is_moved_not_a_crash(big):
    before = build([spec(line=10)])
    after = build([spec(line=big)])
    match = match_findings(before, after)
    assert len(match.moved) == 1 and not match.new and not match.absent


def test_huge_lines_pair_off_in_line_order():
    before = build([spec(line=10**30), spec(line=3), spec(line=2**63)])
    after = build([spec(line=4), spec(line=10**31), spec(line=2**64)])
    match = match_findings(before, after)
    got = [(a.line_start, b.line_start) for a, b in match.moved]
    assert got == [(3, 4), (2**63, 2**64), (10**30, 10**31)]


def test_an_identical_huge_line_is_exact():
    before = build([spec(line=10**30)])
    after = build([spec(line=10**30)])
    match = match_findings(before, after)
    assert len(match.exact) == 1 and not match.moved
