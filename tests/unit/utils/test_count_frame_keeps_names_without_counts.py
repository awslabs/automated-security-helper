# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The count by scanner name keeps a name whose rows all state no finding.

``severity_counts_by_name`` lists every scanner name its rows hold, and counts the
rows by kind. A scanner whose results all state no finding (SARIF kind ``pass``,
``notApplicable`` or ``informational``, with nothing in them that reports a problem)
has rows of the kind ``NOT_A_FINDING``: the scanner ran and reported, so its name is
listed and it keeps its row in the statistics, and the rows count nothing.
"""

import pytest

pytestmark = pytest.mark.unit


def test_a_name_whose_rows_all_state_no_finding_is_kept_and_counts_nothing():
    from automated_security_helper.utils.count_frame import (
        NOT_A_FINDING,
        severity_counts_by_name,
    )

    counts = severity_counts_by_name([("bandit", "HIGH"), ("cdk-nag", NOT_A_FINDING)])

    assert counts.names == ["bandit", "cdk-nag"]
    assert counts.for_name("bandit").high == 1
    kept = counts.for_name("cdk-nag")
    assert [
        getattr(kept, field)
        for field in ("suppressed", "critical", "high", "medium", "low", "info")
    ] == [0, 0, 0, 0, 0, 0]
