# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for model bugs.

Covers bug H8: ReportMetadata default_factory used strftime("%Y%M%d")
where %M is the minute-of-hour rather than the month. The default
report_id must include the current month.
"""

import re
from datetime import datetime, timezone

from automated_security_helper.models.asharp_model import AshAggregatedResults


def test_default_metadata_report_id_contains_current_month():
    """The default metadata.report_id must encode the month, not the minute."""
    now = datetime.now(timezone.utc)
    results = AshAggregatedResults()

    report_id = results.metadata.report_id
    assert report_id is not None
    assert report_id.startswith("ASH-")

    # Format produced by the default_factory: ASH-YYYYMMDD
    match = re.match(r"^ASH-(\d{4})(\d{2})(\d{2})$", report_id)
    assert match is not None, f"Unexpected report_id format: {report_id}"

    year, month, day = match.group(1), match.group(2), match.group(3)
    assert year == f"{now.year:04d}"
    assert month == f"{now.month:02d}"
    assert day == f"{now.day:02d}"


def test_default_report_id_never_reflects_the_minute():
    """The default report_id must not equal the ASH-YYYY{minute}DD pattern.

    This is the exact regression: %M (minute) previously substituted for
    %m (month). When month != minute, the buggy string will differ from
    the correct one.
    """
    now = datetime.now(timezone.utc)
    results = AshAggregatedResults()
    buggy = f"ASH-{now:%Y}{now.minute:02d}{now:%d}"
    correct = f"ASH-{now:%Y}{now.month:02d}{now:%d}"

    if now.minute != now.month:
        assert results.metadata.report_id != buggy
    assert results.metadata.report_id == correct
