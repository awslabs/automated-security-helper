# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A flattened finding's two lines come from the region that supplied its start.

``_extract_location_info`` read ``startLine`` and ``endLine`` each as the first
non-None across ``region`` then ``contextRegion``. A region with a startLine
and no endLine is a one-line finding, and its endLine then came from the
contextRegion, so the flattened range ended at the viewer's context window and
not at the finding. The contextRegion stays the fallback when the region gives
no lines at all.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    Region,
    Result,
)

pytestmark = pytest.mark.unit


def _result(region: Region | None, context: Region | None) -> Result:
    return Result(
        ruleId="B102",
        level="error",
        message=Message(root=Message1(text="exec used")),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri="app.py"),
                        region=region,
                        contextRegion=context,
                    )
                )
            )
        ],
    )


def test_a_one_line_region_does_not_take_the_contexts_end_line():
    flat = FlatVulnerability.from_sarif_result(
        _result(Region(startLine=10), Region(startLine=5, endLine=20)),
        "bandit",
        "SAST",
    )

    assert flat.line_start == 10
    # None, not 10, on purpose: the flat finding records what the region said,
    # and a region that names no endLine said none. The vendored SARIF model
    # states no default for endLine, so none is invented here. Every reader of
    # the range reads None as "the same line as the start"
    # (AshSuppression._line_range_matches and suppression_id both fall back to
    # line_start), which the next test pins from the reader's side.
    assert flat.line_end is None, flat.line_end


def test_a_reader_takes_a_missing_end_line_as_the_start_line():
    from automated_security_helper.models.core import AshSuppression

    flat = FlatVulnerability.from_sarif_result(
        _result(Region(startLine=10), Region(startLine=5, endLine=20)),
        "bandit",
        "SAST",
    )
    on_the_line = AshSuppression(path="**", reason="r", line_start=10, line_end=10)
    past_the_line = AshSuppression(path="**", reason="r", line_start=11, line_end=12)

    assert on_the_line.matches(flat) is True
    # The context window runs to line 20; the finding does not.
    assert past_the_line.matches(flat) is False


def test_a_region_with_both_lines_keeps_them():
    flat = FlatVulnerability.from_sarif_result(
        _result(Region(startLine=10, endLine=12), Region(startLine=5, endLine=20)),
        "bandit",
        "SAST",
    )

    assert (flat.line_start, flat.line_end) == (10, 12)


def test_a_context_region_is_still_the_fallback_when_the_region_has_no_lines():
    flat = FlatVulnerability.from_sarif_result(
        _result(None, Region(startLine=5, endLine=20)), "bandit", "SAST"
    )

    assert (flat.line_start, flat.line_end) == (5, 20)


def test_a_region_that_exists_without_lines_falls_back_to_the_context_too():
    """A region with a character offset and no startLine gives no lines: the
    fallback is decided by the lines, not by the region being None."""
    flat = FlatVulnerability.from_sarif_result(
        _result(Region(charOffset=3), Region(startLine=5, endLine=20)),
        "bandit",
        "SAST",
    )

    assert (flat.line_start, flat.line_end) == (5, 20)
