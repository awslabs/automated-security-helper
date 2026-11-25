# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Report emitter output for inputs a frame column cannot hold.

A path with a lone surrogate (an ``os.fsdecode`` of undecodable bytes) and a
line number past 64 bits are findings the old code (``Counter``, ``list.sort``)
rendered. The frame layer must render them too, with the same order. Code points
are built with ``chr`` so the file itself stays valid UTF-8.
"""

import pytest

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from tests.unit.reporters.test_characterize_report_content_emitter import _emitter

pytestmark = pytest.mark.unit


def _vuln(**fields) -> FlatVulnerability:
    """A finding built without validation, as a path read from disk can arrive."""
    base = {
        "id": "f-1",
        "title": "a finding",
        "description": "",
        "severity": "MEDIUM",
        "scanner": "bandit",
        "scanner_type": "SAST",
    }
    return FlatVulnerability.model_construct(**{**base, **fields})


SURROGATE_PATH = "src/" + chr(0xDC80) + ".py"
BELOW_SURROGATES = "src/" + chr(0xD7FF) + ".py"
ABOVE_SURROGATES = "src/" + chr(0xE000) + ".py"


def test_a_surrogate_path_is_a_hotspot_under_its_own_name():
    emitter = _emitter([_vuln(severity="HIGH", file_path=SURROGATE_PATH, rule_id="R")])
    assert emitter.get_top_hotspots() == [{"location": SURROGATE_PATH, "count": 1}]


def test_surrogate_and_plain_paths_count_and_tie_as_before():
    paths = ["a.py", SURROGATE_PATH, "a.py", SURROGATE_PATH, "b.py"]
    emitter = _emitter([_vuln(severity="HIGH", file_path=p) for p in paths])
    assert emitter.get_top_hotspots() == [
        {"location": "a.py", "count": 2},
        {"location": SURROGATE_PATH, "count": 2},
        {"location": "b.py", "count": 1},
    ]


def test_surrogate_paths_are_detailed_in_code_point_order():
    emitter = _emitter(
        [
            _vuln(severity="HIGH", file_path=ABOVE_SURROGATES, rule_id="R"),
            _vuln(severity="HIGH", file_path=SURROGATE_PATH, rule_id="R"),
            _vuln(severity="HIGH", file_path="src/z.py", rule_id="R"),
            _vuln(severity="HIGH", file_path=BELOW_SURROGATES, rule_id="R"),
        ]
    )
    assert [row["location"] for row in emitter.get_detailed_findings()] == [
        "src/z.py",
        BELOW_SURROGATES,
        SURROGATE_PATH,
        ABOVE_SURROGATES,
    ]


def test_a_surrogate_path_is_listed_in_the_left_out_findings():
    emitter = _emitter(
        [_vuln(severity="HIGH", file_path=SURROGATE_PATH, workspace_project="p")]
    )
    emitter._policy_not_gating = {"p"}
    emitter._is_policy_origin_finding = lambda vuln: True  # type: ignore[method-assign]
    rows = emitter.get_policy_not_gating_findings()
    assert [row["file_path"] for row in rows] == [SURROGATE_PATH]


@pytest.mark.parametrize("big", [10**30, 2**63, -(2**63) - 1])
def test_a_line_number_past_64_bits_sorts_by_value(big):
    emitter = _emitter(
        [
            _vuln(severity="HIGH", file_path="a.py", line_start=big, rule_id="B"),
            _vuln(severity="HIGH", file_path="a.py", line_start=5, rule_id="S"),
        ]
    )
    expected = ["S", "B"] if big > 5 else ["B", "S"]
    assert [row["rule_id"] for row in emitter.get_detailed_findings()] == expected


def test_equal_huge_lines_tie_and_keep_their_order():
    emitter = _emitter(
        [
            _vuln(severity="HIGH", file_path="a.py", line_start=10**30, rule_id="X"),
            _vuln(
                severity="HIGH",
                file_path="a.py",
                line_start=10**30,
                rule_id="X",
                title="second",
            ),
        ]
    )
    assert [row["title"] for row in emitter.get_detailed_findings()] == [
        "a finding",
        "second",
    ]
