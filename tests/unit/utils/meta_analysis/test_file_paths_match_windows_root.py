# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan root that is a Windows drive path places paths below it.

The paths are compared as text with their separators made ``/``, so the string
cases run on any host. The case of a drive letter does not tell two directories
apart on Windows (``C:`` and ``c:`` are one drive), and a reported path may spell
it either way. One case resolves a real directory and runs on Windows only.
"""

import sys

import pytest

from automated_security_helper.utils.meta_analysis.locations_match import (
    file_paths_match,
    resolve_scan_root,
)
from automated_security_helper.utils.meta_analysis.sarif_analysis import (
    validate_sarif_aggregation,
)

pytestmark = pytest.mark.unit

ROOT = "C:\\work\\app"


def _located(uri: str) -> dict:
    return {
        "ruleId": "R1",
        "message": {"text": "m"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 3},
                }
            }
        ],
    }


def _matched(original_uri: str, aggregated_uri: str, scan_root: str) -> int:
    result = validate_sarif_aggregation(
        {"bandit": {"runs": [{"results": [_located(original_uri)]}]}},
        {"runs": [{"results": [_located(aggregated_uri)]}]},
        scan_root=scan_root,
    )
    return result["match_statistics"]["bandit"]["matched_results"]


@pytest.mark.parametrize(
    "first",
    [
        "C:/work/app/lib/a.py",
        "C:\\work\\app\\lib\\a.py",
        "file:///C:/work/app/lib/a.py",
        # The drive letter in the other case is the same drive.
        "c:/work/app/lib/a.py",
        "file:///c:/work/app/lib/a.py",
    ],
)
def test_a_path_below_a_windows_root_is_compared_whole(first):
    assert file_paths_match(first, "lib/a.py", ROOT) is True
    assert file_paths_match("lib/a.py", first, ROOT) is True
    assert file_paths_match(first, "a.py", ROOT) is False
    assert file_paths_match("a.py", first, ROOT) is False


def test_a_sibling_of_a_windows_root_is_not_below_it():
    assert file_paths_match("C:/work/app2/lib/a.py", "2/lib/a.py", ROOT) is False


def test_the_root_in_either_case_and_either_separator_reads_the_same():
    for root in ("C:\\work\\app", "C:/work/app", "c:\\work\\app", "C:\\work\\app\\"):
        assert file_paths_match("C:/work/app/lib/a.py", "lib/a.py", root) is True
        assert file_paths_match("C:/work/app/lib/a.py", "a.py", root) is False


def test_validate_sarif_aggregation_takes_a_windows_root():
    assert resolve_scan_root(ROOT) is not None
    assert _matched("c:/work/app/lib/a.py", "lib/a.py", ROOT) == 1
    assert _matched("c:/work/app/lib/a.py", "a.py", ROOT) == 0


@pytest.mark.skipif(sys.platform != "win32", reason="resolves a real Windows path")
def test_a_resolved_windows_root_matches_a_path_with_the_other_drive_case(tmp_path):
    drive = tmp_path.drive
    lowered = drive.lower() + str(tmp_path)[len(drive) :]
    uri = str(tmp_path / "lib" / "a.py")

    assert _matched(uri, "lib/a.py", lowered) == 1
    assert _matched(uri, "a.py", lowered) == 0
