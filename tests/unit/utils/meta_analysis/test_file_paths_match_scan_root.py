# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""With the scan root known, a result's file is compared whole, not by its end.

Without a root, a relative path matches an absolute one that ends with it, so an
aggregate that dropped a leading directory (``lib/a.py`` written ``a.py``) read as
a file kept, and two files that share their end (``src/main.py`` and
``services/api/src/main.py``) could be taken for one another. With the directory
the scan was run on, both sides are made relative to it and compared whole.
"""

import pytest

from automated_security_helper.utils.meta_analysis.field_mapping import (
    compare_result_fields,
)
from automated_security_helper.utils.meta_analysis.locations_match import (
    file_paths_match,
    locations_match,
)
from automated_security_helper.utils.meta_analysis.sarif_analysis import (
    find_matching_result,
    validate_sarif_aggregation,
)

pytestmark = pytest.mark.unit

ROOT = "/work/app"


def _located(uri: str, line: int = 3) -> dict:
    return {
        "ruleId": "R1",
        "message": {"text": "m"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def _report(*results: dict) -> dict:
    return {"runs": [{"results": list(results)}]}


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        ("/work/app/lib/a.py", "a.py", True),
        ("file:///work/app/lib/a.py", "a.py", True),
        ("/elsewhere/lib/a.py", "lib/a.py", True),
        ("/work/app/src/main.py", "services/api/src/main.py", False),
    ],
)
def test_without_a_root_the_end_of_a_path_still_matches(first, second, expected):
    """The control: with no root known the older end-of-path rule is unchanged."""
    assert file_paths_match(first, second) is expected
    assert file_paths_match(second, first) is expected


@pytest.mark.parametrize(
    ("first", "second"),
    [
        # An aggregate that dropped lib/ is not the same file.
        ("/work/app/lib/a.py", "a.py"),
        ("file:///work/app/lib/a.py", "a.py"),
        # Two files of one scan that share their end are two files.
        ("/work/app/src/main.py", "services/api/src/main.py"),
    ],
)
def test_with_a_root_files_are_compared_whole(first, second):
    assert file_paths_match(first, second, ROOT) is False
    assert file_paths_match(second, first, ROOT) is False


def test_an_absolute_path_outside_the_root_keeps_the_end_of_path_rule():
    """The root cannot place a path that is not below it, so it is compared as it
    is without a root: by its end against a relative path, and whole against
    another absolute one."""
    assert file_paths_match("/elsewhere/lib/a.py", "lib/a.py", ROOT) is True
    assert file_paths_match("lib/a.py", "/elsewhere/lib/a.py", ROOT) is True
    assert file_paths_match("/elsewhere/lib/a.py", "a.py", ROOT) is True
    assert file_paths_match("/elsewhere/lib/a.py", "/elsewhere/lib/a.py", ROOT) is True
    assert file_paths_match("/elsewhere/lib/a.py", "/other/lib/a.py", ROOT) is False
    # An end that is not a whole component is not a tail.
    assert file_paths_match("/elsewhere/lib/a.py", "b/a.py", ROOT) is False


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("/work/app/lib/a.py", "lib/a.py"),
        ("file:///work/app/lib/a.py", "./lib/a.py"),
        ("/work/app/lib/a.py", "file:///work/app/lib/a.py"),
        ("lib/a.py", "lib/a.py"),
        ("/work/app/lib/a.py", "/work/app/lib/a.py"),
    ],
)
def test_with_a_root_the_same_file_in_any_spelling_still_matches(first, second):
    assert file_paths_match(first, second, ROOT) is True
    assert file_paths_match(second, first, ROOT) is True


def test_a_root_with_a_trailing_separator_reads_as_the_same_root():
    assert file_paths_match("/work/app/lib/a.py", "lib/a.py", ROOT + "/") is True
    assert file_paths_match("/work/app/lib/a.py", "a.py", ROOT + "/") is False


def test_a_sibling_directory_that_shares_the_roots_prefix_is_not_below_it():
    """``/work/app2`` is not under ``/work/app``: the prefix is cut at a component,
    so ``2/lib/a.py`` is not the path below the root. The path is outside the
    root and keeps the end-of-path rule."""
    assert file_paths_match("/work/app2/lib/a.py", "2/lib/a.py", ROOT) is False
    assert file_paths_match("/work/app2/lib/a.py", "lib/a.py", ROOT) is True


def test_locations_match_threads_the_root():
    original = _located("/work/app/lib/a.py")["locations"][0]
    stripped = _located("a.py")["locations"][0]
    assert locations_match(original, stripped) is True
    assert locations_match(original, stripped, ROOT) is False


def test_find_matching_result_threads_the_root():
    original = _located("/work/app/lib/a.py")
    aggregated = [_located("a.py")]
    assert find_matching_result(original, aggregated) is aggregated[0]
    assert find_matching_result(original, aggregated, scan_root=ROOT) is None
    kept = [_located("lib/a.py")]
    assert find_matching_result(original, kept, scan_root=ROOT) is kept[0]


def test_compare_result_fields_threads_the_root():
    original = _located("/work/app/lib/a.py")
    stripped = _located("a.py")
    assert compare_result_fields(original, stripped) == []
    paths = [field["path"] for field in compare_result_fields(original, stripped, ROOT)]
    assert paths == ["locations[0].physicalLocation.artifactLocation.uri"]
    assert compare_result_fields(original, _located("lib/a.py"), ROOT) == []


def test_validate_sarif_aggregation_threads_the_root():
    original = {"bandit": _report(_located("/work/app/lib/a.py"))}
    aggregated = _report(_located("a.py"))

    without = validate_sarif_aggregation(original, aggregated)
    assert without["match_statistics"]["bandit"]["matched_results"] == 1

    with_root = validate_sarif_aggregation(original, aggregated, scan_root=ROOT)
    assert with_root["match_statistics"]["bandit"]["matched_results"] == 0
    assert with_root["summary"]["matched_findings"] == 0
    assert len(with_root["unmatched_results"]["bandit"]) == 1


def test_two_files_that_share_their_end_are_told_apart_with_a_root():
    """A monorepo: ``src/main.py`` and ``services/api/src/main.py`` are two files."""
    original = {"bandit": _report(_located("/work/app/src/main.py"))}
    aggregated = _report(_located("services/api/src/main.py"))

    with_root = validate_sarif_aggregation(original, aggregated, scan_root=ROOT)
    assert with_root["match_statistics"]["bandit"]["matched_results"] == 0

    own = _report(_located("services/api/src/main.py"), _located("src/main.py"))
    matched = validate_sarif_aggregation(original, own, scan_root=ROOT)
    assert matched["match_statistics"]["bandit"]["matched_results"] == 1
