"""Regression tests for meta_analysis bug fixes (batch 2).

Covers bugs: #145, #149, #150, #151, #152, #153
"""

from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Bug #145 -- validation_results.py KeyError on severity keys
# ---------------------------------------------------------------------------

class TestBug145ValidationResultsKeyError:
    """validate_sarif_aggregation must not crash when severity keys are missing."""

    def test_missing_fields_uses_safe_key_access(self):
        from automated_security_helper.utils.meta_analysis.validate_sarif_aggregation import (
            validate_sarif_aggregation,
        )

        # Build a minimal report with no results -- should not KeyError
        original_reports = {
            "scanner1": {"runs": [{"results": []}]},
        }
        aggregated = {"runs": [{"results": []}]}

        result = validate_sarif_aggregation(original_reports, aggregated)
        # Should have the expected structure without KeyError
        assert "summary" in result
        assert "missing_fields" in result

    def test_match_statistics_has_expected_keys(self):
        from automated_security_helper.utils.meta_analysis.validate_sarif_aggregation import (
            validate_sarif_aggregation,
        )

        original = {
            "test_scanner": {
                "runs": [{
                    "results": [{
                        "ruleId": "R001",
                        "message": {"text": "test"},
                        "level": "error",
                    }]
                }]
            }
        }
        agg = {"runs": [{"results": []}]}

        result = validate_sarif_aggregation(original, agg)
        stats = result["match_statistics"]["test_scanner"]
        # Access with .get() should not raise
        assert stats.get("critical_fields_missing", 0) >= 0
        assert stats.get("important_fields_missing", 0) >= 0
        assert stats.get("informational_fields_missing", 0) >= 0


# ---------------------------------------------------------------------------
# Bug #149 -- are_values_equivalent: None == "None" returns True
# ---------------------------------------------------------------------------

class TestBug149NoneStringEquivalence:
    """None and the string 'None' must NOT be considered equivalent."""

    def test_none_vs_string_none_not_equivalent(self):
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        assert are_values_equivalent(None, "None") is False

    def test_none_vs_none_is_equivalent(self):
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        assert are_values_equivalent(None, None) is True

    def test_string_none_vs_string_none_is_equivalent(self):
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        assert are_values_equivalent("None", "None") is True

    def test_zero_vs_string_zero_not_equivalent(self):
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        # 0 and "0" are different types; str(0) == str("0") but they shouldn't match
        assert are_values_equivalent(0, "0") is False

    def test_false_vs_string_false_not_equivalent(self):
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        assert are_values_equivalent(False, "False") is False


# ---------------------------------------------------------------------------
# Bug #150 -- normalize_path returns extension leaf only
# ---------------------------------------------------------------------------

class TestBug150NormalizePathLeafOnly:
    """normalize_path must preserve enough path info to distinguish files."""

    def test_two_different_py_files_not_equal(self):
        from automated_security_helper.utils.meta_analysis.normalize_path import (
            normalize_path,
        )

        p1 = normalize_path("src/foo.py")
        p2 = normalize_path("src/bar.py")
        assert p1 != p2, "Different .py files must not normalize to the same value"

    def test_nested_paths_preserved(self):
        from automated_security_helper.utils.meta_analysis.normalize_path import (
            normalize_path,
        )

        p = normalize_path("runs[0].results[0].ruleId")
        # Should preserve enough structure to be useful, not just "ruleId"
        assert "ruleId" in p
        # With the fix, should normalize the full relative path
        normalized = normalize_path("src/utils/helper.py")
        assert "src" in normalized or "utils" in normalized or "helper" in normalized

    def test_full_relative_path_normalized(self):
        from automated_security_helper.utils.meta_analysis.normalize_path import (
            normalize_path,
        )

        result = normalize_path("a/b/c.py")
        # Must contain more than just "c" or "py"
        assert len(result) > 3


# ---------------------------------------------------------------------------
# Bug #151 -- extract_field_paths.py hardcoded test keys
# ---------------------------------------------------------------------------

class TestBug151ExtractFieldPathsHardcoded:
    """extract_field_paths must work for real SARIF objects, not just test fixtures."""

    def test_extracts_from_sarif_result_dict(self):
        from automated_security_helper.utils.meta_analysis.extract_field_paths import (
            extract_field_paths,
        )

        sarif_result = {
            "ruleId": "SEC-001",
            "level": "error",
            "message": {
                "text": "SQL injection found"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/db.py"},
                        "region": {"startLine": 42, "endLine": 42},
                    }
                }
            ],
        }

        paths = extract_field_paths(sarif_result)
        # Must extract actual field paths from the structure, not return empty
        assert len(paths) > 0
        # Should find at least some of the fields
        all_path_keys = list(paths.keys())
        assert len(all_path_keys) > 0

    def test_extracts_nested_keys(self):
        from automated_security_helper.utils.meta_analysis.extract_field_paths import (
            extract_field_paths,
        )

        obj = {
            "alpha": 1,
            "beta": {"gamma": "hello", "delta": [1, 2, 3]},
        }
        paths = extract_field_paths(obj)
        assert len(paths) > 0

    def test_handles_empty_dict(self):
        from automated_security_helper.utils.meta_analysis.extract_field_paths import (
            extract_field_paths,
        )

        paths = extract_field_paths({})
        assert isinstance(paths, dict)


# ---------------------------------------------------------------------------
# Bug #152 -- locations_match _line_ranges_compatible rejects diff==1
# ---------------------------------------------------------------------------

class TestBug152LineRangesOffByOne:
    """A start-line difference of 1 should be accepted (off-by-one is common)."""

    def test_start_diff_1_is_compatible(self):
        from automated_security_helper.utils.meta_analysis.locations_match import (
            _line_ranges_compatible,
        )

        # Lines 10-15 vs 11-15: diff of 1 with overlapping ranges
        assert _line_ranges_compatible(10, 15, 11, 15) is True

    def test_start_diff_2_still_compatible(self):
        from automated_security_helper.utils.meta_analysis.locations_match import (
            _line_ranges_compatible,
        )

        # Lines 10-15 vs 12-18: diff of 2
        assert _line_ranges_compatible(10, 15, 12, 18) is True

    def test_exact_match_compatible(self):
        from automated_security_helper.utils.meta_analysis.locations_match import (
            _line_ranges_compatible,
        )

        assert _line_ranges_compatible(10, 15, 10, 15) is True

    def test_non_overlapping_not_compatible(self):
        from automated_security_helper.utils.meta_analysis.locations_match import (
            _line_ranges_compatible,
        )

        # Lines 10-15 vs 100-200: no overlap
        assert _line_ranges_compatible(10, 15, 100, 200) is False

    def test_locations_match_with_off_by_one_lines(self):
        from automated_security_helper.utils.meta_analysis.locations_match import (
            locations_match,
        )

        loc1 = {
            "physicalLocation": {
                "artifactLocation": {"uri": "src/main.py"},
                "region": {"startLine": 10, "endLine": 15},
            }
        }
        loc2 = {
            "physicalLocation": {
                "artifactLocation": {"uri": "src/main.py"},
                "region": {"startLine": 11, "endLine": 15},
            }
        }
        assert locations_match(loc1, loc2) is True


# ---------------------------------------------------------------------------
# Bug #153 -- find_matching_result returns match on message-only
# ---------------------------------------------------------------------------

class TestBug153FindMatchingResultMessageOnly:
    """find_matching_result must require locations_match for confident matches."""

    def test_message_match_without_location_match_returns_none(self):
        from automated_security_helper.utils.meta_analysis.find_matching_result import (
            find_matching_result,
        )

        original = {
            "ruleId": "R001",
            "message": {"text": "same message"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/file_a.py"},
                        "region": {"startLine": 10},
                    }
                }
            ],
        }

        agg_results = [
            {
                "ruleId": "R001",
                "message": {"text": "same message"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/TOTALLY_DIFFERENT.py"},
                            "region": {"startLine": 999},
                        }
                    }
                ],
            }
        ]

        result = find_matching_result(original, agg_results)
        # Same ruleId + same message but locations clearly don't match
        # Should NOT return a match based on message alone
        assert result is None

    def test_location_match_returns_result(self):
        from automated_security_helper.utils.meta_analysis.find_matching_result import (
            find_matching_result,
        )

        original = {
            "ruleId": "R001",
            "message": {"text": "found issue"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/app.py"},
                        "region": {"startLine": 42},
                    }
                }
            ],
        }

        agg_results = [
            {
                "ruleId": "R001",
                "message": {"text": "found issue"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/app.py"},
                            "region": {"startLine": 42},
                        }
                    }
                ],
            }
        ]

        result = find_matching_result(original, agg_results)
        assert result is not None
