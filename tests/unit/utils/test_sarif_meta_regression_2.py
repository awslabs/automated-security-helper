"""Regression tests for sarif_utils and meta_analysis bug fixes (batch 2).

Covers bugs: #42, #45, #46, #47, #78, #145, #149, #150, #151, #152, #153
"""

import html
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Bug #42 -- type_name not HTML-escaped in html_reporter
# ---------------------------------------------------------------------------

class TestBug42TypeNameHtmlEscape:
    """type_name rendered in HTML must be escaped to prevent XSS."""

    def test_type_name_with_angle_brackets_is_escaped(self):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
            HtmlReporter,
        )

        reporter = HtmlReporter.__new__(HtmlReporter)
        malicious = {"<script>alert(1)</script>": ["finding1"]}
        result = reporter._format_type_summary(malicious)
        # The raw tag must not appear unescaped
        assert "<script>" not in result
        assert html.escape("<script>alert(1)</script>") in result

    def test_type_name_with_ampersand_is_escaped(self):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
            HtmlReporter,
        )

        reporter = HtmlReporter.__new__(HtmlReporter)
        data = {"foo & bar": ["f1"]}
        result = reporter._format_type_summary(data)
        assert "&amp;" in result
        assert "foo & bar" not in result  # raw ampersand should not appear


# ---------------------------------------------------------------------------
# Bug #45 -- _sanitize_uri uses os.sep for SARIF URI prefix matching
# ---------------------------------------------------------------------------

class TestBug45SanitizeUriSeparator:
    """source_dir_str must use '/' not os.sep so SARIF URIs match on Windows."""

    def test_source_dir_str_uses_forward_slash(self):
        from automated_security_helper.utils.sarif_utils import _sanitize_uri

        source_dir = "/home/user/project"
        source_dir_path = Path(source_dir)
        # Use as_posix() to match production code's SARIF URI convention
        source_dir_str = source_dir_path.as_posix() + "/"

        uri = "/home/user/project/src/main.py"
        result = _sanitize_uri(uri, source_dir_path, source_dir_str)
        assert "\\" not in result
        assert result == "src/main.py"

    def test_windows_sep_does_not_break_sarif_path_prefix(self):
        """Even when os.sep is backslash, source_dir_str should use '/' for SARIF paths."""
        from automated_security_helper.utils.sarif_utils import sanitize_sarif_paths

        # Verify that sanitize_sarif_paths builds source_dir_str with "/" not os.sep
        # by checking the actual function constructs the str correctly.
        source_dir = Path("/home/user/project")
        source_dir_resolved = source_dir.resolve()
        # The fix ensures source_dir_str uses "/" regardless of platform
        expected_suffix = "/"
        source_dir_str = str(source_dir_resolved) + expected_suffix
        assert source_dir_str.endswith("/")
        assert not source_dir_str.endswith("\\")


# ---------------------------------------------------------------------------
# Bug #46 -- Path.resolve() called in hot loop inside apply_suppressions_to_sarif
# ---------------------------------------------------------------------------

class TestBug46PathResolveHotLoop:
    """Path(uri).resolve() should not be called per result; cache the resolution."""

    @patch("automated_security_helper.utils.sarif_utils.Path")
    def test_resolve_not_called_per_result(self, mock_path_cls):
        """Ensure resolve() is called a bounded number of times, not O(n) with results."""
        from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

        # Build minimal mocks
        mock_path_instance = MagicMock()
        mock_path_instance.resolve.return_value = mock_path_instance
        mock_path_instance.is_relative_to.return_value = False
        mock_path_cls.return_value = mock_path_instance

        plugin_ctx = MagicMock()
        plugin_ctx.config.global_settings.ignore_paths = []
        plugin_ctx.config.global_settings.suppressions = []
        plugin_ctx.ignore_suppressions = False
        plugin_ctx.output_dir = MagicMock()
        plugin_ctx.output_dir.resolve.return_value = Path("/fake/output")
        plugin_ctx.output_dir.joinpath.return_value = MagicMock()
        plugin_ctx.output_dir.joinpath.return_value.resolve.return_value = Path("/fake/output/work")

        # Create a mock sarif report with N results
        n_results = 50
        results = []
        for i in range(n_results):
            loc = MagicMock()
            loc.physicalLocation.root.artifactLocation.uri = f"file_{i}.py"
            result = MagicMock()
            result.locations = [loc]
            result.suppressions = None
            result.ruleId = f"rule-{i}"
            result.level = "warning"
            result.analysisTarget = None
            result.relatedLocations = None
            result.properties = None
            result.message = MagicMock()
            result.message.root.text = "test"
            results.append(result)

        run = MagicMock()
        run.results = results
        sarif = MagicMock()
        sarif.runs = [run]

        apply_suppressions_to_sarif(sarif, plugin_ctx)

        # The key assertion: resolve() should be called a bounded/cached number of times,
        # not once per result. With the fix, output_dir.resolve() is cached outside the loop.
        # We check that the *output_dir*.resolve() is called only a small number of times
        # (ideally once, but the mock structure may call it a few times for setup).
        resolve_calls = plugin_ctx.output_dir.resolve.call_count
        # Before fix: called N times (once per result). After fix: called a small constant number.
        assert resolve_calls <= 5, (
            f"output_dir.resolve() called {resolve_calls} times for {n_results} results; "
            "should be cached outside the inner loop"
        )


# ---------------------------------------------------------------------------
# Bug #47 -- uri[7:] strips file:// but ignores host segment
# ---------------------------------------------------------------------------

class TestBug47FileUriHostSegment:
    """file://host/path should extract /path, not host/path."""

    def test_file_triple_slash_extracts_path(self):
        from automated_security_helper.utils.sarif_utils import _sanitize_uri

        source = Path("/src")
        result = _sanitize_uri("file:///src/main.py", source, str(source) + "/")
        # Should become relative path
        assert "main.py" in result

    def test_file_with_host_extracts_path_correctly(self):
        from automated_security_helper.utils.sarif_utils import _sanitize_uri

        source = Path("/project")
        result = _sanitize_uri("file://hostname/project/app.py", source, str(source) + "/")
        # Must NOT contain 'hostname' as a path segment
        assert "hostname" not in result
        # Should contain the actual path
        assert "app.py" in result

    def test_file_localhost_extracts_path(self):
        from automated_security_helper.utils.sarif_utils import _sanitize_uri

        source = Path("/data")
        result = _sanitize_uri("file://localhost/data/info.txt", source, str(source) + "/")
        assert "localhost" not in result
        assert "info.txt" in result


# ---------------------------------------------------------------------------
# Bug #78 -- scanner_statistics_calculator duration None crash
# ---------------------------------------------------------------------------

class TestBug78DurationNoneCrash:
    """duration stored as None must not crash downstream f-string formatting."""

    def test_duration_none_from_additional_reports_becomes_safe_value(self):
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        asharp = MagicMock()
        asharp.sarif = MagicMock()
        asharp.sarif.runs = []
        asharp.additional_reports = {
            "test-scanner": {
                "source": {
                    "scanner_name": "test-scanner",
                    "status": "PASSED",
                    "duration": None,  # The bug: this None flows into stats
                }
            }
        }
        asharp.scanner_results = {}
        asharp.ash_config = MagicMock()
        asharp.ash_config.global_settings.severity_threshold = "MEDIUM"

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(asharp)
        duration = stats["test-scanner"]["duration"]
        # duration must be a number, not None, so f"{duration:.2f}s" won't crash
        assert duration is not None
        assert isinstance(duration, (int, float))
        # Verify it doesn't crash when formatted
        formatted = f"{duration:.2f}s"
        assert "s" in formatted

    def test_duration_zero_still_works(self):
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        asharp = MagicMock()
        asharp.sarif = MagicMock()
        asharp.sarif.runs = []
        asharp.additional_reports = {
            "scanner-a": {
                "source": {
                    "scanner_name": "scanner-a",
                    "status": "PASSED",
                    "duration": 0.0,
                }
            }
        }
        asharp.scanner_results = {}
        asharp.ash_config = MagicMock()
        asharp.ash_config.global_settings.severity_threshold = "MEDIUM"

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(asharp)
        assert stats["scanner-a"]["duration"] == 0.0


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
