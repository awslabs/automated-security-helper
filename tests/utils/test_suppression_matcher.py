"""Tests for suppression matcher utility functions."""

from datetime import date, timedelta

from automated_security_helper.models.core import Suppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.suppression_matcher import (
    matches_suppression,
    should_suppress_finding,
    check_for_expiring_suppressions,
    _rule_id_matches,
    _file_path_matches,
    _line_range_matches,
)


class TestSuppressionMatcher:
    """Tests for the suppression matcher utility functions."""

    def test_rule_id_matches(self):
        """Test rule ID matching."""
        # Exact match
        assert _rule_id_matches("RULE-123", "RULE-123") is True

        # Pattern match
        assert _rule_id_matches("RULE-123", "RULE-*") is True
        assert _rule_id_matches("RULE-123", "*-123") is True
        assert _rule_id_matches("RULE-123", "RULE-?23") is True

        # No match
        assert _rule_id_matches("RULE-123", "RULE-456") is False
        assert _rule_id_matches("RULE-123", "OTHER-*") is False

        # None case
        assert _rule_id_matches(None, "RULE-123") is False

    def test_file_path_matches(self):
        """Test file path matching."""
        # Exact match
        assert _file_path_matches("src/example.py", "src/example.py") is True

        # Pattern match
        assert _file_path_matches("src/example.py", "src/*.py") is True
        assert _file_path_matches("src/example.py", "src/*") is True
        assert _file_path_matches("src/example.py", "*/example.py") is True
        assert _file_path_matches("src/example.py", "src/ex*.py") is True

        # No match
        assert _file_path_matches("src/example.py", "test/*.py") is False
        assert _file_path_matches("src/example.py", "src/*.js") is False

        # None case
        assert _file_path_matches(None, "src/example.py") is False

    def test_line_range_matches(self):
        """Test line range matching."""
        # Create test findings
        finding_with_range = FlatVulnerability(
            id="test-1",
            title="Test Finding",
            description="Test Description",
            severity="HIGH",
            scanner="test-scanner",
            scanner_type="SAST",
            file_path="src/example.py",
            line_start=10,
            line_end=15,
        )

        finding_single_line = FlatVulnerability(
            id="test-2",
            title="Test Finding",
            description="Test Description",
            severity="HIGH",
            scanner="test-scanner",
            scanner_type="SAST",
            file_path="src/example.py",
            line_start=20,
            line_end=None,
        )

        finding_no_line = FlatVulnerability(
            id="test-3",
            title="Test Finding",
            description="Test Description",
            severity="HIGH",
            scanner="test-scanner",
            scanner_type="SAST",
            file_path="src/example.py",
            line_start=None,
            line_end=None,
        )

        # Create test suppressions
        suppression_with_range = Suppression(
            rule_id="RULE-123",
            file_path="src/example.py",
            line_start=5,
            line_end=20,
        )

        suppression_single_line = Suppression(
            rule_id="RULE-123",
            file_path="src/example.py",
            line_start=20,
            line_end=None,
        )

        suppression_no_line = Suppression(
            rule_id="RULE-123",
            file_path="src/example.py",
            line_start=None,
            line_end=None,
        )

        # Test with range
        assert _line_range_matches(finding_with_range, suppression_with_range) is True
        assert _line_range_matches(finding_with_range, suppression_no_line) is True
        assert _line_range_matches(finding_with_range, suppression_single_line) is False

        # Test with single line
        assert _line_range_matches(finding_single_line, suppression_with_range) is True
        assert _line_range_matches(finding_single_line, suppression_single_line) is True
        assert _line_range_matches(finding_single_line, suppression_no_line) is True

        # Test with no line
        assert _line_range_matches(finding_no_line, suppression_with_range) is False
        assert _line_range_matches(finding_no_line, suppression_single_line) is False
        assert _line_range_matches(finding_no_line, suppression_no_line) is True

    def test_matches_suppression(self):
        """Test the matches_suppression function."""
        # Create test finding
        finding = FlatVulnerability(
            id="test-1",
            title="Test Finding",
            description="Test Description",
            severity="HIGH",
            scanner="test-scanner",
            scanner_type="SAST",
            rule_id="RULE-123",
            file_path="src/example.py",
            line_start=10,
            line_end=15,
        )

        # Create test suppressions
        suppression_match_all = Suppression(
            rule_id="RULE-123",
            file_path="src/example.py",
            line_start=5,
            line_end=20,
        )

        suppression_match_rule_only = Suppression(
            rule_id="RULE-123",
            file_path="src/other.py",
        )

        suppression_match_path_only = Suppression(
            rule_id="OTHER-RULE",
            file_path="src/example.py",
        )

        suppression_match_no_line = Suppression(
            rule_id="RULE-123",
            file_path="src/example.py",
        )

        suppression_no_match = Suppression(
            rule_id="OTHER-RULE",
            file_path="src/other.py",
        )

        # Test matches
        assert matches_suppression(finding, suppression_match_all) is True
        assert matches_suppression(finding, suppression_match_rule_only) is False
        assert matches_suppression(finding, suppression_match_path_only) is False
        assert matches_suppression(finding, suppression_match_no_line) is True
        assert matches_suppression(finding, suppression_no_match) is False

    def test_should_suppress_finding(self):
        """Test the should_suppress_finding function."""
        # Create test finding
        finding = FlatVulnerability(
            id="test-1",
            title="Test Finding",
            description="Test Description",
            severity="HIGH",
            scanner="test-scanner",
            scanner_type="SAST",
            rule_id="RULE-123",
            file_path="src/example.py",
            line_start=10,
            line_end=15,
        )

        # Create test suppressions
        suppression_match = Suppression(
            rule_id="RULE-123",
            file_path="src/example.py",
        )

        suppression_no_match = Suppression(
            rule_id="OTHER-RULE",
            file_path="src/other.py",
        )

        tomorrow = (date.today() + timedelta(days=1)).strftime("%Y-%m-%d")
        suppression_not_expired = Suppression(
            rule_id="RULE-123",
            file_path="src/example.py",
            expiration=tomorrow,
        )

        # Test with matching suppression
        should_suppress, matching_suppression = should_suppress_finding(
            finding, [suppression_match]
        )
        assert should_suppress is True
        assert matching_suppression == suppression_match

        # Test with non-matching suppression
        should_suppress, matching_suppression = should_suppress_finding(
            finding, [suppression_no_match]
        )
        assert should_suppress is False
        assert matching_suppression is None

        # Test with multiple suppressions
        should_suppress, matching_suppression = should_suppress_finding(
            finding, [suppression_no_match, suppression_match]
        )
        assert should_suppress is True
        assert matching_suppression == suppression_match

        # Test with not expired suppression
        should_suppress, matching_suppression = should_suppress_finding(
            finding, [suppression_not_expired]
        )
        assert should_suppress is True
        assert matching_suppression == suppression_not_expired

    def test_check_for_expiring_suppressions(self):
        """Test the check_for_expiring_suppressions function."""
        # Create test suppressions
        today = date.today().strftime("%Y-%m-%d")
        tomorrow = (date.today() + timedelta(days=1)).strftime("%Y-%m-%d")
        next_week = (date.today() + timedelta(days=7)).strftime("%Y-%m-%d")
        next_month = (date.today() + timedelta(days=29)).strftime("%Y-%m-%d")
        next_year = (date.today() + timedelta(days=365)).strftime("%Y-%m-%d")

        suppression_today = Suppression(
            rule_id="RULE-1",
            file_path="src/example.py",
            expiration=today,
        )

        suppression_tomorrow = Suppression(
            rule_id="RULE-2",
            file_path="src/example.py",
            expiration=tomorrow,
        )

        suppression_next_week = Suppression(
            rule_id="RULE-3",
            file_path="src/example.py",
            expiration=next_week,
        )

        suppression_next_month = Suppression(
            rule_id="RULE-4",
            file_path="src/example.py",
            expiration=next_month,
        )

        suppression_next_year = Suppression(
            rule_id="RULE-5",
            file_path="src/example.py",
            expiration=next_year,
        )

        suppression_no_expiration = Suppression(
            rule_id="RULE-6",
            file_path="src/example.py",
        )

        # Test with default threshold (30 days)
        suppressions = [
            suppression_today,
            suppression_tomorrow,
            suppression_next_week,
            suppression_next_month,
            suppression_next_year,
            suppression_no_expiration,
        ]

        expiring = check_for_expiring_suppressions(suppressions)

        # Today, tomorrow, next week, and next month should be expiring within 30 days
        assert len(expiring) == 4
        assert suppression_today in expiring
        assert suppression_tomorrow in expiring
        assert suppression_next_week in expiring
        assert suppression_next_month in expiring
        assert suppression_next_year not in expiring
        assert suppression_no_expiration not in expiring

        # Test with custom threshold (7 days)
        expiring = check_for_expiring_suppressions(suppressions, days_threshold=7)

        # Only today, tomorrow, and next week should be expiring within 7 days
        assert len(expiring) == 3
        assert suppression_today in expiring
        assert suppression_tomorrow in expiring
