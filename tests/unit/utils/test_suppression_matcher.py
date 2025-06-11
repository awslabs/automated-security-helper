"""Unit tests for suppression_matcher.py."""

from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.suppression_matcher import (
    _rule_id_matches,
    _file_path_matches,
    _line_range_matches,
    should_suppress_finding,
    check_for_expiring_suppressions,
)


def test_rule_id_matches_with_none():
    """Test rule ID matching with None finding rule ID."""
    assert not _rule_id_matches(None, "TEST-001")


def test_file_path_matches_with_none():
    """Test file path matching with None finding file path."""
    assert not _file_path_matches(None, "src/file.py")


def test_line_range_matches_with_none_line_start():
    """Test line range matching with None line start in finding."""
    finding = FlatVulnerability(
        id="test-id",
        title="Test Finding",
        description="Test Description",
        severity="HIGH",
        scanner="test-scanner",
        scanner_type="SAST",
        rule_id="TEST-001",
        file_path="src/file.py",
        line_start=None,
        line_end=None,
    )
    suppression = AshSuppression(
        reason="Test suppression",
        rule_id="TEST-001",
        path="src/file.py",
        line_start=10,
        line_end=20,
    )
    assert not _line_range_matches(finding, suppression)


def test_should_suppress_finding_with_invalid_expiration():
    """Test should_suppress_finding with invalid expiration date."""
    finding = FlatVulnerability(
        id="test-id",
        title="Test Finding",
        description="Test Description",
        severity="HIGH",
        scanner="test-scanner",
        scanner_type="SAST",
        rule_id="TEST-001",
        file_path="src/file.py",
        line_start=15,
        line_end=15,
    )

    # Mock the Suppression class to bypass validation
    with patch(
        "automated_security_helper.utils.suppression_matcher.AshSuppression"
    ) as _:
        # Create a mock suppression instance
        mock_suppression = MagicMock()
        mock_suppression.rule_id = "TEST-001"
        mock_suppression.file_path = "src/file.py"
        mock_suppression.expiration = "invalid-date"
        mock_suppression.line_start = None
        mock_suppression.line_end = None

        with patch(
            "automated_security_helper.utils.suppression_matcher.ASH_LOGGER"
        ) as mock_logger:
            result, matching = should_suppress_finding(finding, [mock_suppression])
            assert not result
            assert matching is None
            mock_logger.warning.assert_called_once()


def test_check_for_expiring_suppressions_with_invalid_date():
    """Test check_for_expiring_suppressions with invalid date format."""
    # Mock the Suppression class to bypass validation
    with patch("automated_security_helper.utils.suppression_matcher.AshSuppression"):
        # Create a mock suppression instance
        mock_instance = MagicMock()
        mock_instance.rule_id = "TEST-001"
        mock_instance.file_path = "src/file.py"
        mock_instance.expiration = "invalid-date"

        # Mock the logger
        with patch(
            "automated_security_helper.utils.suppression_matcher.ASH_LOGGER"
        ) as mock_logger:
            result = check_for_expiring_suppressions([mock_instance])
            assert len(result) == 0
            mock_logger.warning.assert_called_once()


def test_check_for_expiring_suppressions_with_future_date():
    """Test check_for_expiring_suppressions with future date beyond threshold."""
    # Create a date that's beyond the threshold
    future_date = (datetime.now() + timedelta(days=60)).strftime("%Y-%m-%d")

    suppression = AshSuppression(
        reason="Test suppression",
        rule_id="TEST-001",
        path="src/file.py",
        expiration=future_date,
    )

    result = check_for_expiring_suppressions([suppression])
    assert len(result) == 0


def test_check_for_expiring_suppressions_with_expiring_date():
    """Test check_for_expiring_suppressions with date within threshold."""
    # Create a date that's within the threshold
    expiring_date = (datetime.now() + timedelta(days=15)).strftime("%Y-%m-%d")

    suppression = AshSuppression(
        reason="Test suppression",
        rule_id="TEST-001",
        path="src/file.py",
        expiration=expiring_date,
    )

    result = check_for_expiring_suppressions([suppression])
    assert len(result) == 1
    assert result[0] == suppression
