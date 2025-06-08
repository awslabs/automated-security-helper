"""Simple unit tests for the run_ash_scan module."""

from automated_security_helper.interactions.run_ash_scan import format_duration


def test_format_duration_seconds():
    """Test format_duration with seconds only."""
    result = format_duration(45)
    assert result == "45s"


def test_format_duration_minutes():
    """Test format_duration with minutes and seconds."""
    result = format_duration(125)  # 2m 5s
    assert result == "2m 5s"


def test_format_duration_hours():
    """Test format_duration with hours, minutes, and seconds."""
    result = format_duration(3665)  # 1h 1m 5s
    assert result == "1h 1m 5s"
