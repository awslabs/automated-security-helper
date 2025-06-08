"""Tests for core models."""

import pytest
from datetime import date, timedelta
from pydantic import ValidationError

from automated_security_helper.models.core import Suppression


class TestSuppression:
    """Tests for the Suppression model."""

    def test_suppression_model_valid(self):
        """Test that a valid suppression model can be created."""
        suppression = Suppression(
            rule_id="RULE-123",
            path="src/example.py",
            line_start=10,
            line_end=15,
            reason="False positive due to test mock",
            expiration="2099-12-31",
        )
        assert suppression.rule_id == "RULE-123"
        assert suppression.path == "src/example.py"
        assert suppression.line_start == 10
        assert suppression.line_end == 15
        assert suppression.reason == "False positive due to test mock"
        assert suppression.expiration == "2099-12-31"

    def test_suppression_model_minimal(self):
        """Test that a minimal suppression model can be created."""
        suppression = Suppression(
            rule_id="RULE-123",
            path="src/example.py",
        )
        assert suppression.rule_id == "RULE-123"
        assert suppression.path == "src/example.py"
        assert suppression.line_start is None
        assert suppression.line_end is None
        assert suppression.reason is None
        assert suppression.expiration is None

    def test_suppression_model_invalid_line_range(self):
        """Test that a suppression model with invalid line range raises an error."""
        with pytest.raises(ValidationError) as excinfo:
            Suppression(
                rule_id="RULE-123",
                path="src/example.py",
                line_start=20,
                line_end=10,
            )
        assert "line_end must be greater than or equal to line_start" in str(
            excinfo.value
        )

    def test_suppression_model_invalid_expiration_format(self):
        """Test that a suppression model with invalid expiration format raises an error."""
        with pytest.raises(ValidationError) as excinfo:
            Suppression(
                rule_id="RULE-123",
                path="src/example.py",
                expiration="invalid-date",
            )
        assert "Invalid expiration date format" in str(excinfo.value)

    def test_suppression_model_expired_date(self):
        """Test that a suppression model with expired date raises an error."""
        yesterday = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")
        with pytest.raises(ValidationError) as excinfo:
            Suppression(
                rule_id="RULE-123",
                path="src/example.py",
                expiration=yesterday,
            )
        assert "expiration date must be in the future" in str(excinfo.value)

    def test_suppression_model_future_date(self):
        """Test that a suppression model with future date is valid."""
        tomorrow = (date.today() + timedelta(days=1)).strftime("%Y-%m-%d")
        suppression = Suppression(
            rule_id="RULE-123",
            path="src/example.py",
            expiration=tomorrow,
        )
        assert suppression.expiration == tomorrow
