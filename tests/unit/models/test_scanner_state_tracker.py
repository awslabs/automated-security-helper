"""Tests for ScannerStateTracker — state CRUD and name validation."""

import inspect
from unittest.mock import MagicMock

import pytest

from automated_security_helper.models.scanner_validation import (
    ScannerStateTracker,
    ScannerValidationState,
)


@pytest.fixture
def tracker():
    ctx = MagicMock()
    ctx.config = MagicMock()
    return ScannerStateTracker()


class TestScannerStateTrackerCRUD:
    def test_update_then_get_round_trip(self, tracker):
        tracker.update_scanner_state("bandit", registration_status="registered")
        state = tracker.get_scanner_state("bandit")
        assert state is not None
        assert state.name == "bandit"
        assert state.registration_status == "registered"

    def test_update_creates_new_state(self, tracker):
        assert tracker.get_scanner_state("semgrep") is None
        tracker.update_scanner_state("semgrep", registration_status="registered")
        assert tracker.get_scanner_state("semgrep") is not None

    def test_update_merges_fields(self, tracker):
        tracker.update_scanner_state("bandit", registration_status="registered")
        tracker.update_scanner_state("bandit", execution_completed=True)
        state = tracker.get_scanner_state("bandit")
        assert state.registration_status == "registered"
        assert state.execution_completed is True

    def test_get_scanner_state_returns_none_for_unknown(self, tracker):
        assert tracker.get_scanner_state("nonexistent") is None

    def test_get_scanners_by_status(self, tracker):
        tracker.update_scanner_state("bandit", registration_status="registered")
        tracker.update_scanner_state("semgrep", registration_status="registered")
        tracker.update_scanner_state("trivy", registration_status="failed")
        result = tracker.get_scanners_by_status("registration_status", "registered")
        assert sorted(result) == ["bandit", "semgrep"]

    def test_get_scanners_by_status_empty(self, tracker):
        assert tracker.get_scanners_by_status("registration_status", "registered") == []

    def test_update_warns_on_unknown_field(self, tracker):
        # Should not raise, should just warn
        state = tracker.update_scanner_state("bandit", nonexistent_field="value")
        assert state is not None

    def test_get_scanner_state_summary_returns_categorized(self, tracker):
        tracker.update_scanner_state(
            "bandit",
            registration_status="registered",
            execution_completed=True,
        )
        summary = tracker.get_scanner_state_summary()
        assert "completed" in summary
        assert "bandit" in summary["completed"]

    def test_get_scanner_state_summary_skips_class_name_entries(self, tracker):
        # Validation at insert time should reject class names, but if one slips
        # through (legacy state), summary must skip it.
        tracker.scanner_states["BanditScanner"] = ScannerValidationState(
            name="BanditScanner"
        )
        summary = tracker.get_scanner_state_summary()
        for scanners in summary.values():
            assert "BanditScanner" not in scanners


class TestScannerStateTrackerNameValidation:
    def test_rejects_class_name_at_insert(self, tracker):
        with pytest.raises(ValueError, match="class name"):
            tracker.update_scanner_state("BanditScanner", registration_status="registered")

    def test_rejects_empty_name_at_insert(self, tracker):
        with pytest.raises(ValueError):
            tracker.update_scanner_state("", registration_status="registered")

    def test_rejects_none_like_falsy_name(self, tracker):
        with pytest.raises((ValueError, TypeError)):
            tracker.update_scanner_state(None, registration_status="registered")  # type: ignore[arg-type]

    def test_accepts_valid_scanner_name(self, tracker):
        state = tracker.update_scanner_state("bandit", registration_status="registered")
        assert state.name == "bandit"


class TestNoEndswithGuardsInSource:
    def test_no_inline_endswith_scanner_literal(self):
        """No raw inline .endswith("Scanner") guard should remain; only _is_class_name helper."""
        import automated_security_helper.models.scanner_validation as mod

        source = inspect.getsource(mod)
        # The literal string 'endswith("Scanner")' must not appear anywhere
        assert '.endswith("Scanner")' not in source, (
            '.endswith("Scanner") inline guard still present in scanner_validation.py — '
            "route through _is_class_name() instead"
        )

    def test_class_name_helper_exists_and_rejects_suffix(self):
        """_is_class_name helper must exist and correctly identify class names."""
        from automated_security_helper.models.scanner_validation import _is_class_name
        assert _is_class_name("BanditScanner") is True
        assert _is_class_name("bandit") is False
