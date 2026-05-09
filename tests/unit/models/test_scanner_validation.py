"""Tests for models/scanner_validation.py — covers dataclasses and ScannerValidationManager."""

from datetime import datetime
from unittest.mock import MagicMock, patch
import pytest

from automated_security_helper.models.scanner_validation import (
    ScannerValidationState,
    ValidationCheckpoint,
    ScannerValidationManager,
)
from automated_security_helper.core.enums import ScannerStatus


@pytest.fixture
def mock_plugin_context():
    ctx = MagicMock()
    ctx.config = MagicMock()
    return ctx


@pytest.fixture
def manager(mock_plugin_context):
    return ScannerValidationManager(mock_plugin_context)


class TestScannerValidationState:
    """Tests for the ScannerValidationState dataclass."""

    def test_default_values(self):
        state = ScannerValidationState(name="bandit")
        assert state.name == "bandit"
        assert state.plugin_class is None
        assert state.registration_status == "unknown"
        assert state.enablement_status == "unknown"
        assert state.enablement_reason == ""
        assert state.dependency_errors == []
        assert state.queued_for_execution is False
        assert state.execution_completed is False
        assert state.included_in_results is False
        assert state.failure_reason is None
        assert state.metadata == {}

    def test_custom_values(self):
        state = ScannerValidationState(
            name="checkov",
            registration_status="registered",
            enablement_status="enabled",
            queued_for_execution=True,
        )
        assert state.registration_status == "registered"
        assert state.enablement_status == "enabled"
        assert state.queued_for_execution is True


class TestValidationCheckpoint:
    """Tests for the ValidationCheckpoint dataclass."""

    def test_default_values(self):
        cp = ValidationCheckpoint(checkpoint_name="test")
        assert cp.checkpoint_name == "test"
        assert isinstance(cp.timestamp, datetime)
        assert cp.expected_scanners == []
        assert cp.actual_scanners == []
        assert cp.discrepancies == []
        assert cp.errors == []
        assert cp.metadata == {}

    def test_add_discrepancy(self):
        cp = ValidationCheckpoint(checkpoint_name="test")
        cp.add_discrepancy("Missing scanner X")
        assert len(cp.discrepancies) == 1
        assert "Missing scanner X" in cp.discrepancies[0]

    def test_add_error(self):
        cp = ValidationCheckpoint(checkpoint_name="test")
        cp.add_error("Error occurred")
        assert len(cp.errors) == 1
        assert "Error occurred" in cp.errors[0]

    def test_has_issues_false_when_clean(self):
        cp = ValidationCheckpoint(checkpoint_name="test")
        assert cp.has_issues() is False

    def test_has_issues_true_with_discrepancy(self):
        cp = ValidationCheckpoint(checkpoint_name="test")
        cp.add_discrepancy("problem")
        assert cp.has_issues() is True

    def test_has_issues_true_with_error(self):
        cp = ValidationCheckpoint(checkpoint_name="test")
        cp.add_error("error")
        assert cp.has_issues() is True

    def test_get_missing_scanners(self):
        cp = ValidationCheckpoint(
            checkpoint_name="test",
            expected_scanners=["bandit", "checkov", "semgrep"],
            actual_scanners=["bandit", "semgrep"],
        )
        missing = cp.get_missing_scanners()
        assert missing == ["checkov"]

    def test_get_unexpected_scanners(self):
        cp = ValidationCheckpoint(
            checkpoint_name="test",
            expected_scanners=["bandit"],
            actual_scanners=["bandit", "semgrep"],
        )
        unexpected = cp.get_unexpected_scanners()
        assert unexpected == ["semgrep"]

    def test_get_missing_scanners_empty_when_all_present(self):
        cp = ValidationCheckpoint(
            checkpoint_name="test",
            expected_scanners=["bandit", "checkov"],
            actual_scanners=["bandit", "checkov"],
        )
        assert cp.get_missing_scanners() == []

    def test_get_unexpected_scanners_empty_when_all_expected(self):
        cp = ValidationCheckpoint(
            checkpoint_name="test",
            expected_scanners=["bandit", "checkov"],
            actual_scanners=["bandit"],
        )
        assert cp.get_unexpected_scanners() == []


class TestScannerValidationManagerBasic:
    """Tests for ScannerValidationManager basic operations."""

    def test_init(self, manager, mock_plugin_context):
        assert manager.plugin_context == mock_plugin_context
        assert manager.scanner_states == {}
        assert manager.checkpoints == []

    def test_get_scanner_state_returns_none_for_unknown(self, manager):
        assert manager.get_scanner_state("unknown") is None

    def test_update_scanner_state_creates_new(self, manager):
        state = manager.update_scanner_state(
            "bandit", registration_status="registered"
        )
        assert state.name == "bandit"
        assert state.registration_status == "registered"

    def test_update_scanner_state_updates_existing(self, manager):
        manager.update_scanner_state("bandit", registration_status="registered")
        state = manager.update_scanner_state(
            "bandit", enablement_status="enabled"
        )
        assert state.registration_status == "registered"
        assert state.enablement_status == "enabled"

    def test_update_scanner_state_warns_on_unknown_field(self, manager):
        state = manager.update_scanner_state("bandit", nonexistent_field="value")
        # Should not raise, just log a warning
        assert state.name == "bandit"

    def test_create_checkpoint(self, manager):
        cp = manager.create_checkpoint(
            "test_checkpoint",
            expected_scanners=["bandit", "checkov"],
            actual_scanners=["bandit"],
        )
        assert cp.checkpoint_name == "test_checkpoint"
        assert len(manager.checkpoints) == 1
        assert cp.expected_scanners == ["bandit", "checkov"]
        assert cp.actual_scanners == ["bandit"]

    def test_get_scanners_by_status(self, manager):
        manager.update_scanner_state("bandit", registration_status="registered")
        manager.update_scanner_state("checkov", registration_status="registered")
        manager.update_scanner_state("semgrep", registration_status="failed")

        registered = manager.get_scanners_by_status(
            "registration_status", "registered"
        )
        assert registered == ["bandit", "checkov"]

    def test_get_scanners_by_status_empty(self, manager):
        result = manager.get_scanners_by_status("registration_status", "registered")
        assert result == []


class TestScannerValidationManagerValidation:
    """Tests for validation methods."""

    def test_validate_registered_scanners(self, manager):
        scanner1 = MagicMock()
        scanner1.config.name = "bandit"
        scanner1.__class__.__name__ = "BanditScanner"

        scanner2 = MagicMock()
        scanner2.config.name = "checkov"
        scanner2.__class__.__name__ = "CheckovScanner"

        checkpoint = manager.validate_registered_scanners([scanner1, scanner2])

        assert checkpoint.checkpoint_name == "registered_scanners"
        assert "bandit" in checkpoint.expected_scanners
        assert "checkov" in checkpoint.expected_scanners
        assert manager.scanner_states["bandit"].registration_status == "registered"
        assert manager.scanner_states["checkov"].registration_status == "registered"

    def test_validate_scanner_enablement(self, manager):
        # Set up registered scanners
        manager.update_scanner_state("bandit", registration_status="registered")
        manager.update_scanner_state("checkov", registration_status="registered")
        manager.update_scanner_state("semgrep", registration_status="registered")

        checkpoint = manager.validate_scanner_enablement(
            enabled_scanners=["bandit"],
            excluded_scanners=["checkov"],
            dependency_errors={"semgrep": ["Missing semgrep binary"]},
        )

        assert checkpoint.checkpoint_name == "scanner_enablement"
        assert manager.scanner_states["bandit"].enablement_status == "enabled"
        assert manager.scanner_states["checkov"].enablement_status == "excluded"
        assert manager.scanner_states["semgrep"].enablement_status == "missing_deps"

    def test_validate_scanner_enablement_disabled_unknown(self, manager):
        manager.update_scanner_state("bandit", registration_status="registered")

        checkpoint = manager.validate_scanner_enablement(
            enabled_scanners=[],
            excluded_scanners=[],
        )

        assert manager.scanner_states["bandit"].enablement_status == "disabled"

    def test_validate_execution_completion(self, manager):
        manager.update_scanner_state(
            "bandit", queued_for_execution=True
        )
        manager.update_scanner_state(
            "checkov", queued_for_execution=True
        )

        checkpoint = manager.validate_execution_completion(["bandit"])

        assert checkpoint.checkpoint_name == "execution_completion"
        assert manager.scanner_states["bandit"].execution_completed is True
        # checkov was not in completed list
        assert manager.scanner_states["checkov"].failure_reason is not None


class TestDetermineScannerStatus:
    """Tests for determine_scanner_status_from_execution_data."""

    def test_missing_state_returns_missing(self, manager):
        result = manager.determine_scanner_status_from_execution_data("unknown")
        assert result["status"] == "missing"

    def test_missing_deps_status(self, manager):
        manager.update_scanner_state(
            "semgrep",
            enablement_status="missing_deps",
            dependency_errors=["Missing binary"],
        )
        result = manager.determine_scanner_status_from_execution_data("semgrep")
        assert result["status"] == "missing_deps"
        assert result["dependencies_satisfied"] is False

    def test_excluded_status(self, manager):
        manager.update_scanner_state(
            "checkov",
            enablement_status="excluded",
            enablement_reason="Excluded by config",
        )
        result = manager.determine_scanner_status_from_execution_data("checkov")
        assert result["status"] == "excluded"
        assert result["excluded"] is True

    def test_disabled_status(self, manager):
        manager.update_scanner_state(
            "checkov",
            enablement_status="disabled",
            enablement_reason="Scanner disabled",
        )
        result = manager.determine_scanner_status_from_execution_data("checkov")
        assert result["status"] == "excluded"

    def test_completed_status(self, manager):
        manager.update_scanner_state(
            "bandit",
            enablement_status="enabled",
            execution_completed=True,
        )
        result = manager.determine_scanner_status_from_execution_data("bandit")
        assert result["status"] == "completed"
        assert result["execution_completed"] is True

    def test_queued_but_not_completed_is_failed(self, manager):
        manager.update_scanner_state(
            "bandit",
            enablement_status="enabled",
            queued_for_execution=True,
            execution_completed=False,
        )
        result = manager.determine_scanner_status_from_execution_data("bandit")
        assert result["status"] == "failed"

    def test_failure_reason_set(self, manager):
        manager.update_scanner_state(
            "bandit",
            enablement_status="enabled",
            failure_reason="Timeout exceeded",
        )
        result = manager.determine_scanner_status_from_execution_data("bandit")
        assert result["status"] == "failed"
        assert result["failure_reason"] == "Timeout exceeded"


class TestEnsureCompleteResults:
    """Tests for ensure_complete_results."""

    def test_no_missing_scanners(self, manager):
        manager.update_scanner_state("bandit", registration_status="registered")

        aggregated_results = MagicMock()
        aggregated_results.scanner_results = {"bandit": MagicMock()}

        with patch.object(
            manager._checkpointer,
            "_get_executed_scanners_from_validation_state",
            return_value=["bandit"],
        ):
            checkpoint = manager.ensure_complete_results(aggregated_results)
            assert checkpoint.checkpoint_name == "result_completeness"

    def test_adds_missing_scanner_to_results(self, manager):
        manager.update_scanner_state(
            "bandit", registration_status="registered", enablement_status="enabled"
        )
        manager.update_scanner_state(
            "checkov",
            registration_status="registered",
            enablement_status="enabled",
            failure_reason="Timeout",
        )

        aggregated_results = MagicMock()
        aggregated_results.scanner_results = {"bandit": MagicMock()}

        with patch.object(
            manager._checkpointer,
            "_get_executed_scanners_from_validation_state",
            return_value=["bandit"],
        ), patch.object(
            manager._checkpointer,
            "_create_missing_scanner_result_entry",
            return_value=MagicMock(status=ScannerStatus.ERROR),
        ):
            checkpoint = manager.ensure_complete_results(aggregated_results)
            # checkov was missing and should have been added
            assert "checkov" in [
                d for d in checkpoint.discrepancies if "checkov" in d
            ] or len(checkpoint.discrepancies) > 0


class TestGetScannerStateSummary:
    """Tests for _get_scanner_state_summary."""

    def test_returns_categorized_summary(self, manager):
        manager.update_scanner_state(
            "bandit",
            registration_status="registered",
            enablement_status="enabled",
            execution_completed=True,
        )
        manager.update_scanner_state(
            "checkov",
            registration_status="registered",
            enablement_status="excluded",
            enablement_reason="excluded by config",
        )

        summary = manager._get_scanner_state_summary()
        assert isinstance(summary, dict)
        assert "completed" in summary
        assert "excluded" in summary

    def test_skips_class_name_entries(self, manager):
        # Insert a class-name entry directly (bypassing insert-time validation) to
        # verify the summary filters it out even if one slipped in via legacy paths.
        from automated_security_helper.models.scanner_validation import ScannerValidationState
        manager.scanner_states["BanditScanner"] = ScannerValidationState(
            name="BanditScanner", registration_status="registered"
        )
        summary = manager._get_scanner_state_summary()
        # Class name entries (ending in "Scanner") are filtered out
        all_names = []
        for scanners in summary.values():
            all_names.extend(scanners)
        assert "BanditScanner" not in all_names
