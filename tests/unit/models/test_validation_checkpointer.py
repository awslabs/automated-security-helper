"""Tests for ValidationCheckpointer — checkpoint creation and validation logic."""

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.models.scanner_validation import (
    ScannerStateTracker,
    ScannerValidationManager,
    ValidationCheckpoint,
    ValidationCheckpointer,
)
from automated_security_helper.core.enums import ScannerStatus


@pytest.fixture
def tracker():
    return ScannerStateTracker()


@pytest.fixture
def checkpointer(tracker):
    return ValidationCheckpointer(tracker)


@pytest.fixture
def manager():
    ctx = MagicMock()
    ctx.config = MagicMock()
    return ScannerValidationManager(ctx)


class TestValidationCheckpointerCreateCheckpoint:
    def test_creates_validation_checkpoint(self, checkpointer):
        cp = checkpointer.create_checkpoint(
            "test_cp",
            expected_scanners=["bandit", "semgrep"],
            actual_scanners=["bandit"],
        )
        assert isinstance(cp, ValidationCheckpoint)
        assert cp.checkpoint_name == "test_cp"
        assert cp.expected_scanners == ["bandit", "semgrep"]
        assert cp.actual_scanners == ["bandit"]

    def test_checkpoint_appended_to_list(self, checkpointer):
        assert len(checkpointer.checkpoints) == 0
        checkpointer.create_checkpoint("cp1")
        assert len(checkpointer.checkpoints) == 1

    def test_missing_scanners_detected(self, checkpointer):
        cp = checkpointer.create_checkpoint(
            "cp",
            expected_scanners=["bandit", "semgrep"],
            actual_scanners=["bandit"],
        )
        assert cp.get_missing_scanners() == ["semgrep"]
        assert cp.has_issues() is False  # missing scanners don't auto-add discrepancies


class TestValidationCheckpointerExecutionCompletion:
    def test_pass_when_all_complete(self, tracker, checkpointer):
        tracker.update_scanner_state("bandit", registration_status="registered")
        tracker.update_scanner_state("bandit", enablement_status="enabled")
        tracker.update_scanner_state("bandit", queued_for_execution=True)

        cp = checkpointer.validate_execution_completion(["bandit"])
        assert "bandit" in cp.actual_scanners

    def test_fail_detects_missing_scanner(self, tracker, checkpointer):
        tracker.update_scanner_state("bandit", registration_status="registered")
        tracker.update_scanner_state("bandit", enablement_status="enabled")
        tracker.update_scanner_state("bandit", queued_for_execution=True)

        cp = checkpointer.validate_execution_completion([])
        assert cp.get_missing_scanners() == ["bandit"]


class TestRetryRegistrationRemoved:
    def test_retry_scanner_registration_not_on_checkpointer(self):
        assert not hasattr(ValidationCheckpointer, "retry_scanner_registration"), (
            "retry_scanner_registration must not exist on ValidationCheckpointer"
        )

    def test_retry_scanner_registration_still_on_facade(self):
        # The facade keeps it for backward compat with scan_phase.py caller
        assert hasattr(ScannerValidationManager, "retry_scanner_registration"), (
            "ScannerValidationManager facade must still expose retry_scanner_registration"
        )

    def test_retry_returns_empty_list(self):
        ctx = MagicMock()
        mgr = ScannerValidationManager(ctx)
        result = mgr.retry_scanner_registration(["bandit"])
        assert result == []
