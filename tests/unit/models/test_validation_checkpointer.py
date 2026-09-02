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


class TestFacadeExposesEveryMethodScanPhaseCalls:
    """The facade's surface, against the real caller rather than by inspection.

    ``TestRetryRegistrationRemoved`` above already guards one method this way,
    which is the right instinct -- the split into StateTracker/Checkpointer can
    silently drop a facade method and nothing else notices. It guarded one of
    three. ``report_execution_discrepancies`` and ``report_result_completeness``
    were dropped by that same split and went unnoticed because the scan_phase
    test fixture substitutes a bare MagicMock, which fabricates them.

    Derived from the source rather than hardcoded, so a new call added to
    scan_phase.py is covered without anyone remembering to extend this list.
    """

    def _names_called_on_the_manager(self) -> set:
        import re
        from pathlib import Path

        import automated_security_helper

        source = (
            Path(automated_security_helper.__file__).parent
            / "core"
            / "phases"
            / "scan_phase.py"
        ).read_text(encoding="utf-8")
        return set(re.findall(r"self\.validation_manager\.(\w+)\s*\(", source))

    def test_the_source_actually_yielded_names(self):
        """Positive control. An empty set would make the next test vacuous."""
        names = self._names_called_on_the_manager()
        assert len(names) >= 5, f"only found {names!r}; the regex or path is wrong"

    def test_every_called_name_exists_on_the_facade(self):
        missing = sorted(
            name
            for name in self._names_called_on_the_manager()
            if not hasattr(ScannerValidationManager, name)
        )
        assert not missing, (
            f"scan_phase.py calls {missing} on ScannerValidationManager, and the "
            f"facade does not define them. Either restore them or remove the calls"
        )


class TestDiscrepancyReporting:
    """The two restored reporters, on their documented shape."""

    def test_execution_discrepancies_summarises_the_checkpoint(self, manager):
        checkpoint = manager.create_checkpoint(
            "cp",
            expected_scanners=["bandit", "semgrep"],
            actual_scanners=["bandit", "grype"],
        )
        report = manager.report_execution_discrepancies(checkpoint)

        assert report["missing_scanners"] == ["semgrep"]
        assert report["unexpected_scanners"] == ["grype"]
        assert report["missing_count"] == 1
        assert report["unexpected_count"] == 1
        assert report["total_discrepancies"] == 2
        # has_discrepancies tracks the checkpoint's own has_issues(), which is
        # about recorded discrepancies/errors and is NOT implied by a missing
        # scanner -- see test_missing_scanners_detected above.
        assert report["has_discrepancies"] == checkpoint.has_issues()

    def test_execution_discrepancies_on_a_clean_checkpoint(self, manager):
        checkpoint = manager.create_checkpoint(
            "cp", expected_scanners=["bandit"], actual_scanners=["bandit"]
        )
        report = manager.report_execution_discrepancies(checkpoint)

        assert report["missing_scanners"] == []
        assert report["unexpected_scanners"] == []
        assert report["total_discrepancies"] == 0

    def test_result_completeness_summarises_the_checkpoint(self, manager):
        checkpoint = manager.create_checkpoint(
            "cp",
            expected_scanners=["bandit", "semgrep"],
            actual_scanners=["bandit"],
        )
        report = manager.report_result_completeness(checkpoint)

        assert report["missing_scanners"] == ["semgrep"]
        assert report["unexpected_scanners"] == []
        assert report["has_adjustments"] == checkpoint.has_issues()

    def test_reporters_do_not_mutate_the_checkpoint(self, manager):
        """They are pure summaries; a reporter that recorded state would make
        the count depend on how many times it was called."""
        checkpoint = manager.create_checkpoint(
            "cp", expected_scanners=["bandit", "semgrep"], actual_scanners=["bandit"]
        )
        before = (
            list(checkpoint.discrepancies),
            list(checkpoint.errors),
            list(checkpoint.actual_scanners),
        )

        manager.report_execution_discrepancies(checkpoint)
        manager.report_result_completeness(checkpoint)

        assert (
            list(checkpoint.discrepancies),
            list(checkpoint.errors),
            list(checkpoint.actual_scanners),
        ) == before
