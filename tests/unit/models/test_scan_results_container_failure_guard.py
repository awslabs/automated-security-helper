"""A scanner that failed every target must not report PASSED.

This guards the invariant that made a total cdk-nag failure indistinguishable from a clean
project: ``determine_status`` derived status from severity counts alone, so zero findings
meant PASSED whether the scanner examined a hundred templates or none.

These are unit tests on purpose. The invariant belongs to the container rather than to any one
scanner, so it is cheapest to pin here and applies to every scanner that reports per-target
outcomes.
"""

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.scan_results_container import ScanResultsContainer


def _container(**kwargs) -> ScanResultsContainer:
    return ScanResultsContainer(scanner_name="probe-scanner", **kwargs)


class TestTotalFailureIsNotPassed:
    def test_all_targets_failed_is_error(self):
        c = _container(targets_attempted=3, targets_failed=3)
        assert c.determine_status("MEDIUM") == ScannerStatus.ERROR

    def test_all_targets_failed_is_error_even_with_no_findings(self):
        # The exact shape of the reported defect: nothing found, everything failed. Before the
        # guard this returned PASSED, which is what made a broken scanner look clean.
        c = _container(targets_attempted=1, targets_failed=1)
        assert c.finding_count == 0
        assert c.determine_status("MEDIUM") == ScannerStatus.ERROR

    def test_all_targets_failed_outranks_the_severity_threshold(self):
        # A permissive or absent threshold turns the severity gate off. It must not also turn
        # the failure guard off -- the two are unrelated questions.
        c = _container(targets_attempted=2, targets_failed=2)
        assert c.determine_status(None) == ScannerStatus.ERROR
        assert c.determine_status("CRITICAL") == ScannerStatus.ERROR

    @pytest.mark.parametrize(
        "attempted,failed",
        [(3, 2), (10, 1), (2, 0)],
    )
    def test_partial_failure_is_not_error(self, attempted, failed):
        # Some targets succeeded, so the scan produced real information. Reporting ERROR here
        # would make any single unparseable file fail an otherwise good scan.
        c = _container(targets_attempted=attempted, targets_failed=failed)
        assert c.determine_status("MEDIUM") == ScannerStatus.PASSED

    def test_untracked_scanners_keep_existing_behavior(self):
        # Scanners that do not report per-target outcomes leave both counters at 0. The guard
        # must not fire for them, or every such scanner would regress to ERROR.
        c = _container()
        assert c.targets_attempted == 0
        assert c.determine_status("MEDIUM") == ScannerStatus.PASSED

    def test_failed_exceeding_attempted_still_errors(self):
        # Defensive: a miscount must resolve to ERROR rather than being treated as success.
        c = _container(targets_attempted=1, targets_failed=5)
        assert c.determine_status("MEDIUM") == ScannerStatus.ERROR


class TestScanSucceededProperty:
    def test_false_when_everything_failed(self):
        assert _container(targets_attempted=4, targets_failed=4).scan_succeeded is False

    def test_true_when_something_succeeded(self):
        assert _container(targets_attempted=4, targets_failed=3).scan_succeeded is True

    def test_true_when_nothing_was_attempted(self):
        # An empty scan set is not a failure; there was simply nothing to examine.
        assert _container().scan_succeeded is True


class TestNonNegativeIntAttr:
    """The executor reads the counters off arbitrary plugin objects, so it must coerce.

    A plain getattr with a default is not enough: MagicMock auto-creates every attribute, so
    the default never applies and a mock reaches an int-typed field that is not validated on
    assignment. The first comparison then raises TypeError. That is not hypothetical -- it
    broke 19 existing tests when this guard was first wired without coercion.
    """

    def test_reads_a_real_int(self):
        from automated_security_helper.core.phases.scanner_executor import (
            _non_negative_int_attr,
        )

        class Plugin:
            targets_attempted = 7

        assert _non_negative_int_attr(Plugin(), "targets_attempted") == 7

    def test_missing_attribute_is_zero(self):
        from automated_security_helper.core.phases.scanner_executor import (
            _non_negative_int_attr,
        )

        assert _non_negative_int_attr(object(), "targets_attempted") == 0

    def test_mock_attribute_is_zero_not_a_mock(self):
        from unittest.mock import MagicMock

        from automated_security_helper.core.phases.scanner_executor import (
            _non_negative_int_attr,
        )

        # The regression this exists for. Without coercion this returns a MagicMock.
        assert _non_negative_int_attr(MagicMock(), "targets_attempted") == 0

    def test_bool_is_rejected(self):
        from automated_security_helper.core.phases.scanner_executor import (
            _non_negative_int_attr,
        )

        class Plugin:
            targets_failed = True

        # bool subclasses int; reading True as 1 would silently accept a caller bug.
        assert _non_negative_int_attr(Plugin(), "targets_failed") == 0

    def test_negative_is_rejected(self):
        from automated_security_helper.core.phases.scanner_executor import (
            _non_negative_int_attr,
        )

        class Plugin:
            targets_failed = -3

        assert _non_negative_int_attr(Plugin(), "targets_failed") == 0


class TestRecordTargetFailure:
    def test_records_count_and_message(self):
        c = _container()
        c.record_target_attempt()
        c.record_target_failure("tpl.yaml", "TypeError: boom")

        assert c.targets_failed == 1
        # The message must survive. A counter alone tells an operator that something failed
        # but not what, which is only marginally better than the silence it replaced.
        assert any("tpl.yaml" in e and "boom" in e for e in c.errors)

    def test_counter_is_read_by_status(self):
        # The original defect was a failure list that was written and never read. This asserts
        # the recorded failure actually reaches the status decision.
        c = _container()
        c.record_target_attempt()
        c.record_target_failure("tpl.yaml", "TypeError: boom")
        assert c.determine_status("MEDIUM") == ScannerStatus.ERROR
