"""A scanner that evaluated nothing must not report PASSED.

PR #514 taught ``determine_status`` to tell "found nothing" from "failed on everything". This
covers the third case it could not express: "evaluated nothing at all". A scanner with an empty
input set produces zero findings and no failures, which the severity gate reads as a clean
project and renders green.

The hazard these tests exist to hold down is the fix, not the bug. ``targets_attempted``
defaults to a state meaning "this scanner makes no claim about targets", because most scanners
never touch the counters -- bandit, checkov, semgrep, grype, syft, detect-secrets, opengrep,
cfn-nag, npm-audit. Reading that state as "attempted zero" would flip every one of them from
PASSED to SKIPPED and turn a whole clean report yellow, which is a worse defect than the one
being fixed. ``TestNoClaimIsNotAZeroClaim`` is the guard against exactly that, and it is the
test to run first if this file ever goes red.
"""

from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import ScannerSeverityCount
from automated_security_helper.models.scan_results_container import ScanResultsContainer


def _container(**kwargs) -> ScanResultsContainer:
    return ScanResultsContainer(scanner_name="probe-scanner", **kwargs)


# Every builtin scanner that does not track per-target outcomes. Named individually rather than
# discovered, so adding a scanner that tracks targets does not silently shrink the guard.
NON_TRACKING_SCANNERS = (
    "bandit",
    "cfn-nag",
    "checkov",
    "detect-secrets",
    "grype",
    "npm-audit",
    "opengrep",
    "semgrep",
    "syft",
)


class TestNoClaimIsNotAZeroClaim:
    """The cross-scanner regression guard. Read the module docstring before changing these."""

    def test_a_default_container_with_no_findings_is_passed(self):
        # The single most important assertion in this file. A scanner that says nothing about
        # targets and reports no findings has scanned cleanly, and must keep reporting PASSED.
        c = _container()
        assert c.targets_attempted is None, (
            "the default must be the no-claim state; a default of 0 would assert that every "
            "scanner tracked targets and attempted none"
        )
        assert c.determine_status("MEDIUM") == ScannerStatus.PASSED

    @pytest.mark.parametrize("scanner_name", NON_TRACKING_SCANNERS)
    def test_every_non_tracking_scanner_still_passes(self, scanner_name):
        # One case per scanner that would regress, so a failure names the blast radius instead
        # of reporting a single anonymous red test.
        c = ScanResultsContainer(scanner_name=scanner_name)
        assert c.determine_status("MEDIUM") == ScannerStatus.PASSED
        assert c.determine_status(None) == ScannerStatus.PASSED

    def test_a_no_claim_container_with_findings_still_fails(self):
        # The severity gate must remain reachable. A guard that returned early for every
        # no-claim container would suppress real failures.
        c = _container(severity_counts=ScannerSeverityCount(high=1))
        assert c.determine_status("HIGH") == ScannerStatus.FAILED

    def test_no_claim_scan_succeeded_is_true(self):
        assert _container().scan_succeeded is True

    def test_a_no_claim_container_omits_the_counter_when_serialized(self):
        # Reports are dumped with exclude_none, so the no-claim state stays absent from every
        # non-tracking scanner's serialized result rather than appearing as a literal 0 that a
        # downstream consumer could read as "attempted none".
        dumped = _container().model_dump(exclude_none=True, mode="json")
        assert "targets_attempted" not in dumped


class TestTrackedAndAttemptedNothing:
    def test_zero_attempts_is_skipped(self):
        c = _container(targets_attempted=0)
        assert c.determine_status("MEDIUM") == ScannerStatus.SKIPPED

    def test_zero_attempts_is_skipped_with_no_findings(self):
        # The reported shape: nothing evaluated, so nothing found. Before this change the
        # severity gate saw zero findings and returned PASSED, which renders green and reads as
        # "checked, clean".
        c = _container(targets_attempted=0, targets_failed=0)
        assert c.finding_count == 0
        assert c.determine_status("MEDIUM") == ScannerStatus.SKIPPED

    @pytest.mark.parametrize(
        "threshold", [None, "", "ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    )
    def test_zero_attempts_ignores_the_severity_threshold(self, threshold):
        # The threshold answers "which findings are bad enough to fail". It has nothing to say
        # about a scan that produced no findings because it read no input, so no setting of it
        # may turn this back into PASSED.
        assert _container(targets_attempted=0).determine_status(threshold) == (
            ScannerStatus.SKIPPED
        )

    def test_recording_a_zero_attempt_moves_off_the_no_claim_state(self):
        # How a scanner says "I looked and there was nothing to look at" through the API rather
        # than by assigning the field. Calling the method at all is the claim.
        c = _container()
        c.record_target_attempt(count=0)
        assert c.targets_attempted == 0
        assert c.determine_status("MEDIUM") == ScannerStatus.SKIPPED

    def test_a_negative_miscount_is_error_not_passed(self):
        # A negative count is where the ERROR and SKIPPED guards overlap, and this pins which
        # one wins. The ERROR guard tests truthiness, so -1 is truthy and ``0 >= -1`` holds --
        # ERROR, before this branch is reached. That is the right precedence: a counter below
        # zero means the scanner itself is miscounting, which is louder news than "there was
        # nothing to scan".
        #
        # What matters either way is that it does not reach the severity gate, where zero
        # findings off a broken counter would report PASSED.
        assert _container(targets_attempted=-1).determine_status("MEDIUM") == (
            ScannerStatus.ERROR
        )

    def test_a_negative_miscount_is_not_a_successful_scan(self):
        # scan_succeeded agrees with the status above rather than contradicting it, so SARIF
        # executionSuccessful and the rendered status cannot disagree about the same run.
        assert _container(targets_attempted=-1).scan_succeeded is False

    def test_zero_attempts_is_a_successful_execution(self):
        # SARIF executionSuccessful is about whether the tool's run completed, not about what
        # it yielded. A scanner with no applicable input ran fine; the "nothing evaluated"
        # signal is carried by status instead. Flipping this to False would fail every consumer
        # that gates on executionSuccessful, on any repository with no matching files.
        assert _container(targets_attempted=0).scan_succeeded is True


class TestTrackedWithAttempts:
    """The existing PR #514 outcomes, unchanged. These are the negative controls."""

    def test_all_targets_failed_is_still_error(self):
        assert (
            _container(targets_attempted=3, targets_failed=3).determine_status("MEDIUM")
            == ScannerStatus.ERROR
        )

    def test_error_not_skipped_when_a_single_target_failed(self):
        # ERROR and SKIPPED partition the tracked space on the sign of targets_attempted, so
        # this pins that a failed attempt is never mistaken for an absent one.
        c = _container(targets_attempted=1, targets_failed=1)
        assert c.determine_status("MEDIUM") == ScannerStatus.ERROR

    def test_attempts_with_no_failures_and_no_findings_is_passed(self):
        # The case that must stay green: the scanner really did evaluate templates and they
        # really were clean.
        c = _container(targets_attempted=4, targets_failed=0)
        assert c.determine_status("MEDIUM") == ScannerStatus.PASSED

    def test_partial_failure_with_findings_still_reaches_the_severity_gate(self):
        c = _container(
            targets_attempted=3,
            targets_failed=1,
            severity_counts=ScannerSeverityCount(critical=1),
        )
        assert c.determine_status("CRITICAL") == ScannerStatus.FAILED


class TestExecutorBoundaryPreservesTheTriState:
    """The trap lives at this boundary, not in the model.

    The executor copies the counters off arbitrary plugin objects. If that read answers 0 for a
    plugin that has no counter, the model never sees the no-claim state and every non-tracking
    scanner reports SKIPPED. The model tests above cannot catch that, because by then the damage
    is already a 0 in the field.
    """

    def test_a_plugin_without_the_counter_makes_no_claim(self):
        from automated_security_helper.core.phases.scanner_executor import (
            _target_count_attr,
        )

        assert _target_count_attr(object(), "targets_attempted") is None

    def test_a_mock_plugin_makes_no_claim(self):
        from automated_security_helper.core.phases.scanner_executor import (
            _target_count_attr,
        )

        # MagicMock auto-creates every attribute, so a plain getattr default never applies.
        # Answering None keeps an unusable value out of the field instead of coercing it to a
        # zero that means something specific and wrong.
        assert _target_count_attr(MagicMock(), "targets_attempted") is None

    @pytest.mark.parametrize("bad", [True, False, -3, "7", 2.0, None])
    def test_an_unusable_counter_makes_no_claim(self, bad):
        from automated_security_helper.core.phases.scanner_executor import (
            _target_count_attr,
        )

        class Plugin:
            targets_attempted = bad

        assert _target_count_attr(Plugin(), "targets_attempted") is None

    @pytest.mark.parametrize("value", [0, 1, 12])
    def test_a_real_count_is_carried_through(self, value):
        from automated_security_helper.core.phases.scanner_executor import (
            _target_count_attr,
        )

        class Plugin:
            targets_attempted = value

        # Zero has to survive the read. It is the whole signal for a tracking scanner that
        # evaluated nothing, and coercing it away would put the bug back.
        assert _target_count_attr(Plugin(), "targets_attempted") == value

    def test_the_boundary_and_the_model_compose_for_a_non_tracking_plugin(self):
        # The two halves wired together, because each is correct in isolation and the defect
        # only appears in the join.
        from automated_security_helper.core.phases.scanner_executor import (
            _non_negative_int_attr,
            _target_count_attr,
        )

        plugin = object()
        container = _container()
        container.targets_attempted = _target_count_attr(plugin, "targets_attempted")
        container.targets_failed = _non_negative_int_attr(plugin, "targets_failed")

        assert container.determine_status("MEDIUM") == ScannerStatus.PASSED

    def test_the_boundary_and_the_model_compose_for_a_tracking_plugin_at_zero(self):
        from automated_security_helper.core.phases.scanner_executor import (
            _non_negative_int_attr,
            _target_count_attr,
        )

        class Plugin:
            targets_attempted = 0
            targets_failed = 0

        plugin = Plugin()
        container = _container()
        container.targets_attempted = _target_count_attr(plugin, "targets_attempted")
        container.targets_failed = _non_negative_int_attr(plugin, "targets_failed")

        assert container.determine_status("MEDIUM") == ScannerStatus.SKIPPED


class TestABrokenCounterIsNotSilent:
    """A negative counter is dropped at the boundary. It must not be dropped quietly.

    This is the one place where reading each half separately gives the wrong answer about the
    whole. ``TestTrackedAndAttemptedNothing.test_a_negative_miscount_is_error_not_passed`` shows
    the model sends -1 to ERROR, and ``test_an_unusable_counter_makes_no_claim`` shows the
    boundary answers None for -1. Both pass, and together they mean the model's ERROR guard never
    sees a negative from a real plugin: the boundary has already turned it into "no claim", so a
    plugin miscounting its targets reaches the severity gate and reports PASSED off a broken
    counter. Neither half is wrong; the composition is, and only a test spanning both can say so.

    The fix is to keep the coercion and make it audible rather than to let the negative through.
    Returning it would have the model report ERROR -- "it tried and everything broke" -- which is
    a claim nobody has evidence for: all that is known is that the plugin's accounting is wrong.
    Its findings come from SARIF rather than from the counter and are still usable, so failing
    the scan on an accounting bug would be a worse answer than a warning that names it. Raising
    was rejected for the same reason, and because absorbing untrusted values at the boundary
    instead of propagating them is the whole argument for ``_target_count_attr`` existing.
    """

    @staticmethod
    def _read_with_logging(plugin, name="targets_attempted"):
        """Read the counter, returning (value, warning messages).

        ``ASH_LOGGER`` is patched rather than captured with caplog: it logs under the name "ash"
        with propagate=False, so a caplog assertion here reads an empty list and would pass no
        matter what the boundary did.
        """
        from unittest.mock import patch

        from automated_security_helper.core.phases import scanner_executor

        with patch.object(scanner_executor, "ASH_LOGGER") as logger:
            value = scanner_executor._target_count_attr(plugin, name)

        warnings = [
            str(call.args[0]) if call.args else str(call)
            for call in logger.warning.call_args_list
        ]
        return value, warnings

    @pytest.mark.parametrize("negative", [-1, -3, -100])
    def test_a_negative_counter_is_warned_about(self, negative):
        class Plugin:
            targets_attempted = negative

        value, warnings = self._read_with_logging(Plugin())

        assert value is None, "the negative must still not reach the field"
        assert warnings, (
            "dropping a negative counter must produce an operator-visible warning; otherwise a "
            "scanner that miscounts its targets is indistinguishable from one that does not "
            "track them, and reports PASSED"
        )
        joined = " ".join(warnings)
        assert "targets_attempted" in joined, (
            f"the warning must name the counter so it is actionable; got {warnings}"
        )
        assert str(negative) in joined, (
            f"the warning must carry the offending value; got {warnings}"
        )

    def test_the_warning_names_the_plugin_it_came_from(self):
        """A warning that does not say which scanner is broken is not actionable.

        A run has a dozen scanners and the counters are read for each of them, so the message has
        to identify the source or an operator cannot act on it.
        """

        class WidgetScanner:
            targets_attempted = -2

        _, warnings = self._read_with_logging(WidgetScanner())

        assert any("WidgetScanner" in message for message in warnings), (
            f"expected the plugin class name in the warning; got {warnings}"
        )

    @pytest.mark.parametrize(
        "bad", [True, False, "7", 2.0, None, object(), MagicMock()]
    )
    def test_only_negatives_are_warned_about(self, bad):
        """The negative control, and it is what stops this becoming log noise.

        Every other unusable value is a scanner that simply does not track targets -- the normal
        case for nine of the builtins and for the MagicMock every test suite passes in. Warning
        about those would fire on every clean run and train operators to ignore the message,
        which costs more than the silence it replaces. Only a negative is evidence of a counter
        that was tracked and then miscounted.
        """

        class Plugin:
            targets_attempted = bad

        value, warnings = self._read_with_logging(Plugin())

        assert value is None
        assert warnings == [], (
            f"a non-tracking or absent counter is not a defect and must stay quiet; got "
            f"{warnings}"
        )

    def test_an_absent_counter_is_warned_about_for_neither_name(self):
        for name in ("targets_attempted", "targets_failed"):
            value, warnings = self._read_with_logging(object(), name=name)
            assert value is None
            assert warnings == [], f"{name}: {warnings}"

    def test_a_negative_targets_failed_is_warned_about_too(self):
        """``_non_negative_int_attr`` shares the coercion, so it shares the warning.

        The two helpers deliberately have one rule about what counts as usable. A negative
        failure count is the same kind of accounting bug and must not be quieter just because
        this caller collapses None to 0.
        """
        from unittest.mock import patch

        from automated_security_helper.core.phases import scanner_executor

        class Plugin:
            targets_failed = -5

        with patch.object(scanner_executor, "ASH_LOGGER") as logger:
            value = scanner_executor._non_negative_int_attr(Plugin(), "targets_failed")

        assert value == 0
        assert logger.warning.called, (
            "a negative targets_failed must be reported as well"
        )

    def test_the_composed_negative_still_passes_and_says_why(self):
        """The composition, end to end: what an operator gets for a miscounting plugin.

        PASSED is the deliberate outcome, not a residual bug -- see the class docstring. What
        changes is that it is no longer silent. This test is the one that fails if someone
        removes the warning while leaving both halves individually correct, which is exactly how
        the gap arose.
        """
        from unittest.mock import patch

        from automated_security_helper.core.phases import scanner_executor

        class Plugin:
            targets_attempted = -1
            targets_failed = 0

        plugin = Plugin()
        container = _container()
        with patch.object(scanner_executor, "ASH_LOGGER") as logger:
            container.targets_attempted = scanner_executor._target_count_attr(
                plugin, "targets_attempted"
            )
            container.targets_failed = scanner_executor._non_negative_int_attr(
                plugin, "targets_failed"
            )

        assert container.targets_attempted is None
        assert container.determine_status("MEDIUM") == ScannerStatus.PASSED
        assert logger.warning.called, (
            "the status is PASSED, so the warning is the only signal that this scanner's "
            "counters are broken; without it the run is indistinguishable from a clean one"
        )
