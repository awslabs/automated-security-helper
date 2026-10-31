# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: the junitxml reporter reads the threshold from the config.

Why this file exists separately from test_junitxml_threshold_ladder.py
---------------------------------------------------------------------
That file drives the threshold by injecting ``properties.severity_threshold``
onto each SARIF result. Nothing in ASH writes that property -- it has one
reader, in the reporter, and no writer anywhere in the repository -- so every
one of its twenty cells exercised a path a real scan never takes. The matrix was
green while the reporter emitted ``<error>`` for every sub-threshold finding in
production, because the property was absent, ``threshold`` was therefore None,
the guard short-circuited, and ``is_actionable`` kept its initial True. The
``Skipped`` branch was unreachable outside those fixtures.

So a green fixture-driven matrix is not evidence that the gate works. The tests
here drive the threshold the way a scan does -- through
``model.ash_config.global_settings.severity_threshold`` -- and set no per-result
property at all. Every assertion below fails on the code as it stood before the
threshold source was fixed.

Per-scanner threshold overrides
-------------------------------
``_compute_exit_code`` grades each result by the threshold governing its own
scanner (``ScannerStatisticsCalculator.get_scanner_threshold_info``, memoized
per scanner), so a scanner the operator tightened or relaxed through
``options.severity_threshold`` was judged by its own setting in the exit code
and the summary table, and by the global setting in this report. An earlier
version of this docstring said the exit code did not consult them; it does, and
``TestScannerThresholdIsRead`` pins the reporter to the same resolver.

What these tests do not cover
-----------------------------
* ``<failure>``. The reporter imports only ``Error`` and ``Skipped``, so a
  qualifying finding is always ``<error>`` and never ``<failure>``. That is
  unchanged here and pinned only incidentally, by asserting on ``error``.
"""

import xml.etree.ElementTree as ET  # nosec B405

import pytest

from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from tests.unit.plugin_modules.ash_builtin.reporters.test_junitxml_reporter import (
    ALL_SARIF_LEVELS,
    THRESHOLD_QUALIFYING_LEVELS,
    _get_reporter,
    _make_model,
    _make_result,
    _make_run,
    _outcome,
    _without_scanner_thresholds,
)

pytestmark = pytest.mark.unit

# THRESHOLD_QUALIFYING_LEVELS and ALL_SARIF_LEVELS are imported rather than
# transcribed again. This file used to carry its own copy, which meant one table
# existed three times -- here, in test_junitxml_threshold_ladder.py, and inside
# run_ash_scan._compute_exit_code -- and the two test copies could have drifted
# apart without any test noticing. The single remaining transcription lives in
# the helper module, tied to the ladder by
# TestQualifyingLevelsMatchTheLadder.


def _render_from_config(tmp_path, level, threshold, issue_severity=None):
    """Report one finding whose threshold comes only from the scan config.

    The result deliberately carries no ``severity_threshold`` and no
    ``below_threshold`` property, so the reporter has nowhere to read a
    threshold from except the config. The threshold is always set explicitly
    rather than left at the default, because ``get_default_config`` honours the
    ``ASH_CONFIG`` environment variable and a defaulted threshold would make
    these assertions depend on the environment.
    """
    result = _make_result(level=level, scanner_name="bandit")
    if issue_severity is not None:
        result.properties.__pydantic_extra__["issue_severity"] = issue_severity

    model = _without_scanner_thresholds(_make_model(runs=[_make_run(results=[result])]))
    model.ash_config.global_settings.severity_threshold = threshold

    output = _get_reporter(tmp_path).report(model)
    return ET.fromstring(output).find(".//testcase")  # nosec B314


def _render_kind(tmp_path, level, threshold, kind):
    """Report one finding at an explicit SARIF ``kind`` and return its testcase."""
    result = _make_result(level=level, scanner_name="cdk-nag")
    result.kind = kind
    model = _without_scanner_thresholds(_make_model(runs=[_make_run(results=[result])]))
    model.ash_config.global_settings.severity_threshold = threshold
    output = _get_reporter(tmp_path).report(model)
    return ET.fromstring(output).find(".//testcase")  # nosec B314


class TestConfigThresholdIsRead:
    """The defect, stated as the two cells CI actually hit."""

    def test_note_finding_is_skipped_under_the_configured_medium_threshold(
        self, tmp_path
    ):
        """Bandit's LOW findings are SARIF `note`; six of them turned CI red.

        Before the fix this was ``<error>``: with no per-result property the
        reporter never obtained a threshold, so it never consulted the ladder,
        and ``result.kind`` defaulting to ``Kind.fail`` satisfied the kind check
        before ``level`` was looked at.
        """
        testcase = _render_from_config(tmp_path, level="note", threshold="MEDIUM")
        assert _outcome(testcase) == "below-threshold"
        assert testcase.find("skipped").get("type") == "threshold"

    def test_none_finding_is_skipped_under_the_configured_medium_threshold(
        self, tmp_path
    ):
        """Level `none` maps to INFO, below every threshold except ALL."""
        testcase = _render_from_config(tmp_path, level="none", threshold="MEDIUM")
        assert _outcome(testcase) == "below-threshold"

    def test_a_qualifying_finding_is_still_an_error(self, tmp_path):
        """Positive control: the fix must not skip everything.

        Without this, a helper that returned a falsy threshold -- or an
        ``is_actionable`` wired to False -- would pass every assertion above
        while reporting a critical finding as skipped.
        """
        testcase = _render_from_config(tmp_path, level="error", threshold="MEDIUM")
        assert _outcome(testcase) == "actionable"


class TestConfigThresholdMatrix:
    """All five thresholds against all four levels, driven through config."""

    @pytest.mark.parametrize("threshold", sorted(THRESHOLD_QUALIFYING_LEVELS))
    @pytest.mark.parametrize("level", ALL_SARIF_LEVELS)
    def test_matches_the_exit_code_qualifying_levels(self, tmp_path, level, threshold):
        qualifies = level in THRESHOLD_QUALIFYING_LEVELS[threshold]
        expected = "actionable" if qualifies else "below-threshold"
        actual = _outcome(_render_from_config(tmp_path, level, threshold))
        assert actual == expected, (
            f"threshold={threshold} level={level}: exit code says "
            f"{'qualifying' if qualifies else 'below threshold'}, "
            f"reporter says {actual}"
        )

    def test_both_outcomes_occur(self, tmp_path):
        """Guards against a matrix that is uniformly one value."""
        outcomes = {
            _outcome(_render_from_config(tmp_path, lvl, t))
            for t in THRESHOLD_QUALIFYING_LEVELS
            for lvl in ALL_SARIF_LEVELS
        }
        assert outcomes == {"actionable", "below-threshold"}


class TestIssueSeverityWinsOverLevel:
    """properties.issue_severity decides where a scanner emits it.

    Same precedence as count_actionable_results (aggregation.py:505-513) and the
    exit code (run_ash_scan.py:1098-1106). It is load-bearing because SARIF has
    four levels for ASH's five severities: `error` covers CRITICAL and HIGH.
    """

    def test_high_issue_severity_is_below_a_critical_threshold(self, tmp_path):
        """Judged from level `error` alone this would be actionable."""
        testcase = _render_from_config(
            tmp_path, level="error", threshold="CRITICAL", issue_severity="HIGH"
        )
        assert _outcome(testcase) == "below-threshold"

    def test_critical_issue_severity_is_actionable_at_a_critical_threshold(
        self, tmp_path
    ):
        """The other side of the same cell, so the test above cannot pass by
        gating everything off."""
        testcase = _render_from_config(
            tmp_path, level="error", threshold="CRITICAL", issue_severity="CRITICAL"
        )
        assert _outcome(testcase) == "actionable"

    def test_an_unrecognised_issue_severity_falls_back_to_the_level(self, tmp_path):
        """Checkov omits issue_severity, so the level path must stay live."""
        testcase = _render_from_config(
            tmp_path, level="note", threshold="MEDIUM", issue_severity="not-a-severity"
        )
        assert _outcome(testcase) == "below-threshold"


class TestPerResultPropertyStillOverridesConfig:
    """The config is the default, not the only source."""

    def test_property_threshold_beats_the_configured_threshold(self, tmp_path):
        """A result-level ALL keeps a `none` finding actionable under MEDIUM."""
        result = _make_result(
            level="none", scanner_name="bandit", severity_threshold="ALL"
        )
        model = _make_model(runs=[_make_run(results=[result])])
        model.ash_config.global_settings.severity_threshold = "MEDIUM"
        output = _get_reporter(tmp_path).report(model)
        testcase = ET.fromstring(output).find(".//testcase")  # nosec B314
        assert _outcome(testcase) == "actionable"

    def test_below_threshold_property_beats_a_qualifying_level(self, tmp_path):
        """An explicit below_threshold still short-circuits the gate."""
        result = _make_result(
            level="error", scanner_name="bandit", below_threshold=True
        )
        model = _make_model(runs=[_make_run(results=[result])])
        model.ash_config.global_settings.severity_threshold = "MEDIUM"
        output = _get_reporter(tmp_path).report(model)
        testcase = ET.fromstring(output).find(".//testcase")  # nosec B314
        assert _outcome(testcase) == "below-threshold"


class TestOptOutStillBypassesTheGate:
    """respect_severity_threshold=False must ignore the config threshold too.

    The opt-out was previously easy to satisfy by accident: with the gate dead,
    disabling it changed nothing. Now that the gate is live, this is a real
    assertion.
    """

    def test_disabled_option_reports_a_sub_threshold_finding_as_an_error(
        self, tmp_path
    ):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            JUnitXMLReporterConfig,
            JUnitXMLReporterConfigOptions,
        )

        config = JUnitXMLReporterConfig(
            options=JUnitXMLReporterConfigOptions(respect_severity_threshold=False)
        )
        result = _make_result(level="note", scanner_name="bandit")
        model = _make_model(runs=[_make_run(results=[result])])
        model.ash_config.global_settings.severity_threshold = "CRITICAL"
        output = _get_reporter(tmp_path, config=config).report(model)
        testcase = ET.fromstring(output).find(".//testcase")  # nosec B314
        assert _outcome(testcase) == "actionable"


class TestConfiguredSeverityThresholdHelper:
    """The threshold source itself, read directly.

    Asserting on the helper as well as through the reporter is deliberate: a
    reporter-only test cannot distinguish "read the config" from "happened to
    agree with the config's default".
    """

    def test_reads_global_settings(self, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            _configured_severity_threshold,
        )

        model = _make_model()
        model.ash_config.global_settings.severity_threshold = "HIGH"
        assert _configured_severity_threshold(model) == "HIGH"

    def test_upper_cases_the_value(self):
        """The ladder is case-sensitive and reads an unrecognised value as
        CRITICAL, so a lowercase threshold would silently loosen the gate."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            _configured_severity_threshold,
        )

        class _Settings:
            severity_threshold = "low"

        class _Config:
            global_settings = _Settings()

        class _Model:
            ash_config = _Config()

        assert _configured_severity_threshold(_Model()) == "LOW"

    def test_falls_back_to_a_threshold_the_ladder_recognises(self):
        """With no config, the result must be a VALID threshold, not merely the constant.

        This test used to assert equality with ``ASH_DEFAULT_SEVERITY_LEVEL``,
        which could not fail for the reason that matters: it compared the
        function against the same constant the function reads, so it pinned
        *which* constant was used and said nothing about whether the value was
        usable. ``ASH_DEFAULT_SEVERITY_LEVEL`` is an unvalidated
        ``os.environ.get``, and the ladder reads an unrecognised threshold as
        CRITICAL -- so ``ASH_DEFAULT_SEVERITY_LEVEL=INFO``, a plausible way to
        ask for "report everything", would have produced the strictest gate in
        the codebase and this assertion would still have passed.

        Membership in ``SEVERITY_THRESHOLDS`` is the property that actually
        protects the gate.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            _configured_severity_threshold,
        )
        from automated_security_helper.utils.severity_ladder import (
            SEVERITY_THRESHOLDS,
        )

        class _Model:
            ash_config = None

        assert _configured_severity_threshold(_Model()) in SEVERITY_THRESHOLDS

    def test_an_unrecognised_threshold_is_coerced_to_all_not_to_critical(self):
        """The dangerous direction, pinned.

        An unrecognised threshold reaches the ladder as CRITICAL, the strictest
        gate, so a typo silently hides findings. Coercing to ALL fails toward
        reporting instead. Asserting ALL specifically rather than just "valid" is
        the point: CRITICAL is also valid and would satisfy a weaker assertion
        while being exactly the wrong answer.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            _configured_severity_threshold,
        )

        class _Settings:
            severity_threshold = "INFO"  # plausible, and not a valid threshold

        class _Config:
            global_settings = _Settings()

        class _Model:
            ash_config = _Config()

        assert _configured_severity_threshold(_Model()) == "ALL"

    def test_an_unrecognised_per_result_property_falls_back_to_config(self, tmp_path):
        """A bad per-result threshold must not gate like CRITICAL either."""
        result = _make_result(
            level="note", scanner_name="bandit", severity_threshold="INFO"
        )
        model = _without_scanner_thresholds(
            _make_model(runs=[_make_run(results=[result])])
        )
        model.ash_config.global_settings.severity_threshold = "ALL"
        output = _get_reporter(tmp_path).report(model)
        testcase = ET.fromstring(output).find(".//testcase")  # nosec B314
        # Under ALL a `note` is actionable. Had "INFO" reached the ladder it would
        # have gated like CRITICAL and skipped this finding.
        assert _outcome(testcase) == "actionable"


class TestScannerThresholdIsRead:
    """A scanner's own ``options.severity_threshold`` governs its findings.

    The exit code resolves the threshold per result's scanner through
    ``ScannerStatisticsCalculator.get_scanner_threshold_info``; the reporter
    read ``global_settings.severity_threshold`` for every result, so a finding
    the exit code ignored under a scanner's CRITICAL override was still an
    ``<error>`` here (and the reverse under a scanner's LOW override).
    """

    @staticmethod
    def _render(tmp_path, scanner_name, level, scanner_threshold):
        result = _make_result(level=level, scanner_name=scanner_name)
        model = _without_scanner_thresholds(
            _make_model(runs=[_make_run(results=[result])])
        )
        model.ash_config.global_settings.severity_threshold = "MEDIUM"
        model.ash_config.scanners.bandit.options.severity_threshold = scanner_threshold
        output = _get_reporter(tmp_path).report(model)
        return ET.fromstring(output).find(".//testcase")  # nosec B314

    def test_a_scanner_relaxed_to_critical_skips_its_warning_finding(self, tmp_path):
        """At the base this was ``<error>``: MEDIUM graded a warning actionable."""
        testcase = self._render(tmp_path, "bandit", "warning", "CRITICAL")
        assert _outcome(testcase) == "below-threshold"

    def test_a_scanner_tightened_to_low_reports_its_note_finding(self, tmp_path):
        """At the base this was skipped: MEDIUM graded a note below threshold."""
        testcase = self._render(tmp_path, "bandit", "note", "LOW")
        assert _outcome(testcase) == "actionable"

    def test_another_scanner_keeps_the_global_threshold(self, tmp_path):
        """The control: bandit's override reaches bandit's findings only."""
        testcase = self._render(tmp_path, "semgrep", "warning", "CRITICAL")
        assert _outcome(testcase) == "actionable"

    @staticmethod
    def _render_cdk_nag(tmp_path, level, scanner_threshold):
        """A finding of the hyphenated scanner ``cdk-nag``, whose configuration
        section is the underscored ``cdk_nag``."""
        result = _make_result(level=level, scanner_name="cdk-nag")
        model = _without_scanner_thresholds(
            _make_model(runs=[_make_run(results=[result])])
        )
        model.ash_config.global_settings.severity_threshold = "MEDIUM"
        model.ash_config.scanners.cdk_nag.options.severity_threshold = scanner_threshold
        # The resolver the exit code uses finds the section under the hyphenated
        # name; a reporter that looked the section up by the name as written
        # would read the global threshold instead.
        resolved = ScannerStatisticsCalculator.get_scanner_threshold_info(
            model, "cdk-nag"
        )
        assert resolved == (scanner_threshold, "config"), resolved
        output = _get_reporter(tmp_path).report(model)
        return ET.fromstring(output).find(".//testcase")  # nosec B314

    def test_a_hyphenated_scanner_name_finds_its_underscored_section(self, tmp_path):
        """The mapping a separate lookup would get wrong: cdk-nag relaxed to
        CRITICAL skips its warning finding, which the global MEDIUM would
        have reported."""
        testcase = self._render_cdk_nag(tmp_path, "warning", "CRITICAL")
        assert _outcome(testcase) == "below-threshold"

    def test_a_hyphenated_scanner_tightened_to_low_reports_its_note(self, tmp_path):
        """The other direction, so the case above cannot pass by skipping every
        cdk-nag finding."""
        testcase = self._render_cdk_nag(tmp_path, "note", "LOW")
        assert _outcome(testcase) == "actionable"


class TestActionableSubErrorFindingsAreNotSilentlyPassed:
    """The last silent-pass path in this reporter, and the one case it must keep.

    The emit cascade covers level `error`, kind `fail`, and level `warning`. An
    actionable finding at `note` or `none` whose kind is not `fail` matched none
    of them and fell through with no result element -- which renders as a passing
    test case. The reporter would decide a finding was actionable and then
    publish it as a pass.

    The fix is gated on `kind` rather than applied to every leftover, because
    `kind` is what distinguishes a finding from the absence of one. cdk-nag emits
    level `none` with kind `informational` for a COMPLIANT check, and erroring on
    that would report passed controls as problems -- turning a clean compliance
    scan red under a threshold of ALL, the opposite of the fix's intent.
    """

    @pytest.mark.parametrize("kind", ["open", "review"])
    @pytest.mark.parametrize("level", ["note", "none"])
    def test_a_finding_kind_is_reported_not_passed(self, tmp_path, level, kind):
        testcase = _render_kind(tmp_path, level=level, threshold="ALL", kind=kind)
        error = testcase.find("error")
        assert error is not None, (
            f"level={level} kind={kind} is actionable under ALL and asserts a "
            "finding, so it must not render as a bare passing test case"
        )
        assert error.get("type") == "note"
        assert testcase.find("failure") is None

    @pytest.mark.parametrize("kind", ["pass", "informational"])
    @pytest.mark.parametrize("level", ["note", "none"])
    def test_a_non_finding_kind_stays_a_passing_testcase(self, tmp_path, level, kind):
        """The control that keeps the arm above from being over-broad."""
        testcase = _render_kind(tmp_path, level=level, threshold="ALL", kind=kind)
        assert testcase.find("error") is None
        assert testcase.find("failure") is None
        assert testcase.find("skipped") is None

    @pytest.mark.parametrize("threshold", ["ALL", "MEDIUM"])
    @pytest.mark.parametrize("level", ["none", "note", "warning", "error"])
    def test_a_not_applicable_result_is_skipped_not_passed(
        self, tmp_path, level, threshold
    ):
        """SARIF ``notApplicable`` says the rule was NOT evaluated.

        cdk-nag writes it, with level ``none``, for a rule that raised instead
        of reaching an answer, and the exit code fails the scan for that rule
        through the run-level notification. The reporter used to render the
        result as a bare passing test case, so the JUnit artefact said the rule
        passed while the process status said it was never evaluated. Skipped is
        JUnit's own word for a test that did not run.

        The reading does not depend on the gate or the level. A first fix put
        the arm inside the actionable branch, so under the default MEDIUM gate
        a cdk-nag ``none`` result read "below configured severity threshold"
        and a ``warning`` or ``error`` one was reported as an error: a severity
        for a rule that was never run.
        """
        testcase = _render_kind(
            tmp_path, level=level, threshold=threshold, kind="notApplicable"
        )
        assert testcase.find("error") is None
        assert testcase.find("failure") is None
        skipped = testcase.find("skipped")
        assert skipped is not None
        assert skipped.get("type") == "not-evaluated"
        assert skipped.get("message") == "Rule was not evaluated for this target"

    @pytest.mark.parametrize("level", ["none", "warning", "error"])
    def test_a_not_applicable_result_is_skipped_with_the_gate_off(
        self, tmp_path, level
    ):
        """``respect_severity_threshold=False`` turns the severity gate off, and
        a result that was never evaluated has no severity to gate. A check placed
        inside the threshold-respecting path would, with the gate off, report a
        ``notApplicable`` result at ``warning`` or ``error`` as an error."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            JUnitXMLReporterConfig,
            JUnitXMLReporterConfigOptions,
        )

        config = JUnitXMLReporterConfig(
            options=JUnitXMLReporterConfigOptions(respect_severity_threshold=False)
        )
        result = _make_result(level=level, scanner_name="cdk-nag")
        result.kind = "notApplicable"
        model = _without_scanner_thresholds(
            _make_model(runs=[_make_run(results=[result])])
        )
        model.ash_config.global_settings.severity_threshold = "MEDIUM"

        output = _get_reporter(tmp_path, config=config).report(model)

        testcase = ET.fromstring(output).find(".//testcase")  # nosec B314
        assert testcase.find("error") is None
        assert testcase.find("failure") is None
        skipped = testcase.find("skipped")
        assert skipped is not None
        assert skipped.get("type") == "not-evaluated"

    def test_a_suppression_in_effect_wins_over_not_applicable(self, tmp_path):
        """Two reasons to skip, one case: the suppression's, because the
        operator accepted that finding."""
        from automated_security_helper.schemas.sarif_schema_model import Suppression

        result = _make_result(
            level="none",
            scanner_name="cdk-nag",
            suppressions=[Suppression(kind="inSource", justification="accepted")],
        )
        result.kind = "notApplicable"
        model = _without_scanner_thresholds(
            _make_model(runs=[_make_run(results=[result])])
        )
        model.ash_config.global_settings.severity_threshold = "MEDIUM"

        output = _get_reporter(tmp_path).report(model)

        testcase = ET.fromstring(output).find(".//testcase")  # nosec B314
        skipped = testcase.find("skipped")
        assert skipped is not None
        assert skipped.get("type") == "suppression"
        assert skipped.get("message") == "accepted"

    def test_cdk_nag_compliant_check_is_not_reported_as_a_problem(self, tmp_path):
        """cdk-nag's real compliant shape, named explicitly.

        ``cdk_nag_wrapper._level_and_kind`` returns ``(Level.none,
        Kind.informational)`` for a check whose compliance is anything but
        Non-Compliant. Under a threshold of ALL that finding is actionable, so it
        is exactly the case a blanket error arm would have broken.
        """
        from automated_security_helper.schemas.sarif_schema_model import Kind, Level

        testcase = _render_kind(
            tmp_path, level=Level.none, threshold="ALL", kind=Kind.informational
        )
        assert testcase.find("error") is None
        assert testcase.find("skipped") is None

    def test_below_threshold_still_wins_over_the_new_arm(self, tmp_path):
        """The new arm sits inside `if is_actionable`, so the gate still precedes it."""
        testcase = _render_kind(tmp_path, level="note", threshold="MEDIUM", kind="open")
        assert _outcome(testcase) == "below-threshold"
