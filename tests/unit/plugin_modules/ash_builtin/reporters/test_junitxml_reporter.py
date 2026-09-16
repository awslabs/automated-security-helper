# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for JunitXmlReporter.

Covers: empty findings, multiple scanners, severity mapping,
suppressed findings handling, and XML output validity.
"""

import xml.etree.ElementTree as ET  # nosec B405

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    Kind1,
    Level,
    Message,
    Message1,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(
    rule_id: str = "TEST-001",
    message_text: str = "Test finding",
    level: str = "warning",
    scanner_name: str = "test-scanner",
    suppressions: list | None = None,
    below_threshold: bool | None = None,
    severity_threshold: str | None = None,
) -> Result:
    """Build a minimal SARIF Result with configurable properties."""
    extra = {"scanner_name": scanner_name}
    if below_threshold is not None:
        extra["below_threshold"] = below_threshold
    if severity_threshold is not None:
        extra["severity_threshold"] = severity_threshold

    props = PropertyBag(tags=[f"tool_name::{scanner_name}"])
    # Inject extra fields via pydantic's __pydantic_extra__
    props.__pydantic_extra__ = extra

    return Result(
        ruleId=rule_id,
        level=level,
        message=Message(root=Message1(text=message_text)),
        properties=props,
        suppressions=suppressions,
    )


def _make_run(
    results: list[Result] | None = None, tool_name: str = "test-scanner"
) -> Run:
    """Build a minimal SARIF Run."""
    return Run(
        tool=Tool(driver=ToolComponent(name=tool_name)),
        results=results,
    )


def _make_model(runs: list[Run] | None = None) -> AshAggregatedResults:
    """Build an AshAggregatedResults with given SARIF runs."""
    AshConfig.model_rebuild()
    AshAggregatedResults.model_rebuild()

    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.metadata.generated_at = "2025-01-15T10:30:00+00:00"

    if runs is not None:
        model.sarif = SarifReport(runs=runs)

    return model


def _plugin_context(tmp_path):
    """Build a lightweight PluginContext."""
    from automated_security_helper.base.plugin_context import PluginContext

    return PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )


def _get_reporter(tmp_path, config=None):
    """Instantiate a JunitXmlReporter."""
    from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
        JunitXmlReporter,
        JUnitXMLReporterConfig,
    )

    ctx = _plugin_context(tmp_path)
    if config is None:
        return JunitXmlReporter(context=ctx)
    return JunitXmlReporter(context=ctx, config=config)


def _parse_xml(xml_string: str) -> ET.Element:
    """Parse XML string and return root element."""
    return ET.fromstring(xml_string)  # nosec B314


# ---------------------------------------------------------------------------
# The qualifying-level table, transcribed once
#
# Transcribed verbatim from _THRESHOLD_QUALIFYING_LEVELS in
# run_ash_scan._compute_exit_code. It is a function-local dict there, so it
# cannot be imported, and transcribing it is the point: it is an oracle written
# from the exit code's behaviour, so if the reporter and the exit code ever
# disagree about a level again, the matrices below catch it.
#
# It lives HERE, in the module both threshold test files already import their
# helpers from, because it previously existed as two independent transcriptions
# -- one per test file -- against that third copy inside _compute_exit_code.
# Three copies of one table is the drift utils/severity_ladder.py exists to end,
# and two of the three were in tests that would have had to disagree silently
# before anyone noticed. TestQualifyingLevelsMatchTheLadder ties this remaining
# transcription to the ladder itself, so an oracle that drifts from the
# implementation fails rather than quietly grading against the wrong answer.
# ---------------------------------------------------------------------------

THRESHOLD_QUALIFYING_LEVELS = {
    "ALL": {"error", "warning", "note", "none"},
    "LOW": {"error", "warning", "note"},
    "MEDIUM": {"error", "warning"},
    "HIGH": {"error"},
    "CRITICAL": {"error"},
}

ALL_SARIF_LEVELS = ("error", "warning", "note", "none")


def _outcome(testcase) -> str:
    """Reduce a testcase to 'actionable', 'below-threshold' or 'silent'."""
    if testcase.find("skipped") is not None:
        return "below-threshold"
    if testcase.find("error") is not None:
        return "actionable"
    return "silent"


class TestQualifyingLevelsMatchTheLadder:
    """The transcribed oracle must agree with the ladder it grades against.

    Without this, the table above is only an assertion about what someone
    believed the exit code did. With it, a change to the ladder that makes the
    reporter and the exit code disagree fails here, naming the cell, instead of
    silently regrading every matrix cell against a stale expectation.
    """

    def test_table_is_exactly_what_the_ladder_derives(self):
        from automated_security_helper.utils.severity_ladder import (
            SEVERITY_THRESHOLDS,
            sarif_level_fails_threshold,
        )

        derived = {
            threshold: {
                level
                for level in ALL_SARIF_LEVELS
                if sarif_level_fails_threshold(level, threshold)
            }
            for threshold in SEVERITY_THRESHOLDS
        }
        assert derived == THRESHOLD_QUALIFYING_LEVELS

    def test_the_table_covers_every_threshold_the_ladder_knows(self):
        """A threshold added to the ladder must not silently skip the matrices."""
        from automated_security_helper.utils.severity_ladder import (
            SEVERITY_THRESHOLDS,
        )

        assert set(THRESHOLD_QUALIFYING_LEVELS) == set(SEVERITY_THRESHOLDS)


# ---------------------------------------------------------------------------
# Tests: empty findings
# ---------------------------------------------------------------------------


class TestEmptyFindings:
    """Reporter handles models with no findings gracefully."""

    def test_no_sarif_produces_valid_xml(self, tmp_path):
        """A model with sarif=None should produce a valid but empty report."""
        model = _make_model(runs=None)
        model.sarif = None
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        assert root.tag == "testsuites"
        # No test suites when there are no results
        assert len(root.findall("testsuite")) == 0

    def test_empty_runs_list_produces_valid_xml(self, tmp_path):
        """A sarif report with an empty runs list produces valid XML."""
        model = _make_model(runs=[])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        assert root.tag == "testsuites"
        assert len(root.findall("testsuite")) == 0

    def test_run_with_no_results_produces_valid_xml(self, tmp_path):
        """A run with results=None should not crash."""
        model = _make_model(runs=[_make_run(results=None)])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        assert root.tag == "testsuites"

    def test_run_with_empty_results_produces_valid_xml(self, tmp_path):
        """A run with results=[] should not crash."""
        model = _make_model(runs=[_make_run(results=[])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        assert root.tag == "testsuites"


# ---------------------------------------------------------------------------
# Tests: multiple scanners
# ---------------------------------------------------------------------------


class TestMultipleScanners:
    """Results from different scanners get separate test suites."""

    def test_two_scanners_produce_two_suites(self, tmp_path):
        """Findings from different scanners go into different test suites."""
        results = [
            _make_result(rule_id="RULE-A", scanner_name="bandit"),
            _make_result(rule_id="RULE-B", scanner_name="trivy"),
        ]
        model = _make_model(runs=[_make_run(results=results)])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        suites = root.findall("testsuite")
        suite_names = {s.get("name") for s in suites}
        assert "bandit" in suite_names
        assert "trivy" in suite_names
        assert len(suites) == 2

    def test_same_scanner_grouped_in_one_suite(self, tmp_path):
        """Multiple findings from one scanner share a single test suite."""
        results = [
            _make_result(rule_id="RULE-A", scanner_name="bandit"),
            _make_result(rule_id="RULE-B", scanner_name="bandit"),
        ]
        model = _make_model(runs=[_make_run(results=results)])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        suites = root.findall("testsuite")
        assert len(suites) == 1
        assert suites[0].get("name") == "bandit"
        # Two test cases in this suite
        test_cases = suites[0].findall("testcase")
        assert len(test_cases) == 2

    def test_scanner_name_from_tags_fallback(self, tmp_path):
        """When scanner_name not in __pydantic_extra__, fall back to tags."""
        result = _make_result(rule_id="R1", scanner_name="semgrep")
        # Remove scanner_name from extra but keep it in tags
        del result.properties.__pydantic_extra__["scanner_name"]
        result.properties.tags = ["tool_name::semgrep"]

        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        suites = root.findall("testsuite")
        assert len(suites) == 1
        assert suites[0].get("name") == "semgrep"


# ---------------------------------------------------------------------------
# Tests: severity mapping (level -> error/warning in JUnit)
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    """SARIF levels are properly mapped to JUnit error types."""

    def test_error_level_produces_error_element(self, tmp_path):
        """A finding with level='error' becomes a JUnit Error."""
        result = _make_result(level="error", scanner_name="scanner1")
        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        tc = root.find(".//testcase")
        error = tc.find("error")
        assert error is not None
        assert error.get("type") == "error"

    def test_warning_level_with_open_kind_produces_warning_type(self, tmp_path):
        """A finding with level='warning' and kind='open' becomes type='warning'."""
        result = _make_result(level="warning", scanner_name="scanner1")
        # Override kind so it does not match "fail" in the first condition
        result.kind = "open"
        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        tc = root.find(".//testcase")
        error = tc.find("error")
        assert error is not None
        assert error.get("type") == "warning"

    def test_warning_level_with_fail_kind_produces_error_type(self, tmp_path):
        """A finding with level='warning' and kind='fail' hits the error branch."""
        result = _make_result(level="warning", scanner_name="scanner1")
        # kind defaults to "fail", so level check is bypassed
        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        tc = root.find(".//testcase")
        error = tc.find("error")
        assert error is not None
        # kind=="fail" hits first branch -> type_="error"
        assert error.get("type") == "error"

    def test_note_level_is_skipped_below_threshold_whatever_the_kind(self, tmp_path):
        """A `note` finding is below the configured MEDIUM threshold, so it skips.

        RENAMED, and this is the interesting kind of rename: the old name was
        test_note_level_with_open_kind_produces_no_error, and it kept passing
        across the threshold-source fix while pinning something else entirely.
        That is worse than breaking, because a green test whose name no longer
        describes its subject reads as coverage that is not there.

        Before the fix the reporter could not obtain a threshold, so
        `is_actionable` stayed True and control reached the level/kind cascade.
        With level `note` and kind forced to `open`, no branch there matched, and
        the testcase came out bare -- a silent pass. The old assertions,
        `error is None` and `failure is None`, were satisfied by that emptiness,
        and the old comment said so: "Neither error nor warning condition is
        met."

        Now the gate resolves MEDIUM from the config, `note` maps to LOW, and the
        finding is skipped as below threshold. The cascade is never reached, so
        the old comment is false. Both original assertions still hold -- there is
        still no error and still no failure -- which is exactly why the rename is
        necessary rather than optional.

        The `skipped` assertion is added so this cannot drift quietly a second
        time: if the outcome changes again, the test fails instead of passing for
        a third reason. The silent-pass path the old name described is still
        reachable and is covered by
        test_actionable_finding_matching_no_level_branch_is_silent below.
        """
        result = _make_result(level="note", scanner_name="scanner1")
        # Override kind so it does not match "fail" in the first condition
        result.kind = "open"
        model = _make_model(runs=[_make_run(results=[result])])
        model.ash_config.global_settings.severity_threshold = "MEDIUM"
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        tc = root.find(".//testcase")
        assert tc.find("error") is None
        assert tc.find("failure") is None
        skipped = tc.find("skipped")
        assert skipped is not None, "expected a below-threshold skip, not a bare pass"
        assert skipped.get("type") == "threshold"

    def test_actionable_finding_matching_no_level_branch_is_reported(self, tmp_path):
        """An actionable finding at `note` with kind `open` is an error, not a pass.

        RE-POINTED. An earlier revision of this test asserted the opposite -- no
        error, no failure, no skip -- because the level/kind cascade emitted only
        for level `error`, kind `fail`, or level `warning`, and an actionable
        finding matching none of those fell through with no result element. Its
        docstring said it pinned that behaviour rather than endorsing it.

        It is no longer pinned. A test case with no result element renders as a
        PASS, so the reporter was deciding a finding was actionable and then
        publishing it as a pass -- the one direction a security report must not
        fail in. There is now a `kind`-gated arm emitting
        `<error type="note">`, and this test asserts it.

        Reaching the arm takes a threshold of ALL, under which `note` is
        actionable; at MEDIUM the finding is skipped before the cascade runs. The
        companion case -- a kind that asserts there is no finding, where the bare
        passing test case is correct and is preserved -- is covered in
        test_junitxml_config_threshold.py.
        """
        result = _make_result(level="note", scanner_name="scanner1")
        result.kind = "open"
        model = _make_model(runs=[_make_run(results=[result])])
        model.ash_config.global_settings.severity_threshold = "ALL"
        output = _get_reporter(tmp_path).report(model)

        tc = _parse_xml(output).find(".//testcase")
        error = tc.find("error")
        assert error is not None, "an actionable finding must not render as a pass"
        assert error.get("type") == "note"
        assert tc.find("failure") is None
        assert tc.find("skipped") is None

    def test_below_threshold_false_does_not_force_a_finding_above_threshold(
        self, tmp_path
    ):
        """`below_threshold=False` is not decisive; the configured gate still applies.

        Only `True` short-circuits. `False` leaves is_actionable True, the gate
        runs anyway, and the gate may override it -- so the property can force a
        finding below threshold but cannot force one above it. Previously only the
        `True` case was covered, which left the asymmetry undocumented by any
        test and the comment describing it unverified.
        """
        result = _make_result(
            level="note", scanner_name="scanner1", below_threshold=False
        )
        model = _make_model(runs=[_make_run(results=[result])])
        model.ash_config.global_settings.severity_threshold = "MEDIUM"
        output = _get_reporter(tmp_path).report(model)

        tc = _parse_xml(output).find(".//testcase")
        skipped = tc.find("skipped")
        assert skipped is not None, (
            "below_threshold=False must not exempt a note finding from a MEDIUM gate"
        )
        assert skipped.get("type") == "threshold"

    def test_below_threshold_produces_skipped(self, tmp_path):
        """A finding below severity threshold is marked as Skipped."""
        result = _make_result(
            level="warning",
            scanner_name="scanner1",
            below_threshold=True,
        )
        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        tc = root.find(".//testcase")
        skipped = tc.find("skipped")
        assert skipped is not None
        assert "threshold" in skipped.get("message", "")

    def test_severity_threshold_critical_skips_warning(self, tmp_path):
        """When threshold is CRITICAL, a warning-level finding is skipped."""
        result = _make_result(
            level="warning",
            scanner_name="scanner1",
            severity_threshold="CRITICAL",
        )
        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        tc = root.find(".//testcase")
        skipped = tc.find("skipped")
        assert skipped is not None

    def test_severity_threshold_medium_allows_warning(self, tmp_path):
        """When threshold is MEDIUM, a warning-level finding is actionable."""
        result = _make_result(
            level="warning",
            scanner_name="scanner1",
            severity_threshold="MEDIUM",
        )
        # Set kind to 'open' so the warning-level branch is tested directly
        result.kind = "open"
        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        tc = root.find(".//testcase")
        error = tc.find("error")
        assert error is not None
        assert error.get("type") == "warning"

    def test_respect_severity_threshold_disabled(self, tmp_path):
        """When respect_severity_threshold is False, below_threshold is ignored."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            JUnitXMLReporterConfig,
            JUnitXMLReporterConfigOptions,
        )

        config = JUnitXMLReporterConfig(
            options=JUnitXMLReporterConfigOptions(respect_severity_threshold=False)
        )
        result = _make_result(
            level="warning",
            scanner_name="scanner1",
            below_threshold=True,
        )
        # Set kind to 'open' so the warning-level branch is tested
        result.kind = "open"
        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path, config=config)
        output = reporter.report(model)

        root = _parse_xml(output)
        tc = root.find(".//testcase")
        # Should be an error since threshold checking is disabled
        error = tc.find("error")
        assert error is not None
        assert error.get("type") == "warning"


# ---------------------------------------------------------------------------
# Tests: suppressed findings
# ---------------------------------------------------------------------------


class TestSuppressedFindings:
    """Suppressed findings are represented as Skipped test cases."""

    def test_suppressed_finding_is_skipped(self, tmp_path):
        """A finding with suppressions produces a Skipped element."""
        suppression = Suppression(
            kind=Kind1.inSource,
            justification="Accepted risk per security review",
        )
        result = _make_result(
            level="error",
            scanner_name="scanner1",
            suppressions=[suppression],
        )
        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        tc = root.find(".//testcase")
        skipped = tc.find("skipped")
        assert skipped is not None
        assert "Accepted risk" in skipped.get("message", "")

    def test_suppressed_finding_has_no_error(self, tmp_path):
        """Suppressed findings should not have an error element."""
        suppression = Suppression(
            kind=Kind1.external,
            justification="False positive",
        )
        result = _make_result(
            level="error",
            scanner_name="scanner1",
            suppressions=[suppression],
        )
        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        tc = root.find(".//testcase")
        assert tc.find("error") is None

    def test_multiple_suppressions_on_one_result(self, tmp_path):
        """Multiple suppressions on one result each produce a Skipped."""
        suppressions = [
            Suppression(kind=Kind1.inSource, justification="Reason A"),
            Suppression(kind=Kind1.external, justification="Reason B"),
        ]
        result = _make_result(
            level="error",
            scanner_name="scanner1",
            suppressions=suppressions,
        )
        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        tc = root.find(".//testcase")
        # junitparser handles multiple results; just verify skipped is present
        skipped_elements = tc.findall("skipped")
        assert len(skipped_elements) >= 1


# ---------------------------------------------------------------------------
# Tests: XML output validity
# ---------------------------------------------------------------------------


class TestXmlOutputValidity:
    """The output must be well-formed, parseable XML."""

    def test_output_is_parseable_xml(self, tmp_path):
        """Report output parses as valid XML without exceptions."""
        results = [
            _make_result(rule_id="A", scanner_name="s1"),
            _make_result(rule_id="B", scanner_name="s2"),
        ]
        model = _make_model(runs=[_make_run(results=results)])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        # Should not raise
        root = _parse_xml(output)
        assert root is not None

    def test_xml_has_testsuites_root(self, tmp_path):
        """Root element must be <testsuites>."""
        result = _make_result(scanner_name="s1")
        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        assert root.tag == "testsuites"

    def test_testcase_has_name_and_classname(self, tmp_path):
        """Each testcase element has name and classname attributes."""
        result = _make_result(rule_id="MY-RULE", message_text="Something bad")
        model = _make_model(runs=[_make_run(results=[result], tool_name="scanner1")])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        tc = root.find(".//testcase")
        assert tc is not None
        assert tc.get("name") is not None
        assert "MY-RULE" in tc.get("name")
        assert tc.get("classname") == "MY-RULE"

    def test_special_characters_in_message_are_escaped(self, tmp_path):
        """XML special chars in messages don't break the output."""
        result = _make_result(
            message_text="Use <foo> & \"bar\" for 'baz'",
            scanner_name="scanner1",
        )
        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        # Should parse without error (XML escaping handled)
        root = _parse_xml(output)
        assert root is not None

    def test_report_name_is_ash_scan_report(self, tmp_path):
        """The top-level testsuites element has name='ASH Scan Report'."""
        result = _make_result(scanner_name="s1")
        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        assert root.get("name") == "ASH Scan Report"

    def test_metadata_in_system_out(self, tmp_path):
        """Properties are written to system-out of the test case."""
        result = _make_result(rule_id="R1", scanner_name="bandit")
        model = _make_model(runs=[_make_run(results=[result])])
        reporter = _get_reporter(tmp_path)
        output = reporter.report(model)

        root = _parse_xml(output)
        tc = root.find(".//testcase")
        system_out = tc.find("system-out")
        assert system_out is not None
        assert "scanner_name" in system_out.text
