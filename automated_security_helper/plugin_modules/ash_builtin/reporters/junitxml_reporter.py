# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL
from automated_security_helper.models.flat_vulnerability import (
    extract_workspace_project,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.severity_ladder import (
    SEVERITIES,
    SEVERITY_THRESHOLDS,
    sarif_level_fails_threshold,
    severity_fails_threshold,
)


import defusedxml
import warnings


# SARIF `kind` values that assert a finding exists. `fail` is handled earlier by
# the level cascade; `open` and `review` reach the arm below.
_FINDING_KINDS = frozenset({"fail", "open", "review"})

# SARIF `kind` values that assert the opposite -- the rule ran and there is
# nothing to report. cdk-nag uses `informational` for a COMPLIANT check
# (cdk_nag_wrapper._level_and_kind), so rendering these as anything but a
# passing test case would report a passed control as a problem.
_NON_FINDING_KINDS = frozenset({"pass", "informational", "notApplicable"})


def _normalized_threshold(value: object) -> str | None:
    """Upper-case *value* if it names a threshold the ladder recognises, else None.

    One validation point for both threshold sources. Returning None for an
    unrecognised value rather than passing it through matters because the ladder
    reads an unknown threshold as CRITICAL, which is the strictest gate -- so a
    typo silently hides findings instead of surfacing an error.
    """
    if not value:
        return None
    upper = str(value).upper()
    return upper if upper in SEVERITY_THRESHOLDS else None


def _configured_severity_threshold(model: "AshAggregatedResults") -> str:
    """The severity threshold this scan was configured with.

    Read from ``global_settings.severity_threshold``, which is where the gate
    actually lives. This is the same field the exit code reads
    (``run_ash_scan._compute_exit_code``) and the same one
    ``ReportContentEmitter`` reads, so the report and the exit code cannot
    describe different runs.

    Upper-cased because the ladder in ``utils.severity_ladder`` is
    case-SENSITIVE and ``_compute_exit_code`` upper-cases too. Without it a
    lowercase value would gate like CRITICAL here and MEDIUM there. The field is
    a ``Literal`` of upper-case names today, so this is defensive rather than
    load-bearing -- but it is load-bearing the moment anything sets the field
    from outside that Literal, which a per-project workspace threshold would do.

    Validated against ``SEVERITY_THRESHOLDS`` rather than trusted, and this is
    the interesting part. With no config the value comes from
    ``ASH_DEFAULT_SEVERITY_LEVEL``, which is an unvalidated
    ``os.environ.get(..., "MEDIUM")``. The ladder reads an *unrecognised*
    threshold as CRITICAL, so an operator who sets
    ``ASH_DEFAULT_SEVERITY_LEVEL=INFO`` meaning "report everything" would get the
    strictest possible gate and see every finding below ``error`` silently
    skipped -- a failure in the dangerous direction, from a plausible mistake,
    with nothing in the output to say it happened.

    An unrecognised value is therefore coerced to ``ALL`` with a warning rather
    than passed through. ``ALL`` is chosen over raising because a reporter that
    throws mid-report loses the whole artefact, and over ``MEDIUM`` because when
    the configuration is not understood the safe reading is to report everything
    and let a human filter, not to silently drop findings.
    """
    threshold = ASH_DEFAULT_SEVERITY_LEVEL
    config = getattr(model, "ash_config", None)
    if config is not None and getattr(
        getattr(config, "global_settings", None), "severity_threshold", None
    ):
        threshold = config.global_settings.severity_threshold

    normalized = _normalized_threshold(threshold)
    if normalized is None:
        ASH_LOGGER.warning(
            "Unrecognised severity threshold %r; the JUnit XML report will treat "
            "every finding as actionable (ALL) rather than apply an unknown gate. "
            "Valid values are: %s.",
            threshold,
            ", ".join(SEVERITY_THRESHOLDS),
        )
        return "ALL"
    return normalized


class JUnitXMLReporterConfigOptions(ReporterOptionsBase):
    # Consider findings as failures only if they're at or above the scanner's severity threshold
    respect_severity_threshold: bool = True


class JUnitXMLReporterConfig(ReporterPluginConfigBase):
    name: Literal["junitxml"] = "junitxml"
    extension: str = "junit.xml"
    enabled: bool = True
    options: JUnitXMLReporterConfigOptions = JUnitXMLReporterConfigOptions()


@ash_reporter_plugin
class JunitXmlReporter(ReporterPluginBase[JUnitXMLReporterConfig]):
    """Formats results as JUnitXML.

    Workspace mode: one merged artefact, with the project in the testsuite name
    as ``<project>/<scanner>``.

    A deliberate deviation from the RFC, which said the project *becomes* the
    testsuite name. Taken literally that discards the per-scanner grouping
    single-directory mode has, and every CI front end that renders JUnit XML
    groups by suite name -- so a reader would lose the ability to see that
    bandit failed and checkov did not. The compound name costs nothing, keeps
    the project as the primary sort key (it is the leading segment, so suites
    for one project sort together), and makes the workspace artefact a strict
    refinement of the per-project ones rather than a lossy reshape of them.

    A single-directory scan is unaffected: with no project attribution the suite
    name stays the bare scanner name it has always been.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        with warnings.catch_warnings():
            defusedxml.defuse_stdlib()
        if self.config is None:
            self.config = JUnitXMLReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model in JUnitXML.

        Creates a test suite for each finding type, with individual findings as test cases.
        Failed findings are represented as failed tests with appropriate error messages.
        """
        from junitparser import (
            Error,
            JUnitXml,
            Skipped,
            TestCase,
            TestSuite,
        )

        report = JUnitXml(name="ASH Scan Report")

        test_suite_dict = {}

        # Read once: the threshold is a property of the scan, not of a finding.
        configured_threshold = _configured_severity_threshold(model)

        # Process SARIF report @ model.sarif
        if model.sarif is not None:
            all_results = model.sarif.get_all_results()
            for result in all_results:
                # Create test case name from SARIF result details
                test_name = (
                    f"{result.message.root.text} [{result.ruleId}]"
                    if result.ruleId
                    else result.message.root.text
                )
                test_case = TestCase(
                    name=test_name,
                    classname=result.ruleId,
                )
                props = result.properties

                # Add failure details for failed findings
                if result.suppressions and len(result.suppressions) > 0:
                    test_case.result = [
                        Skipped(
                            message=suppression.justification,
                            type_="suppression",
                        )
                        for suppression in result.suppressions
                    ]
                else:
                    # Determine if finding is actionable based on severity threshold
                    is_actionable = True

                    # An explicit below_threshold property is consulted first,
                    # but only `True` is decisive: it sets is_actionable False,
                    # which makes the `if is_actionable and ...` gate below
                    # short-circuit. `False` is *not* decisive -- it leaves
                    # is_actionable True, the gate runs anyway, and the gate may
                    # override it back to False. So the property can force a
                    # finding below threshold but cannot force one above it.
                    #
                    # That asymmetry is deliberate rather than tidy: this arm can
                    # only ever mark a finding as needing no attention, so a
                    # producer that writes it cannot use it to suppress the
                    # configured gate and smuggle a sub-threshold finding back in
                    # as an error.
                    #
                    # Read with getattr because pydantic's extra="allow" exposes
                    # extras as attributes, so the older
                    # hasattr-then-__pydantic_extra__ pair had an unreachable
                    # second branch. Nothing in ASH writes this property -- both
                    # readers, here and in bedrock_summary_reporter, have no
                    # writer -- so in a real scan this leaves is_actionable alone
                    # and the gate below decides.
                    if self.config.options.respect_severity_threshold and props:
                        below_threshold = getattr(props, "below_threshold", None)
                        if below_threshold is not None:
                            is_actionable = not below_threshold

                    if is_actionable and self.config.options.respect_severity_threshold:
                        # The threshold comes from the scan's configuration, not
                        # from the finding.
                        #
                        # This is the fix. The reporter used to read the
                        # threshold *only* from properties.severity_threshold --
                        # a property nothing in ASH writes. So `threshold` was
                        # None for every real finding, the guard below
                        # short-circuited, is_actionable kept its initializer of
                        # True, and the Skipped branch was unreachable outside
                        # tests that injected the property themselves. Every
                        # sub-threshold finding was reported as a failure: a
                        # level of `note` or `none` still reached `<error>`
                        # because `result.kind` defaults to Kind.fail, which
                        # satisfies the kind check below before level is ever
                        # consulted. Bandit's LOW findings are SARIF `note`,
                        # which is how a clean scan came back red in CI.
                        #
                        # A per-result property still wins where one is present,
                        # since a finding-level statement is more specific than a
                        # scan-level default; it is simply no longer the only
                        # source.
                        threshold = (
                            _normalized_threshold(
                                getattr(props, "severity_threshold", None)
                            )
                            or configured_threshold
                        )

                        # The gate lives in utils.severity_ladder, shared with
                        # ScanResultsContainer.determine_status and matching the
                        # qualifying-level table the exit code uses, so the
                        # reporter cannot call a finding actionable that the exit
                        # code ignores.
                        #
                        # properties.issue_severity decides when a scanner emits
                        # a severity ASH recognises, and the SARIF level decides
                        # otherwise -- the same precedence, in the same order, as
                        # count_actionable_results (aggregation.py:505-513) and
                        # the exit code (run_ash_scan.py:1098-1106). It matters
                        # because SARIF has four levels for ASH's five
                        # severities: `error` covers CRITICAL and HIGH, so a HIGH
                        # finding judged from its level alone is actionable even
                        # under a CRITICAL threshold. Checkov is the one shipped
                        # scanner that omits issue_severity, and it stays gated
                        # through the level path.
                        #
                        # No `threshold and ...` guard here. Earlier revisions had
                        # one, to stop a falsy threshold reaching the ladder as
                        # "no gate configured" and marking a whole scan below
                        # threshold. That case is now impossible at the source:
                        # _normalized_threshold rejects every value the ladder
                        # would not recognise, including the empty string, and
                        # _configured_severity_threshold substitutes ALL. Keeping
                        # a second guard here would mean neither was exercised.
                        issue_severity = str(
                            getattr(props, "issue_severity", "") or ""
                        ).upper()
                        if issue_severity in SEVERITIES:
                            is_actionable = severity_fails_threshold(
                                issue_severity, threshold
                            )
                        else:
                            is_actionable = sarif_level_fails_threshold(
                                result.level, threshold
                            )

                    # Only mark as error if it's actionable
                    if is_actionable:
                        if result.level == "error" or result.kind == "fail":
                            test_case.result = [
                                Error(message=result.message.root.text, type_="error")
                            ]
                        elif result.level == "warning":
                            test_case.result = [
                                Error(message=result.message.root.text, type_="warning")
                            ]
                        elif result.kind in _FINDING_KINDS:
                            # An actionable finding at `note` or `none` whose kind
                            # still asserts a finding -- `open` or `review`. Before
                            # this arm existed it fell out of the cascade with no
                            # result element at all, which renders as a PASSING
                            # test case: the reporter would decide a finding was
                            # actionable and then publish it as a pass. That is the
                            # one direction a security report must not fail in.
                            #
                            # Deliberately not extended to every kind. `pass`,
                            # `informational` and `notApplicable` assert the
                            # opposite -- the rule ran and found nothing -- and
                            # cdk-nag uses `informational` with level `none` for a
                            # COMPLIANT check (cdk_nag_wrapper._level_and_kind).
                            # Erroring on those would report passed controls as
                            # problems, which is how a threshold of ALL would turn
                            # a clean compliance scan red.
                            #
                            # `Error` rather than `Failure` because the module
                            # imports only Error and Skipped; type_ carries the
                            # distinction, as it already does for `warning`.
                            test_case.result = [
                                Error(message=result.message.root.text, type_="note")
                            ]
                        # Any remaining kind is a non-finding (_NON_FINDING_KINDS)
                        # and keeps its bare, passing test case.
                    else:
                        # Mark as skipped if below threshold
                        test_case.result = [
                            Skipped(
                                message="Finding is below configured severity threshold",
                                type_="threshold",
                            )
                        ]
                # elif result.kind not in ["notApplicable", "informational"]:
                #     pass

                # Add additional metadata in system-out
                metadata = []
                if hasattr(result, "properties") and result.properties is not None:
                    for key, value in result.properties.model_dump(
                        by_alias=True
                    ).items():
                        metadata.append(f"{key}: {value}")
                if metadata:
                    test_case.system_out = "\n".join(metadata)

                # Create test suite for this finding type
                actual_scanner = "ash"
                if "scanner_name" in result.properties.__pydantic_extra__:
                    actual_scanner = result.properties.__pydantic_extra__[
                        "scanner_name"
                    ]
                elif result.properties and result.properties.tags:
                    for tag in result.properties.tags:
                        if tag.startswith("tool_name::"):
                            actual_scanner = tag.split("::")[1]
                            break
                if (
                    actual_scanner == "ash"
                    and result.properties
                    and hasattr(result.properties, "scanner_details")
                ):
                    if hasattr(result.properties.scanner_details, "tool_name"):
                        actual_scanner = result.properties.scanner_details.tool_name
                # In workspace mode the suite is named "<project>/<scanner>".
                # Project leads so that one project's suites sort together in
                # every CI front end that groups by suite name; the scanner is
                # kept because discarding it -- the RFC's literal reading -- would
                # lose a grouping single-directory mode has, for no gain.
                #
                # Read through the shared helper rather than inline, so this and
                # the flattening path cannot disagree about where the attribution
                # lives -- which is how a finding ends up under the wrong project
                # in one report and the right one in another.
                project = extract_workspace_project(result)
                suite_name = (
                    f"{project}/{actual_scanner}" if project else actual_scanner
                )
                if suite_name not in test_suite_dict:
                    test_suite_dict[suite_name] = TestSuite(name=suite_name)
                test_suite_dict[suite_name].add_testcase(test_case)

        for suite_name, test_suite in test_suite_dict.items():
            del suite_name  # keyed for grouping; the name is already on the suite
            report.add_testsuite(test_suite)
        # Return the XML string representation of all test suites
        report_bytes: bytes = report.tostring()
        return report_bytes.decode("utf-8")
