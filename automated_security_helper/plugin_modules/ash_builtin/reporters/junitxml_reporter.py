# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re
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
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.flat_vulnerability import (
    extract_workspace_project,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
    workspace_policy_gates,
    workspace_project_scanner_thresholds,
    workspace_project_thresholds,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_skipped_rows import (
    skipped_project_detail,
    skipped_projects,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sarif_utils import (
    FINDING_KINDS,
    result_message_text,
    result_rule_id,
    suppressions_in_effect,
)
from automated_security_helper.utils.severity_ladder import (
    SEVERITIES,
    SEVERITY_THRESHOLDS,
    sarif_level_fails_threshold,
    severity_fails_threshold,
)


import defusedxml
import warnings


# The SARIF `kind` values that assert a finding exists are `sarif_utils.FINDING_KINDS`,
# shared with the other reporters. `fail` is handled earlier by the level
# cascade; `open` and `review` reach the arm below.
#
# The other kinds (`pass`, `informational`) do not assert a finding. cdk-nag uses
# `informational` for a COMPLIANT check (cdk_nag_wrapper._level_and_kind). They
# are graded by level like any result, so that the report agrees with the exit
# code: an actionable one with no `error` or `warning` level is a passing test
# case, and one below the threshold is a skip. `notApplicable` is neither: the
# rule was NOT evaluated, so it renders as skipped (see the emit cascade in
# `report`).

#: The ``type`` attribute on a skipped project's ``<skipped>`` element. Distinct
#: from the existing ``suppression`` and ``threshold`` types, which are both about
#: a finding that exists; this one says no scan happened. Named on the module so a
#: consumer and a test can select on it without matching the message text.
SKIPPED_PROJECT_SKIP_TYPE = "project-skipped"

#: The ``classname`` on a skipped project's test case. Not a scanner name, because
#: no scanner ran: attributing the case to one would put a project nothing
#: examined inside a tool's results.
SKIPPED_PROJECT_CLASSNAME = "ash.workspace"


#: The ``properties.origin`` value the workspace executor writes on a finding from
#: a scanner only the workspace policy added (``workspace.execution.POLICY_ORIGIN``,
#: spelled here rather than imported so this reporter does not import the executor).
_POLICY_ORIGIN = "workspace-policy"

#: The ``type`` of the skip a non-gating policy-origin finding is reported with.
POLICY_NOT_GATING_SKIP_TYPE = "policy-not-gating"


def _is_policy_origin(props: object, extra: dict) -> bool:
    """Whether a finding came from a scanner only the workspace policy added.

    Read from ``properties.origin`` first (the field the schema documents) and
    from the ``workspace-policy`` tag the executor writes beside it, as a
    reporter that groups by tag would. Both land in the property bag's extras,
    so the extras dict the caller already read is checked as well as the
    attribute.
    """
    origin = extra.get("origin")
    if origin is None and props is not None:
        origin = getattr(props, "origin", None)
    if origin == _POLICY_ORIGIN:
        return True
    tags = getattr(props, "tags", None) if props is not None else None
    return isinstance(tags, (list, tuple)) and _POLICY_ORIGIN in tags


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
    (``run_ash_scan._compute_exit_code``) for a finding whose scanner has no
    threshold of its own and whose project recorded none, and the same one
    ``ReportContentEmitter`` falls back to in that case, so the report and the
    exit code cannot describe different runs. The per-project and per-scanner
    gates are read ahead of it in ``report`` (``workspace_project_thresholds``,
    ``_scanner_threshold``).

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


def _scanner_threshold(
    model: "AshAggregatedResults", scanner_name: str, cache: dict
) -> str | None:
    """The scanner's own ``options.severity_threshold``, normalized, or None.

    Read through ``ScannerStatisticsCalculator.get_scanner_threshold_info``, the
    resolver the exit code grades each result by and the summary table prints,
    so the report cannot call a finding actionable that the exit code ignores
    (or the reverse). The resolver names three sources: ``config`` (the
    scanner's own ``options.severity_threshold``), ``global`` (the scan's
    ``global_settings``) and ``unavailable`` (no recorded configuration, so
    ASH's default). Only ``config`` counts here: the other two are the one
    value ``_configured_severity_threshold`` already reads, and it validates
    that value and warns where the resolver would pass an unrecognised one
    through. Memoized per scanner because the resolver dumps the whole
    scanners section on every call and a large SARIF carries one result per
    finding.
    """
    if scanner_name not in cache:
        threshold, source = ScannerStatisticsCalculator.get_scanner_threshold_info(
            model, scanner_name
        )
        cache[scanner_name] = (
            _normalized_threshold(threshold) if source == "config" else None
        )
    return cache[scanner_name]


#: XML 1.0 forbids these characters in text and attributes (section 2.2): C0
#: controls other than tab, line feed and carriage return, the surrogate range
#: and the two noncharacters. A scanner message, a suppression justification or a
#: property value can carry one (a file name in a scanned repository may), and a
#: document holding one is not well-formed, so no JUnit consumer reads it.
_XML_FORBIDDEN = re.compile(
    "[%s-%s%s%s%s-%s%s-%s%s%s]"
    % tuple(
        chr(point)
        for point in (
            0x00,
            0x08,
            0x0B,
            0x0C,
            0x0E,
            0x1F,
            0xD800,
            0xDFFF,
            0xFFFE,
            0xFFFF,
        )
    )
)


def _xml_text(value: object) -> str:
    """*value* as text XML 1.0 admits, each forbidden character written as its escape.

    Written out (``\\x01``, ``\\ufffe``) rather than dropped, so a reader can
    see what the text held; the layout characters XML allows (tab, newline,
    carriage return) are kept as they are, because ``system-out`` is joined
    with newlines.
    """
    text = "" if value is None else str(value)

    def shown(match: re.Match[str]) -> str:
        point = ord(match.group(0))
        return f"\\x{point:02x}" if point < 0x100 else f"\\u{point:04x}"

    return _XML_FORBIDDEN.sub(shown, text)


def _as_flag(value: object) -> bool | None:
    """*value* as a true or false flag, or None when it states neither.

    A boolean is itself; the strings ``true`` and ``false`` (any case) and the
    integers 1 and 0 are read as those. Anything else is no flag: a string such
    as ``"false"`` is truthy to Python, so negating it hid an actionable finding.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "false"):
            return lowered == "true"
    return None


#: The ``type`` of the ``<error>`` element for each SARIF level; ``none`` is the
#: level of a finding that carries no severity, so it takes the lowest label.
_ERROR_TYPE_BY_LEVEL = {
    "error": "error",
    "warning": "warning",
    "note": "note",
    "none": "note",
}


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

    A skipped project gets a suite of its own, named after the project with no
    scanner segment -- there is no scanner, since none ran -- holding one test case
    marked ``<skipped>``. That is JUnit's own statement that a test did not run, so
    every CI front end already counts it apart from failures and errors and the
    project cannot turn a job red. Without it a skipped project has no findings, so
    no test cases, so no suite, and vanishes from this artefact in the one way a
    reader cannot notice. See ``workspace_skipped_rows``.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        # defuse_stdlib's first call imports defusedxml.cElementTree, which issues a
        # DeprecationWarning; catch_warnings alone restores filters, it does not
        # silence anything.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
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

        # Read once: the global threshold is a property of the scan, not of a
        # finding. A scanner's own threshold is resolved per scanner below and
        # memoized here; a project's gate threshold is read off the workspace
        # block per finding.
        configured_threshold = _configured_severity_threshold(model)
        scanner_thresholds: dict = {}
        project_thresholds = workspace_project_thresholds(model)
        # The per-scanner gates each project's verdict recorded, and whether a
        # policy scanner's findings decided it. Both read off the workspace
        # block: the merged file carries no ash_config to read a scanner's own
        # threshold from, and nothing else says a project's policy findings were
        # excluded from its verdict.
        project_scanner_thresholds = workspace_project_scanner_thresholds(model)
        policy_gates = workspace_policy_gates(model)

        # Process SARIF report @ model.sarif
        if model.sarif is not None:
            all_results = model.sarif.get_all_results()
            for result in all_results:
                # Create test case name from SARIF result details. Every value
                # a scanner or the scanned repository wrote passes through
                # _xml_text, because XML 1.0 forbids a control character in
                # text and attributes and one makes the whole document
                # unreadable to every JUnit consumer.
                message_text = _xml_text(result_message_text(result, default=""))
                named_rule = result_rule_id(result)
                rule_id = _xml_text(named_rule) if named_rule else None
                test_name = (
                    f"{message_text} [{rule_id}]"
                    if rule_id and message_text
                    else message_text or rule_id or ""
                )
                test_case = TestCase(
                    name=test_name,
                    classname=rule_id,
                )
                # A result can carry no properties at all (an imported SARIF, a
                # producer that writes none). Every read below goes through
                # getattr so that result still gets its test case instead of
                # losing the whole artefact to an AttributeError.
                props = result.properties

                # The scanner the finding came from, and the workspace project it
                # was attributed to. Both are read before the gate, because the
                # threshold a finding is judged by belongs to its scanner and to
                # its project, not to the scan as a whole.
                actual_scanner = "ash"
                extra = getattr(props, "__pydantic_extra__", None) or {}
                if "scanner_name" in extra:
                    actual_scanner = extra["scanner_name"]
                elif props is not None and getattr(props, "tags", None):
                    for tag in props.tags:
                        if tag.startswith("tool_name::"):
                            actual_scanner = tag.split("::")[1]
                            break
                if (
                    actual_scanner == "ash"
                    and props is not None
                    and hasattr(props, "scanner_details")
                    and hasattr(props.scanner_details, "tool_name")
                ):
                    actual_scanner = props.scanner_details.tool_name
                # An imported SARIF can name its scanner with anything (a list,
                # a mapping). The name is a cache key and a suite name below, so
                # a value that is not text falls back to the default suite
                # instead of losing the whole artefact to a TypeError.
                if not isinstance(actual_scanner, str) or not actual_scanner:
                    actual_scanner = "ash"
                # Read through the shared helper rather than inline, so this and
                # the flattening path cannot disagree about where the attribution
                # lives -- which is how a finding ends up under the wrong project
                # in one report and the right one in another.
                project = extract_workspace_project(result)

                # A suppression hides the finding only when it is in effect:
                # one whose state is rejected or underReview (SARIF 3.35.4) was
                # never an approval, so the finding is graded below as the exit
                # code, the per-scanner counts and the workspace verdict grade
                # it. Only the suppressions in effect are rendered as the skip.
                in_effect = suppressions_in_effect(result.suppressions)
                if in_effect:
                    # One <skipped> for the case, however many suppressions
                    # accepted it: JUnit counts each child as a skip, so one
                    # test was counted as two. The justifications are joined.
                    test_case.result = [
                        Skipped(
                            message=_xml_text(
                                "; ".join(
                                    suppression.justification
                                    for suppression in in_effect
                                    if suppression.justification
                                )
                            ),
                            type_="suppression",
                        )
                    ]
                elif result.kind == "notApplicable":
                    # SARIF 2.1.0 3.27.9: "the rule specified by ruleId was not
                    # evaluated". cdk-nag writes this for a rule that raised
                    # instead of reaching an answer, and the exit code fails the
                    # scan for that rule through the run-level notification. A
                    # bare test case says the rule passed, which it did not;
                    # JUnit's own word for a test that did not run is skipped,
                    # which no CI front end counts as a pass or a failure.
                    #
                    # Decided here, before any threshold grading, because the
                    # result has no severity to grade: its level is `none` for a
                    # cdk-nag rule, which under every gate but ALL would have
                    # read "below configured severity threshold", and a
                    # producer writing `warning` or `error` on such a result
                    # would have had it reported as an error. Neither says what
                    # happened, which is that the rule was never run.
                    test_case.result = [
                        Skipped(
                            message="Rule was not evaluated for this target",
                            type_="not-evaluated",
                        )
                    ]
                elif (
                    project
                    and _is_policy_origin(props, extra)
                    and policy_gates.get(project) is False
                ):
                    # A finding from a scanner only the workspace policy added, in
                    # a project whose policy_scanners_gate is explicitly off. The
                    # project's verdict reported it and excluded it from the
                    # actionable count (execution.py's gating_results), and the
                    # exit code followed that verdict; an <error> here would say
                    # the finding failed the project when the scan said it did
                    # not. Decided ahead of the threshold, because it is not a
                    # question of severity: the operator added the scanner for
                    # visibility, not as a gate. Skipped rather than a bare
                    # passing case, so the finding is still visible in the report
                    # with the reason it is not red. Only an explicit False takes
                    # this arm: a project whose entry carries no gate (a file
                    # written before the field existed, whose verdict applied the
                    # gate) and a project the workspace block does not list fall
                    # to the threshold grading below, the fail-closed side.
                    test_case.result = [
                        Skipped(
                            message=(
                                "Finding is from a workspace-policy scanner that "
                                "does not gate this project"
                            ),
                            type_=POLICY_NOT_GATING_SKIP_TYPE,
                        )
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
                        # Read as a flag: the string "false" is truthy to Python,
                        # and negating it marked an actionable finding as
                        # below threshold. A value that states neither true nor
                        # false decides nothing, and the gate runs.
                        below_threshold = _as_flag(
                            getattr(props, "below_threshold", None)
                        )
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
                        #
                        # After it, the most specific recorded gate: the threshold
                        # the project's verdict graded this finding's scanner by
                        # (the scanner's own options.severity_threshold, as the
                        # project's outcome recorded it), then the project's gate
                        # (a merged workspace file carries no ash_config, and each
                        # project's outcome was judged against its own recorded
                        # gate threshold, so grading every project against ASH's
                        # default here contradicted the per-project verdicts and
                        # the exit code); then, for a single scan, the scanner's
                        # own options.severity_threshold, which the exit code
                        # grades each result by and this reporter used to ignore;
                        # then the scan's global threshold. The recorded scanner
                        # gate comes before the project gate because that is the
                        # order the verdict resolved them in: a scanner the
                        # project's config tightened or relaxed was judged by its
                        # own setting, and reading the project gate first graded
                        # its findings differently from the verdict.
                        threshold = (
                            _normalized_threshold(
                                getattr(props, "severity_threshold", None)
                            )
                            or project_scanner_thresholds.get(project, {}).get(
                                actual_scanner
                            )
                            or project_thresholds.get(project)
                            or _scanner_threshold(
                                model, actual_scanner, scanner_thresholds
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
                        issue_severity = (
                            str(getattr(props, "issue_severity", "") or "")
                            .strip()
                            .upper()
                        )
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
                        # The `type` follows the level, so a LOW (`note`)
                        # finding is not ranked above a MEDIUM (`warning`) one.
                        # It used to follow the kind first: the default kind
                        # `fail` typed every finding "error".
                        #
                        # A kind that asserts a finding (`fail`, `open`,
                        # `review`) always yields an <error>: the level's own
                        # type when it names one, else `error` for `fail` and
                        # `note` for the others. Before the `note` type existed
                        # an actionable `open` or `review` finding at `note` or
                        # `none` fell out with no result element, which renders
                        # as a PASSING test case: the one direction a security
                        # report must not fail in.
                        #
                        # `pass` and `informational` assert the opposite -- the
                        # rule ran and found nothing; cdk-nag uses
                        # `informational` with level `none` for a COMPLIANT
                        # check (cdk_nag_wrapper._level_and_kind). They keep a
                        # bare, passing test case unless the producer also
                        # graded them `error` or `warning`. `notApplicable` (the
                        # rule was not evaluated) never reaches this cascade:
                        # it is decided ahead of the gate, above.
                        #
                        # `Error` rather than `Failure` because the module
                        # imports only Error and Skipped; type_ carries the
                        # distinction.
                        level_type = _ERROR_TYPE_BY_LEVEL.get(str(result.level))
                        if result.kind in FINDING_KINDS:
                            error_type = level_type or (
                                "error" if result.kind == "fail" else "note"
                            )
                        elif result.level in ("error", "warning"):
                            error_type = level_type
                        else:
                            error_type = None
                        if error_type is not None:
                            test_case.result = [
                                Error(message=message_text, type_=error_type)
                            ]
                    else:
                        # Mark as skipped if below threshold. Whatever its kind:
                        # the exit code reads the level against the threshold
                        # and ignores the kind, so a `pass` or `informational`
                        # result that is not actionable is a skip here too, and
                        # the report agrees with the exit code.
                        test_case.result = [
                            Skipped(
                                message="Finding is below configured severity threshold",
                                type_="threshold",
                            )
                        ]

                # Add additional metadata in system-out
                metadata = []
                if props is not None:
                    for key, value in props.model_dump(by_alias=True).items():
                        metadata.append(f"{key}: {value}")
                if metadata:
                    test_case.system_out = _xml_text("\n".join(metadata))

                # In workspace mode the suite is named "<project>/<scanner>".
                # Project leads so that one project's suites sort together in
                # every CI front end that groups by suite name; the scanner is
                # kept because discarding it -- the RFC's literal reading -- would
                # lose a grouping single-directory mode has, for no gain.
                suite_name = _xml_text(
                    f"{project}/{actual_scanner}" if project else actual_scanner
                )
                if suite_name not in test_suite_dict:
                    test_suite_dict[suite_name] = TestSuite(name=suite_name)
                test_suite_dict[suite_name].add_testcase(test_case)

        for suite_name, test_suite in test_suite_dict.items():
            del suite_name  # keyed for grouping; the name is already on the suite
            report.add_testsuite(test_suite)

        # One suite per skipped project, added after the finding suites and
        # OUTSIDE the `model.sarif is not None` block above. Both placements are
        # load-bearing: a workspace whose scanned projects came back clean has no
        # results and may have no SARIF at all, and that is exactly the artefact
        # where losing the skip means the file says nothing whatever.
        #
        # Built separately rather than inserted into test_suite_dict, so a project
        # name can never collide with a grouping key and silently replace a
        # scanner's suite. It cannot today -- every workspace-mode finding suite
        # carries a "<project>/<scanner>" name with a separator in it, and a bare
        # project name has none -- but that is a property of the naming above
        # rather than of anything enforced, and a merge that changed it would be
        # invisible here.
        for entry in skipped_projects(model):
            suite = TestSuite(name=_xml_text(entry.project))
            case = TestCase(
                name=f"project skipped ({entry.reason.value})",
                classname=SKIPPED_PROJECT_CLASSNAME,
            )
            case.result = [
                Skipped(
                    message=_xml_text(skipped_project_detail(entry)),
                    type_=SKIPPED_PROJECT_SKIP_TYPE,
                )
            ]
            suite.add_testcase(case)
            report.add_testsuite(suite)

        # Return the XML string representation of all test suites
        report_bytes: bytes = report.tostring()
        return report_bytes.decode("utf-8")
