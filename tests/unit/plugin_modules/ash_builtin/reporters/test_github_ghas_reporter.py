# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the GitHub Advanced Security (GHAS) SARIF reporter.

The reporter's whole job is a wire-format transform, so these tests assert the
emitted structure -- which rule ids appear, what ``security-severity`` each one
carries, which results survive suppression filtering -- rather than that
``report()`` returned a string. A reporter that emitted ``{}`` for every input
would satisfy a "did not raise" test.
"""

import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.github_ghas_reporter import (
    GHASReporter,
    GHASReporterConfig,
    GHASReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Address,
    ArtifactLocation,
    Kind1,
    Level,
    Location,
    Message,
    MultiformatMessageString,
    PhysicalLocation,
    PropertyBag,
    Region,
    ReportingConfiguration,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


def _rule(
    rule_id,
    *,
    level=None,
    security_severity=None,
    underscored=None,
    short_desc=None,
    help_text=None,
    help_uri=None,
    tags=None,
):
    """Build a ReportingDescriptor with only the fields a test cares about."""
    props = None
    if security_severity is not None or underscored is not None or tags is not None:
        extra = {}
        if security_severity is not None:
            extra["security-severity"] = security_severity
        if underscored is not None:
            extra["security_severity"] = underscored
        props = PropertyBag(tags=tags or [], **extra)
    return ReportingDescriptor(
        id=rule_id,
        shortDescription=(
            MultiformatMessageString(text=short_desc) if short_desc else None
        ),
        help=MultiformatMessageString(text=help_text) if help_text else None,
        helpUri=help_uri,
        defaultConfiguration=(
            ReportingConfiguration(level=level) if level is not None else None
        ),
        properties=props,
    )


def _result(
    rule_id,
    *,
    level=None,
    text="finding text",
    locations=None,
    suppressions=None,
    message=None,
):
    return Result(
        ruleId=rule_id,
        level=level,
        message=message if message is not None else Message(text=text),
        locations=locations,
        suppressions=suppressions,
    )


def _unlevelled_result(rule_id="R", text="finding text"):
    """A Result whose ``level`` key is absent, not set to None.

    ``_result(level=None)`` sets the field, so the falsy guard catches it and the
    "error" fallback runs. Omitting the key entirely applies the field default
    instead, which is the shape every third-party scanner's SARIF produces and
    the only one that can carry an unconverted enum member.
    """
    return Result.model_validate({"ruleId": rule_id, "message": {"text": text}})


def _location(uri, **region_kwargs):
    return Location(
        physicalLocation=PhysicalLocation(
            artifactLocation=ArtifactLocation(uri=uri),
            region=Region(**region_kwargs) if region_kwargs else None,
        )
    )


def _model(run):
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[run])
    return model


@pytest.fixture
def reporter(test_plugin_context):
    return GHASReporter(context=test_plugin_context)


class TestReportStructure:
    """End-to-end structure of the document report() emits."""

    def test_emits_driver_rules_flattened_from_driver_and_extensions(self, reporter):
        run = Run(
            tool=Tool(
                driver=ToolComponent(
                    name="ASH", rules=[_rule("DRIVER1", level=Level.error)]
                ),
                extensions=[
                    ToolComponent(
                        name="bandit", rules=[_rule("EXT1", level=Level.note)]
                    ),
                    ToolComponent(
                        name="semgrep", rules=[_rule("EXT2", level=Level.warning)]
                    ),
                ],
            ),
            results=[],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert len(doc["runs"]) == 1, (
            "GHAS ingests one repository root; exactly one run"
        )
        driver = doc["runs"][0]["tool"]["driver"]
        # Set equality, not a count: an equal count with different membership is
        # exactly what a mapping bug produces.
        assert {r["id"] for r in driver["rules"]} == {"DRIVER1", "EXT1", "EXT2"}
        assert "extensions" not in driver
        assert doc["runs"][0]["tool"].keys() == {"driver"}

    def test_every_rule_carries_security_severity(self, reporter):
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", rules=[_rule("R1")])),
            results=[],
        )

        doc = json.loads(reporter.report(_model(run)))

        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "security-severity" in rule["properties"], (
            "GitHub renders severity from properties['security-severity']; "
            "a rule without it displays as a bare 'Error'"
        )

    def test_document_envelope_fields(self, reporter):
        run = Run(tool=Tool(driver=ToolComponent(name="ASH")), results=[])

        doc = json.loads(reporter.report(_model(run)))

        assert doc["version"] == "2.1.0"
        assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "ASH - Automated Security Helper"
        assert driver["organization"] == "Amazon Web Services"
        assert (
            driver["informationUri"]
            == "https://github.com/awslabs/automated-security-helper"
        )

    def test_output_is_compact_json(self, reporter):
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", rules=[_rule("R1")])),
            results=[_result("R1", level=Level.error)],
        )

        raw = reporter.report(_model(run))

        assert ", " not in raw and '": ' not in raw, (
            "report() must use compact separators to keep the upload small"
        )

    def test_result_ids_survive_the_transform(self, reporter):
        rule_ids = ["R1", "R2", "R3"]
        run = Run(
            tool=Tool(
                driver=ToolComponent(
                    name="ASH", rules=[_rule(r, level=Level.error) for r in rule_ids]
                )
            ),
            results=[_result(r, level=Level.error) for r in rule_ids],
        )

        doc = json.loads(reporter.report(_model(run)))

        emitted = [r["ruleId"] for r in doc["runs"][0]["results"]]
        assert emitted == rule_ids, "result order and membership must be preserved"


class TestInvocationsDoNotReachGitHub:
    """Error-level tool notifications must not be uploaded to Code Scanning.

    cdk-nag's scanner now writes one ``toolExecutionNotifications`` entry per rule that raised
    instead of returning a verdict, at ``level: error``, and those survive into the aggregated
    ``ash.sarif`` -- measured on this repository, 11 of them where there were previously none.
    ``github/codeql-action/upload-sarif`` renders an error-level notification as an analysis
    error, so if they reached this report every ASH scan of a CDK repository would report
    failures in Code Scanning that are not findings.

    They do not, and this pins why rather than trusting it. ``report()`` reads ``model.sarif``
    to harvest rules and results and then assembles a FRESH run dict carrying only
    ``tool.driver`` and ``results``. It does not copy the run, so there is nowhere for an
    invocation to arrive from. Measured against a real scan: ``ash.ghas.sarif`` has no
    ``invocations`` key while ``ash.sarif`` alongside it has eleven notifications.

    The guard is worth having because the containment is incidental. Nothing in ``report()``
    names invocations or explains that omitting them is load-bearing, so a future refactor that
    started from the source run and pruned it -- a natural way to write this -- would begin
    uploading them with no test objecting. ASH's own workflow uploads ``ash.ghas.sarif``, so this
    report is the boundary.
    """

    def test_error_level_tool_notifications_are_not_forwarded(self, reporter):
        from automated_security_helper.schemas.sarif_schema_model import (
            Invocation,
            Message1,
            Notification,
            ReportingDescriptorReference,
            ReportingDescriptorReference3,
        )

        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", rules=[_rule("R1")])),
            results=[_result("R1")],
            invocations=[
                Invocation(
                    executionSuccessful=True,
                    toolExecutionNotifications=[
                        Notification(
                            level=Level.error,
                            message=Message(
                                root=Message1(
                                    text="Rule AwsSolutions-IAM5 could not be evaluated"
                                )
                            ),
                            associatedRule=ReportingDescriptorReference(
                                root=ReportingDescriptorReference3(
                                    id="AwsSolutions-IAM5"
                                )
                            ),
                        )
                    ],
                )
            ],
        )

        model = _model(run)
        assert model.sarif.runs[0].invocations[0].toolExecutionNotifications, (
            "the input must actually carry an error notification, or this test passes "
            "against a reporter that forwards everything"
        )

        doc = json.loads(reporter.report(model))

        assert "invocations" not in doc["runs"][0], (
            "an error-level tool notification reached the report uploaded to GitHub Code "
            "Scanning, where it renders as an analysis error rather than a finding"
        )
        # The findings themselves still have to arrive, so the assertion above cannot be
        # satisfied by a reporter that emitted nothing at all.
        assert [r["ruleId"] for r in doc["runs"][0]["results"]] == ["R1"]


class TestEmptyAndErrorPaths:
    def test_no_sarif_returns_empty_report(self, reporter):
        model = AshAggregatedResults()
        model.sarif = None

        doc = json.loads(reporter.report(model))

        assert doc["runs"][0]["results"] == []
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []

    def test_sarif_with_no_runs_returns_empty_report(self, reporter):
        model = AshAggregatedResults()
        model.sarif = SarifReport(version="2.1.0", runs=[])

        doc = json.loads(reporter.report(model))

        assert doc["runs"][0]["results"] == []
        assert doc["version"] == "2.1.0"

    def test_unexpected_failure_produces_no_report_at_all(self, reporter, caplog):
        """A failed transform must not emit a SARIF document claiming zero findings.

        This assertion is the inversion of an earlier one that required the
        handler to "degrade" to ``_empty_report()``. Degrading is what made the
        failure invisible: the document is byte-identical to the legitimate-empty
        case below, so ``ReportPhase`` took the write branch, logged at INFO,
        wrote a schema-valid SARIF asserting zero findings, and painted the
        reporter green. The only thing separating a crashed transform from a clean
        repository was one ERROR line in a log nothing downstream reads.

        A reporter that raises would abort the run, which is why the handler
        stays. Returning None instead writes no file, so no analysis is uploaded
        and whatever GitHub Code Scanning already holds for this tool and category
        is left as it was. The coverage this inversion keeps -- that one broken
        result does not propagate an exception out of ``report()`` -- is asserted
        directly below.
        """

        class ExplodingResults:
            def __iter__(self):
                raise RuntimeError("iteration exploded")

            def __bool__(self):
                return True

        run = Run(tool=Tool(driver=ToolComponent(name="ASH")), results=[])
        # Assignment is not re-validated by pydantic, so this injects a fault at
        # the exact point report() iterates results.
        run.results = ExplodingResults()

        assert reporter.report(_model(run)) is None

    def test_unexpected_failure_still_does_not_raise(self, reporter):
        """The coverage the inverted assertion above was protecting."""

        class ExplodingResults:
            def __iter__(self):
                raise RuntimeError("iteration exploded")

            def __bool__(self):
                return True

        run = Run(tool=Tool(driver=ToolComponent(name="ASH")), results=[])
        run.results = ExplodingResults()

        reporter.report(_model(run))  # must not propagate

    def test_unexpected_failure_is_logged_where_quiet_cannot_hide_it(
        self, reporter, caplog
    ):
        """Returning None is silent unless the reason is on the operator's log."""
        import logging

        class ExplodingResults:
            def __iter__(self):
                raise RuntimeError("iteration exploded")

            def __bool__(self):
                return True

        run = Run(tool=Tool(driver=ToolComponent(name="ASH")), results=[])
        run.results = ExplodingResults()

        caplog.set_level(logging.ERROR)
        reporter.report(_model(run))

        assert [
            record
            for record in caplog.records
            if record.levelno >= logging.ERROR
            and "Failed to create GHAS SARIF report" in record.getMessage()
        ]

    def test_the_failure_path_is_not_the_legitimate_empty_path(self, reporter):
        """The two outcomes were byte-identical, which is the whole defect."""

        class ExplodingResults:
            def __iter__(self):
                raise RuntimeError("iteration exploded")

            def __bool__(self):
                return True

        run = Run(tool=Tool(driver=ToolComponent(name="ASH")), results=[])
        run.results = ExplodingResults()

        empty_model = AshAggregatedResults()
        empty_model.sarif = None

        assert reporter.report(_model(run)) != reporter.report(empty_model)


class TestCollectRules:
    def test_none_component_is_ignored(self, reporter):
        rules_map = {}
        reporter._collect_rules([None], rules_map)
        assert rules_map == {}

    def test_component_without_rules_is_ignored(self, reporter):
        rules_map = {}
        reporter._collect_rules([ToolComponent(name="empty")], rules_map)
        assert rules_map == {}

    def test_the_scanner_named_first_keeps_a_rule_id_in_any_order(self, reporter):
        # Listed extension first: the bare id still goes to "driver", which
        # sorts first by name. Without a `qualified` map the other declaration
        # is not entered at all.
        rules_map = {}
        reporter._collect_rules(
            [
                ToolComponent(
                    name="ext", rules=[_rule("DUP", short_desc="from extension")]
                ),
                ToolComponent(
                    name="driver", rules=[_rule("DUP", short_desc="from driver")]
                ),
            ],
            rules_map,
        )

        assert list(rules_map) == ["DUP"]
        assert rules_map["DUP"]["short_description"] == "from driver"

    def test_hyphenated_security_severity_is_preserved_as_string(self, reporter):
        rules_map = {}
        reporter._collect_rules(
            [ToolComponent(name="d", rules=[_rule("R", security_severity=9.5)])],
            rules_map,
        )
        assert rules_map["R"]["security_severity"] == "9.5"

    def test_underscored_security_severity_is_accepted(self, reporter):
        """ASH-internal code writes the underscored spelling; both must work."""
        rules_map = {}
        reporter._collect_rules(
            [ToolComponent(name="d", rules=[_rule("R", underscored="7.5")])],
            rules_map,
        )
        assert rules_map["R"]["security_severity"] == "7.5"

    def test_hyphenated_spelling_takes_precedence_over_underscored(self, reporter):
        rules_map = {}
        reporter._collect_rules(
            [
                ToolComponent(
                    name="d",
                    rules=[_rule("R", security_severity="9.0", underscored="1.0")],
                )
            ],
            rules_map,
        )
        assert rules_map["R"]["security_severity"] == "9.0"

    def test_rule_metadata_is_captured(self, reporter):
        rules_map = {}
        reporter._collect_rules(
            [
                ToolComponent(
                    name="d",
                    rules=[
                        _rule(
                            "R",
                            level=Level.warning,
                            short_desc="a short description",
                            help_text="some help",
                            help_uri="https://example.test/rules/R",
                            tags=["security", "cwe-79"],
                        )
                    ],
                )
            ],
            rules_map,
        )

        info = rules_map["R"]
        assert info["default_level"] == "warning"
        assert info["short_description"] == "a short description"
        assert info["help_text"] == "some help"
        assert info["help_uri"] == "https://example.test/rules/R"
        assert info["tags"] == ["security", "cwe-79"]

    def test_default_configuration_with_an_absent_level_key_reads_as_warning(
        self, reporter
    ):
        """ReportingConfiguration.level defaults to warning and is unvalidated too.

        A rule that declares a defaultConfiguration without spelling out
        ``level`` must read as "warning", so the security-severity lookup hits
        6.0 by name rather than by falling off the end of the table.
        """
        rule = ReportingDescriptor.model_validate(
            {"id": "R", "defaultConfiguration": {"enabled": True}}
        )
        rules_map = {}

        reporter._collect_rules(
            [ToolComponent(name="ASH", rules=[rule])],
            rules_map,
        )

        assert rules_map["R"]["default_level"] == "warning"

    def test_rule_without_properties_has_no_severity_or_tags(self, reporter):
        rules_map = {}
        reporter._collect_rules(
            [ToolComponent(name="d", rules=[_rule("R")])], rules_map
        )
        assert rules_map["R"]["security_severity"] is None
        assert rules_map["R"]["tags"] == []
        assert rules_map["R"]["default_level"] is None
        assert rules_map["R"]["help_uri"] is None


class TestResolveSecuritySeverity:
    def test_scanner_supplied_severity_is_preserved_verbatim(self, reporter):
        rules_map = {
            "R": {"security_severity": "9.8", "default_level": "note"},
        }
        # defaultConfiguration would map "note" to 3.0; the scanner value wins.
        assert (
            reporter._resolve_security_severity("R", rules_map, {"R": "error"}) == "9.8"
        )

    # error scores 9.5, GitHub's Critical band, because the gate fails an error
    # finding as CRITICAL; it was 8.0 (High).
    @pytest.mark.parametrize(
        "level,expected",
        [("error", "9.5"), ("warning", "6.0"), ("note", "3.0"), ("none", "1.0")],
    )
    def test_derived_from_rule_default_level(self, reporter, level, expected):
        rules_map = {"R": {"security_severity": None, "default_level": level}}
        assert reporter._resolve_security_severity("R", rules_map, {}) == expected

    @pytest.mark.parametrize(
        "level,expected",
        [("error", "9.5"), ("warning", "6.0"), ("note", "3.0"), ("none", "1.0")],
    )
    def test_derived_from_result_level_when_rule_has_no_default(
        self, reporter, level, expected
    ):
        rules_map = {"R": {"security_severity": None, "default_level": None}}
        assert (
            reporter._resolve_security_severity("R", rules_map, {"R": level})
            == expected
        )

    def test_result_severity_outranks_rule_default_level(self, reporter):
        """The results decide, as they decide the gate, not the rule default.

        A result carries ``issue_severity`` and may override the rule's level,
        and the gate grades results, so a rule defaulting to ``note`` whose finding
        is ``error`` reaches GitHub as it fails the scan, CRITICAL, not Low (3.0).
        """
        rules_map = {"R": {"security_severity": None, "default_level": "note"}}
        assert (
            reporter._resolve_security_severity("R", rules_map, {"R": "CRITICAL"})
            == "9.5"
        )

    def test_unknown_level_string_reads_as_the_missing_level(self, reporter):
        # A level that is not a SARIF level is read as MISSING_SARIF_LEVEL
        # ("warning", MEDIUM) by every grader, so it scores Medium, 6.0. The
        # example is not "Level.warning", the stringified enum member, since
        # _level_value makes that unreachable,
        # so the coverage is kept against a level that really is foreign.
        rules_map = {"R": {"security_severity": None, "default_level": "critical"}}
        assert reporter._resolve_security_severity("R", rules_map, {}) == "6.0"

    def test_unknown_rule_falls_back_to_medium(self, reporter):
        assert reporter._resolve_security_severity("MISSING", {}, {}) == "6.0"


class TestBuildSlimRules:
    def test_optional_fields_are_omitted_when_absent(self, reporter):
        rules_map = {
            "R": {
                "security_severity": "6.0",
                "default_level": None,
                "short_description": None,
                "help_uri": None,
                "help_text": None,
                "tags": [],
            }
        }

        (rule,) = reporter._build_slim_rules(rules_map, {})

        assert rule == {"id": "R", "properties": {"security-severity": "6.0"}}

    def test_present_fields_are_emitted(self, reporter):
        rules_map = {
            "R": {
                "security_severity": "8.0",
                "default_level": None,
                "short_description": "sd",
                "help_uri": "https://example.test/r",
                "help_text": "ht",
                "tags": ["t1"],
            }
        }

        (rule,) = reporter._build_slim_rules(rules_map, {})

        assert rule["shortDescription"] == {"text": "sd"}
        assert rule["helpUri"] == "https://example.test/r"
        assert rule["help"] == {"text": "ht"}
        assert rule["properties"] == {"security-severity": "8.0", "tags": ["t1"]}

    def test_markdown_help_is_stripped(self, reporter):
        """The reporter emits help.text only -- markdown is the bulk of the size."""
        run = Run(
            tool=Tool(
                driver=ToolComponent(
                    name="ASH",
                    rules=[
                        ReportingDescriptor(
                            id="R",
                            help=MultiformatMessageString(
                                text="plain", markdown="# a very long markdown body"
                            ),
                        )
                    ],
                )
            ),
            results=[],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert doc["runs"][0]["tool"]["driver"]["rules"][0]["help"] == {"text": "plain"}


class TestBuildSlimResults:
    def test_suppressed_results_are_excluded_by_default(self, reporter):
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH")),
            results=[
                _result("KEEP", level=Level.error),
                _result(
                    "DROP",
                    level=Level.error,
                    suppressions=[
                        Suppression(kind=Kind1.external, justification="accepted risk")
                    ],
                ),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert {r["ruleId"] for r in doc["runs"][0]["results"]} == {"KEEP"}

    def test_suppressed_results_are_kept_when_configured(self, test_plugin_context):
        reporter = GHASReporter(
            context=test_plugin_context,
            config=GHASReporterConfig(
                options=GHASReporterConfigOptions(exclude_suppressed=False)
            ),
        )
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH")),
            results=[
                _result("KEEP", level=Level.error),
                _result(
                    "SUPPRESSED",
                    level=Level.error,
                    suppressions=[Suppression(kind=Kind1.external)],
                ),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert {r["ruleId"] for r in doc["runs"][0]["results"]} == {
            "KEEP",
            "SUPPRESSED",
        }

    def test_empty_suppressions_list_does_not_exclude(self, reporter):
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH")),
            results=[_result("R", level=Level.error, suppressions=[])],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert len(doc["runs"][0]["results"]) == 1

    def test_missing_result_level_is_the_missing_level(self, reporter):
        # level=None sets the field, so this covers the explicit-None path only.
        # The absent-key path is a different shape; see
        # test_result_with_an_absent_level_key_emits_warning below.
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH")),
            results=[_result("R", level=None)],
        )

        doc = json.loads(reporter.report(_model(run)))

        # MISSING_SARIF_LEVEL, as the gate and every report read it. It was
        # "error" here, CRITICAL, while the gate read the same finding as LOW.
        assert doc["runs"][0]["results"][0]["level"] == "warning"

    def test_result_with_an_absent_level_key_emits_warning(self, reporter):
        """The emitted value must be a SARIF level, not a stringified enum.

        GitHub reads ``level`` to place the alert. "Level.error" is not a member
        of the SARIF 2.1.0 level enum, so the upload carries a schema-invalid
        value at the one field that decides alert severity.
        """
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH")),
            results=[_unlevelled_result("R")],
        )

        doc = json.loads(reporter.report(_model(run)))

        # SARIF's own default (3.27.10), MISSING_SARIF_LEVEL; it was "error".
        assert doc["runs"][0]["results"][0]["level"] == "warning"

    def test_result_with_an_absent_level_key_scores_as_the_missing_level(
        self, reporter
    ):
        """An absent level is the field default, warning: 6.0, GitHub's Medium band.

        The rule is declared but carries neither a scanner security-severity nor
        a defaultConfiguration, so _resolve_security_severity falls through to
        the result -- graded as the gate grades it, MISSING_SARIF_LEVEL being
        MEDIUM, here and at the gate.
        """
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", rules=[_rule("R")])),
            results=[_unlevelled_result("R")],
        )

        doc = json.loads(reporter.report(_model(run)))

        (rule,) = doc["runs"][0]["tool"]["driver"]["rules"]
        assert rule["properties"]["security-severity"] == "6.0"

    def test_level_held_as_an_enum_member_emits_error(self, reporter):
        """Assignment is unvalidated, so the reporter cannot trust the type."""
        result = _result("R", level=Level.warning)
        result.level = Level.error
        run = Run(tool=Tool(driver=ToolComponent(name="ASH")), results=[result])

        doc = json.loads(reporter.report(_model(run)))

        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_no_emitted_level_contains_a_dot(self, reporter):
        """A blanket shape check over every level the document carries.

        Any "EnumName.member" leak shows up as a dot, whatever field or code
        path produced it, so this catches sites a per-field test would miss.
        """
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH")),
            results=[
                _unlevelled_result("ABSENT"),
                _result("EXPLICIT", level=Level.warning),
                _result("NONE", level=None),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        levels = [r["level"] for r in doc["runs"][0]["results"]]
        assert levels == ["warning", "warning", "warning"]
        assert all("." not in level for level in levels), levels

    def test_result_level_is_carried_through(self, reporter):
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH")),
            results=[
                _result("E", level=Level.error),
                _result("W", level=Level.warning),
                _result("N", level=Level.note),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]} == {
            "E": "error",
            "W": "warning",
            "N": "note",
        }

    def test_message_text_is_carried_through(self, reporter):
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH")),
            results=[_result("R", level=Level.error, text="the actual message")],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert doc["runs"][0]["results"][0]["message"] == {"text": "the actual message"}

    def test_message_falls_back_to_rule_id(self, reporter):
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH")),
            results=[
                _result("RULE_X", level=Level.error, message=Message(id="msg-id"))
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert doc["runs"][0]["results"][0]["message"] == {"text": "RULE_X"}

    def test_message_falls_back_to_placeholder_without_rule_id(self, reporter):
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH")),
            results=[Result(level=Level.error, message=Message(id="msg-id"))],
        )

        doc = json.loads(reporter.report(_model(run)))

        emitted = doc["runs"][0]["results"][0]
        assert emitted["message"] == {"text": "Finding detected"}
        assert "ruleId" not in emitted

    def test_result_level_seeds_severity_for_a_rule_with_no_default(self, reporter):
        """The level lookup built from results must reach _build_slim_rules."""
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", rules=[_rule("R")])),
            results=[_result("R", level=Level.note)],
        )

        doc = json.loads(reporter.report(_model(run)))

        (rule,) = doc["runs"][0]["tool"]["driver"]["rules"]
        assert rule["properties"]["security-severity"] == "3.0"

    def test_the_most_severe_result_decides_for_a_repeated_rule(self, reporter):
        """The rule's alert severity is its worst finding's, whatever the order.

        The first result does not win, so a rule whose note comes first is not
        scored Low while its error fails the scan as CRITICAL.
        """
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", rules=[_rule("R")])),
            results=[
                _result("R", level=Level.note),
                _result("R", level=Level.error),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        (rule,) = doc["runs"][0]["tool"]["driver"]["rules"]
        assert rule["properties"]["security-severity"] == "9.5"

    def test_a_result_left_out_of_the_file_does_not_score_its_rule(self, reporter):
        """Only the results the file emits decide a rule's security-severity.

        A suppressed error is left out of ash.ghas.sarif by default, and it still
        raised its rule to 9.5, so GitHub showed the rule's one remaining alert,
        a note, as Critical.
        """
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", rules=[_rule("R")])),
            results=[
                _result(
                    "R",
                    level=Level.error,
                    suppressions=[Suppression(kind=Kind1.external)],
                ),
                _result("R", level=Level.note),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert [r["level"] for r in doc["runs"][0]["results"]] == ["note"]
        (rule,) = doc["runs"][0]["tool"]["driver"]["rules"]
        assert rule["properties"]["security-severity"] == "3.0"

    @pytest.mark.parametrize(
        "default_level, expected", [(None, "6.0"), (Level.note, "3.0")]
    )
    def test_a_rule_whose_results_are_all_left_out_keeps_its_baseline(
        self, reporter, default_level, expected
    ):
        """The rule stays, scored as if it had no results: its own default.

        It is kept rather than dropped so the rules list does not depend on which
        findings are suppressed; with no result in the file, no alert carries it.
        """
        run = Run(
            tool=Tool(
                driver=ToolComponent(
                    name="ASH", rules=[_rule("R", level=default_level)]
                )
            ),
            results=[
                _result(
                    "R",
                    level=Level.error,
                    suppressions=[Suppression(kind=Kind1.external)],
                )
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert doc["runs"][0]["results"] == []
        (rule,) = doc["runs"][0]["tool"]["driver"]["rules"]
        assert rule["properties"]["security-severity"] == expected

    def test_a_suppressed_result_the_file_keeps_still_scores_its_rule(
        self, test_plugin_context
    ):
        """With exclude_suppressed off the result is emitted, so it counts."""
        reporter = GHASReporter(
            context=test_plugin_context,
            config=GHASReporterConfig(
                options=GHASReporterConfigOptions(exclude_suppressed=False)
            ),
        )
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", rules=[_rule("R")])),
            results=[
                _result(
                    "R",
                    level=Level.error,
                    suppressions=[Suppression(kind=Kind1.external)],
                ),
                _result("R", level=Level.note),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert len(doc["runs"][0]["results"]) == 2
        (rule,) = doc["runs"][0]["tool"]["driver"]["rules"]
        assert rule["properties"]["security-severity"] == "9.5"

    def test_synthetic_rule_entry_is_recorded_in_the_rules_map(self, reporter):
        """A result naming an undeclared rule gets a rules_map entry.

        report() builds the emitted rules from rules_map after this helper
        runs, so the entry reaches the document; see
        test_an_undeclared_rule_is_emitted_and_scored_from_its_results.
        """
        rules_map = {}
        level_map = {}

        slim = reporter._build_slim_results(
            [_result("UNDECLARED", level=Level.warning)], rules_map, level_map
        )

        # Each slim result comes paired with the severity the gate grades it at.
        assert [(severity, r["ruleId"]) for severity, r in slim] == [
            ("MEDIUM", "UNDECLARED")
        ]
        assert rules_map["UNDECLARED"] == {
            "id": "UNDECLARED",
            "component": "",
            "security_severity": None,
            "default_level": None,
            "short_description": None,
            "help_uri": None,
            "help_text": None,
            "tags": [],
        }
        assert level_map["UNDECLARED"] == "warning"

    def test_an_undeclared_rule_is_emitted_and_scored_from_its_results(self, reporter):
        """A result whose rule the run does not declare still gets a rule entry.

        The rules list was built before the results, so the entry made for an
        undeclared rule never reached the document: GitHub got the result with
        no rule, and no security-severity, for it.
        """
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", rules=[_rule("DECLARED")])),
            results=[
                _result("DECLARED", level=Level.error),
                Result.model_validate(
                    {
                        "ruleId": "UNDECLARED",
                        "level": "error",
                        "message": {"text": "finding text"},
                        "properties": {"issue_severity": "HIGH"},
                    }
                ),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert {r["ruleId"] for r in doc["runs"][0]["results"]} == {
            "DECLARED",
            "UNDECLARED",
        }
        rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        assert list(rules) == ["DECLARED", "UNDECLARED"]
        assert rules["UNDECLARED"]["properties"]["security-severity"] == "8.0"

    def test_a_result_naming_its_rule_through_rule_id_keeps_it(self, reporter):
        """SARIF lets a result name its rule as rule.id instead of ruleId (3.27.7).

        Such a result was emitted with neither a ruleId nor a rule entry, so
        GitHub had nothing to group it under and no security-severity for it.
        """
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", rules=[])),
            results=[
                Result.model_validate(
                    {
                        "rule": {"id": "VIA-RULE"},
                        "level": "error",
                        "message": {"text": "finding text"},
                        "properties": {"issue_severity": "HIGH"},
                    }
                )
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert [r.get("ruleId") for r in doc["runs"][0]["results"]] == ["VIA-RULE"]
        (rule,) = doc["runs"][0]["tool"]["driver"]["rules"]
        assert rule["id"] == "VIA-RULE"
        assert rule["properties"]["security-severity"] == "8.0"

    def test_an_undeclared_rule_with_no_result_in_the_file_is_not_emitted(
        self, reporter
    ):
        """Only the results the file emits make an undeclared rule's entry."""
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", rules=[_rule("DECLARED")])),
            results=[
                _result("DECLARED", level=Level.note),
                _result(
                    "UNDECLARED",
                    level=Level.error,
                    suppressions=[Suppression(kind=Kind1.external)],
                ),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert [r["ruleId"] for r in doc["runs"][0]["results"]] == ["DECLARED"]
        assert [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]] == [
            "DECLARED"
        ]


class TestBuildSlimLocations:
    def test_no_locations_yields_empty_list(self, reporter):
        assert reporter._build_slim_locations(None) == []
        assert reporter._build_slim_locations([]) == []

    def test_location_without_physical_location_is_skipped(self, reporter):
        assert reporter._build_slim_locations([Location()]) == []

    def test_physical_location_without_a_usable_uri_is_skipped(self, reporter):
        """No uri means GitHub cannot anchor the alert, so the location is dropped."""
        # An address-only physicalLocation has no artifactLocation at all.
        no_artifact = Location(
            physicalLocation=PhysicalLocation(address=Address(name="mem-region"))
        )
        uri_is_none = Location(
            physicalLocation=PhysicalLocation(
                artifactLocation=ArtifactLocation(), region=Region(startLine=1)
            )
        )
        empty_uri = Location(
            physicalLocation=PhysicalLocation(
                artifactLocation=ArtifactLocation(uri=""),
                region=Region(startLine=1),
            )
        )

        assert reporter._build_slim_locations([no_artifact]) == []
        assert reporter._build_slim_locations([uri_is_none]) == []
        assert reporter._build_slim_locations([empty_uri]) == []
        # A good location alongside a bad one still survives.
        assert (
            len(reporter._build_slim_locations([no_artifact, _location("ok.py")])) == 1
        )

    def test_uri_and_full_region_are_emitted(self, reporter):
        locs = reporter._build_slim_locations(
            [
                _location(
                    "src/app.py", startLine=10, endLine=12, startColumn=3, endColumn=7
                )
            ]
        )

        assert locs == [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {
                        "startLine": 10,
                        "endLine": 12,
                        "startColumn": 3,
                        "endColumn": 7,
                    },
                }
            }
        ]

    def test_partial_region_emits_only_present_fields(self, reporter):
        locs = reporter._build_slim_locations([_location("src/app.py", startLine=4)])

        assert locs[0]["physicalLocation"]["region"] == {"startLine": 4}

    def test_absent_region_is_omitted(self, reporter):
        locs = reporter._build_slim_locations([_location("src/app.py")])

        assert locs == [
            {"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}}}
        ]

    def test_multiple_locations_are_all_emitted_in_order(self, reporter):
        locs = reporter._build_slim_locations(
            [_location("a.py", startLine=1), _location("b.py", startLine=2)]
        )

        assert [loc["physicalLocation"]["artifactLocation"]["uri"] for loc in locs] == [
            "a.py",
            "b.py",
        ]

    def test_locations_reach_the_emitted_result(self, reporter):
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH")),
            results=[
                _result(
                    "R",
                    level=Level.error,
                    locations=[_location("src/deep/nested.py", startLine=42)],
                )
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        (emitted,) = doc["runs"][0]["results"]
        phys = emitted["locations"][0]["physicalLocation"]
        assert phys["artifactLocation"]["uri"] == "src/deep/nested.py"
        assert phys["region"]["startLine"] == 42

    def test_result_without_locations_omits_the_key(self, reporter):
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH")),
            results=[_result("R", level=Level.error, locations=None)],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert "locations" not in doc["runs"][0]["results"][0]


class TestConfigDefaults:
    def test_model_post_init_supplies_a_default_config(self, test_plugin_context):
        reporter = GHASReporter(context=test_plugin_context)

        assert isinstance(reporter.config, GHASReporterConfig)
        assert reporter.config.name == "github-ghas"
        assert reporter.config.extension == "ghas.sarif"
        assert reporter.config.options.exclude_suppressed is True

    def test_workspace_behaviour_is_per_project(self):
        from automated_security_helper.base.reporter_plugin import (
            ReporterWorkspaceBehaviour,
        )

        assert (
            GHASReporter.workspace_behaviour == ReporterWorkspaceBehaviour.PER_PROJECT
        ), (
            "MERGED would emit a multi-root document that GitHub either rejects "
            "or mis-locates; see the module docstring"
        )
