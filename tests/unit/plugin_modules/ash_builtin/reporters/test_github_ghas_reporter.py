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

    def test_unexpected_failure_degrades_to_empty_report(self, reporter, caplog):
        """A reporter that raises aborts the run; this one must degrade instead."""

        class ExplodingResults:
            def __iter__(self):
                raise RuntimeError("iteration exploded")

            def __bool__(self):
                return True

        run = Run(tool=Tool(driver=ToolComponent(name="ASH")), results=[])
        # Assignment is not re-validated by pydantic, so this injects a fault at
        # the exact point report() iterates results.
        run.results = ExplodingResults()

        doc = json.loads(reporter.report(_model(run)))

        assert doc["runs"][0]["results"] == []
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []


class TestCollectRules:
    def test_none_component_is_ignored(self, reporter):
        rules_map = {}
        reporter._collect_rules(None, rules_map)
        assert rules_map == {}

    def test_component_without_rules_is_ignored(self, reporter):
        rules_map = {}
        reporter._collect_rules(ToolComponent(name="empty"), rules_map)
        assert rules_map == {}

    def test_first_definition_of_a_rule_id_wins(self, reporter):
        rules_map = {}
        reporter._collect_rules(
            ToolComponent(
                name="driver", rules=[_rule("DUP", short_desc="from driver")]
            ),
            rules_map,
        )
        reporter._collect_rules(
            ToolComponent(
                name="ext", rules=[_rule("DUP", short_desc="from extension")]
            ),
            rules_map,
        )

        assert list(rules_map) == ["DUP"]
        assert rules_map["DUP"]["short_description"] == "from driver"

    def test_hyphenated_security_severity_is_preserved_as_string(self, reporter):
        rules_map = {}
        reporter._collect_rules(
            ToolComponent(name="d", rules=[_rule("R", security_severity=9.5)]),
            rules_map,
        )
        assert rules_map["R"]["security_severity"] == "9.5"

    def test_underscored_security_severity_is_accepted(self, reporter):
        """ASH-internal code writes the underscored spelling; both must work."""
        rules_map = {}
        reporter._collect_rules(
            ToolComponent(name="d", rules=[_rule("R", underscored="7.5")]),
            rules_map,
        )
        assert rules_map["R"]["security_severity"] == "7.5"

    def test_hyphenated_spelling_takes_precedence_over_underscored(self, reporter):
        rules_map = {}
        reporter._collect_rules(
            ToolComponent(
                name="d", rules=[_rule("R", security_severity="9.0", underscored="1.0")]
            ),
            rules_map,
        )
        assert rules_map["R"]["security_severity"] == "9.0"

    def test_rule_metadata_is_captured(self, reporter):
        rules_map = {}
        reporter._collect_rules(
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
            ),
            rules_map,
        )

        info = rules_map["R"]
        assert info["default_level"] == "warning"
        assert info["short_description"] == "a short description"
        assert info["help_text"] == "some help"
        assert info["help_uri"] == "https://example.test/rules/R"
        assert info["tags"] == ["security", "cwe-79"]

    def test_rule_without_properties_has_no_severity_or_tags(self, reporter):
        rules_map = {}
        reporter._collect_rules(ToolComponent(name="d", rules=[_rule("R")]), rules_map)
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

    @pytest.mark.parametrize(
        "level,expected",
        [("error", "8.0"), ("warning", "6.0"), ("note", "3.0"), ("none", "1.0")],
    )
    def test_derived_from_rule_default_level(self, reporter, level, expected):
        rules_map = {"R": {"security_severity": None, "default_level": level}}
        assert reporter._resolve_security_severity("R", rules_map, {}) == expected

    @pytest.mark.parametrize(
        "level,expected",
        [("error", "8.0"), ("warning", "6.0"), ("note", "3.0"), ("none", "1.0")],
    )
    def test_derived_from_result_level_when_rule_has_no_default(
        self, reporter, level, expected
    ):
        rules_map = {"R": {"security_severity": None, "default_level": None}}
        assert (
            reporter._resolve_security_severity("R", rules_map, {"R": level})
            == expected
        )

    def test_rule_default_level_outranks_result_level(self, reporter):
        rules_map = {"R": {"security_severity": None, "default_level": "note"}}
        assert (
            reporter._resolve_security_severity("R", rules_map, {"R": "error"}) == "3.0"
        )

    def test_unknown_level_string_falls_back_to_medium(self, reporter):
        rules_map = {"R": {"security_severity": None, "default_level": "Level.warning"}}
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

    def test_missing_result_level_defaults_to_error(self, reporter):
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH")),
            results=[_result("R", level=None)],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert doc["runs"][0]["results"][0]["level"] == "error", (
            "an unlevelled finding must not silently downgrade"
        )

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

    def test_first_result_level_wins_for_a_repeated_rule(self, reporter):
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", rules=[_rule("R")])),
            results=[
                _result("R", level=Level.note),
                _result("R", level=Level.error),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        (rule,) = doc["runs"][0]["tool"]["driver"]["rules"]
        assert rule["properties"]["security-severity"] == "3.0"

    def test_synthetic_rule_entry_is_recorded_in_the_rules_map(self, reporter):
        """A result naming an undeclared rule gets a rules_map entry.

        Note the ordering: report() builds the emitted rules list *before*
        _build_slim_results runs, so a synthetic entry created here does not
        reach the emitted document. This pins the current behaviour of the
        helper itself; see test_undeclared_rule_is_absent_from_emitted_rules
        for the document-level consequence.
        """
        rules_map = {}
        level_map = {}

        slim = reporter._build_slim_results(
            [_result("UNDECLARED", level=Level.warning)], rules_map, level_map
        )

        assert [r["ruleId"] for r in slim] == ["UNDECLARED"]
        assert rules_map["UNDECLARED"] == {
            "id": "UNDECLARED",
            "security_severity": None,
            "default_level": None,
            "short_description": None,
            "help_uri": None,
            "help_text": None,
            "tags": [],
        }
        assert level_map["UNDECLARED"] == "warning"

    def test_undeclared_rule_is_absent_from_emitted_rules(self, reporter):
        """Documents the known gap: results can reference an unlisted rule."""
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", rules=[_rule("DECLARED")])),
            results=[
                _result("DECLARED", level=Level.error),
                _result("UNDECLARED", level=Level.error),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))

        assert {r["ruleId"] for r in doc["runs"][0]["results"]} == {
            "DECLARED",
            "UNDECLARED",
        }
        assert {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]} == {
            "DECLARED"
        }


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
