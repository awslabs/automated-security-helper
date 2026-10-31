# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The GitLab SAST report describes the scan and each finding as they are.

* ``scan.status`` read "failure" whenever a finding was actionable, the value
  the transform-failure path uses, so a completed scan with findings read as a
  broken one. Findings do not fail the scan; an incomplete transform does.
* A result whose ``kind`` says no problem (pass, notApplicable, informational)
  was published as an Info vulnerability.
* A message given by ``id`` alone had an empty description.
* The suppression reason came from the first suppression only, and a rejected
  or under-review suppression downgraded the finding.
* The scanner-name lookup stopped at a ``scanner_details`` without a tool name.
* ``SECRET-`` was stripped from every position of a secret rule id.
* A long suppression justification exceeded the schema's solution length.
* Exception text reached ``scan.messages`` without the sanitizing every other
  reporter error gets.
"""

import json

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    GitLabSASTReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Kind,
    Kind1,
    Level,
    Location,
    Message,
    MultiformatMessageString,
    PhysicalLocation,
    PropertyBag,
    Region,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    State,
    Suppression,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


@pytest.fixture
def reporter(test_plugin_context):
    return GitLabSASTReporter(context=test_plugin_context)


def _located(uri="app/main.py", line=7) -> Location:
    return Location(
        physicalLocation=PhysicalLocation(
            artifactLocation=ArtifactLocation(uri=uri), region=Region(startLine=line)
        )
    )


def _model(*results: Result) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.sarif.runs[0].results = list(results)
    return model


def _completed_scan(*results: Result) -> AshAggregatedResults:
    """A model whose one selected scanner completed, so coverage is whole."""
    model = _model(*results)
    model.ash_config = AshConfig(project_name="status-test")
    model.scanner_results["bandit"] = ScannerStatusInfo(
        status=ScannerStatus.PASSED, excluded=False, dependencies_satisfied=True
    )
    model.additional_reports["bandit"] = {
        "source": {"scanner_name": "bandit", "status": ScannerStatus.PASSED.value}
    }
    return model


def _report(reporter, model) -> dict:
    return json.loads(reporter.report(model))


class TestScanStatus:
    def test_a_completed_scan_with_findings_is_a_success(self, reporter):
        model = _completed_scan(
            Result(ruleId="B101", level=Level.error, message=Message(text="m"))
        )
        model.metadata.summary_stats.actionable = 1

        report = _report(reporter, model)

        assert len(report["vulnerabilities"]) == 1
        assert report["scan"]["status"] == "success"
        assert "messages" not in report["scan"]


class TestNonFindingKinds:
    @pytest.mark.parametrize(
        "kind", [Kind.pass_, Kind.notApplicable, Kind.informational]
    )
    def test_a_result_that_states_no_problem_is_not_a_vulnerability(
        self, reporter, kind
    ):
        report = _report(
            reporter,
            _model(
                Result(
                    ruleId="CDK-1",
                    kind=kind,
                    level=Level.none,
                    message=Message(text="x"),
                ),
                Result(ruleId="B102", level=Level.error, message=Message(text="y")),
            ),
        )

        assert [v["name"] for v in report["vulnerabilities"]] == ["B102"]


class TestMessageAndSecretText:
    def test_a_message_given_by_id_names_the_id(self, reporter):
        result = Result(ruleId="R1", level=Level.warning)
        result.message = Message.model_validate({"id": "default"})

        (vuln,) = _report(reporter, _model(result))["vulnerabilities"]

        assert vuln["description"] == "default"
        assert vuln["raw_source_code_extract"] == "default"

    @staticmethod
    def _vulnerability_with_rule(reporter, rule: ReportingDescriptor) -> dict:
        """The one vulnerability of a run whose driver declares *rule* and whose
        only result names the message string ``default`` by id."""
        result = Result(ruleId="R1", level=Level.warning)
        result.message = Message.model_validate({"id": "default"})
        model = AshAggregatedResults()
        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="t", rules=[rule])),
                    results=[result],
                )
            ],
        )
        (vuln,) = _report(reporter, model)["vulnerabilities"]
        return vuln

    def test_a_message_given_by_id_is_resolved_against_the_rule(self, reporter):
        """The description was the key of the message string, not the string
        the rule names by it."""
        vuln = self._vulnerability_with_rule(
            reporter,
            ReportingDescriptor(
                id="R1",
                messageStrings={
                    "default": MultiformatMessageString(text="Hardcoded password")
                },
            ),
        )

        assert vuln["description"] == "Hardcoded password"
        assert vuln["raw_source_code_extract"] == "Hardcoded password"

    def test_an_id_the_rule_does_not_name_falls_back_to_its_short_description(
        self, reporter
    ):
        vuln = self._vulnerability_with_rule(
            reporter,
            ReportingDescriptor(
                id="R1",
                shortDescription=MultiformatMessageString(text="Password in source"),
            ),
        )

        assert vuln["description"] == "Password in source"

    def test_the_secret_prefix_is_read_once(self, reporter):
        result = Result(
            ruleId="SECRET-SECRET-KEYWORD", level=Level.error, message=Message(text="m")
        )

        (vuln,) = _report(reporter, _model(result))["vulnerabilities"]

        assert (
            vuln["raw_source_code_extract"] == "Secret of type Secret Keyword detected"
        )


class TestSuppressions:
    def test_the_first_reasoned_suppression_in_effect_gives_the_solution(
        self, reporter
    ):
        result = Result(
            ruleId="B101",
            level=Level.error,
            message=Message(text="m"),
            suppressions=[
                Suppression(kind=Kind1.inSource),
                Suppression(kind=Kind1.external, justification="Reviewed: test code"),
            ],
        )

        (vuln,) = _report(reporter, _model(result))["vulnerabilities"]

        assert vuln["severity"] == "Info"
        assert "Reviewed: test code" in vuln["solution"]

    @pytest.mark.parametrize("state", [State.rejected, State.underReview])
    def test_a_suppression_not_in_effect_leaves_the_finding_open(self, reporter, state):
        result = Result(
            ruleId="B101",
            level=Level.error,
            message=Message(text="m"),
            suppressions=[
                Suppression(kind=Kind1.inSource, state=state, justification="j")
            ],
        )

        (vuln,) = _report(reporter, _model(result))["vulnerabilities"]

        assert vuln["severity"] == "Critical"
        assert "solution" not in vuln

    def test_a_long_justification_is_cut_to_the_schema_length(self, reporter):
        result = Result(
            ruleId="B101",
            level=Level.error,
            message=Message(text="m"),
            suppressions=[Suppression(kind=Kind1.inSource, justification="x" * 8000)],
        )

        (vuln,) = _report(reporter, _model(result))["vulnerabilities"]

        assert len(vuln["solution"]) == 7000
        assert vuln["solution"].endswith("...")


class TestScannerName:
    def test_the_tag_is_read_when_scanner_details_names_no_tool(self, reporter):
        result = Result(
            ruleId="R1",
            level=Level.error,
            message=Message(text="m"),
            properties=PropertyBag(
                scanner_details={"tool_version": "1.0"}, tags=["tool_name::semgrep"]
            ),
        )

        (vuln,) = _report(reporter, _model(result))["vulnerabilities"]

        assert vuln["details"]["scanner"]["value"] == "semgrep"
        assert vuln["identifiers"][0] == {
            "type": "semgrep-rule",
            "name": "semgrep Rule R1",
            "value": "R1",
        }

    def test_an_empty_scanner_name_falls_through(self, reporter):
        result = Result(
            ruleId="R1",
            level=Level.error,
            message=Message(text="m"),
            properties=PropertyBag(
                scanner_name="", scanner_details={"tool_name": "bandit"}
            ),
        )

        (vuln,) = _report(reporter, _model(result))["vulnerabilities"]

        assert vuln["details"]["scanner"]["value"] == "bandit"


class TestFailureText:
    def test_an_exception_is_written_through_the_error_text_sanitizer(
        self, reporter, monkeypatch
    ):
        def boom(*args, **kwargs):
            raise RuntimeError("bad \x1b[31mred\x1b[0m input")

        monkeypatch.setattr(GitLabSASTReporter, "_assemble_report", boom)

        result = Result(ruleId="R1", message=Message(text="m"), locations=[_located()])
        report = _report(reporter, _model(result))

        (message,) = report["scan"]["messages"]
        assert "\x1b" not in message["value"]
        assert "bad" in message["value"] and "input" in message["value"]
