# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The GHAS document keeps each scanner's rule, each result's identity, and
GitHub's upload limits.

* Rules were flattened by bare id, first wins: a second scanner declaring the
  same id with other text got the first scanner's description and score, and the
  two scanners' results pooled into one severity. Its rule is now declared under
  ``<scanner>/<id>`` and its results name it.
* A suppression ``rejected`` or ``underReview`` kept the result out of the
  upload under ``exclude_suppressed``; only a suppression in effect does.
* ``partialFingerprints`` and ``fingerprints`` were dropped from the slim copy,
  the identity GitHub tracks an alert by across uploads.
* No cap was applied to results, rules, locations or tags, which GitHub's
  documentation bounds and rejects a file for exceeding.
"""

import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters import (
    github_ghas_reporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.github_ghas_reporter import (
    GHASReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
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
    return GHASReporter(context=test_plugin_context)


def _model(run: Run) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[run])
    return model


def _rule(rule_id: str, text: str, tags=None) -> ReportingDescriptor:
    return ReportingDescriptor(
        id=rule_id,
        shortDescription=MultiformatMessageString(text=text),
        properties=PropertyBag(tags=list(tags or [])),
    )


def _result(rule_id: str, scanner: str, **kwargs) -> Result:
    return Result(
        ruleId=rule_id,
        level=Level.error,
        message=Message(text=f"{scanner} says"),
        properties=PropertyBag(scanner_name=scanner),
        locations=[_location("src/a.py", 1)],
        **kwargs,
    )


def _location(uri: str, line: int) -> Location:
    return Location(
        physicalLocation=PhysicalLocation(
            artifactLocation=ArtifactLocation(uri=uri), region=Region(startLine=line)
        )
    )


def _run(results, extensions) -> Run:
    return Run(
        tool=Tool(driver=ToolComponent(name="ASH"), extensions=extensions),
        results=results,
    )


class TestRuleIdCollisions:
    def test_a_second_scanners_differing_rule_is_declared_under_its_own_name(
        self, reporter
    ):
        run = _run(
            [_result("CVE-2024-1", "grype"), _result("CVE-2024-1", "trivy")],
            [
                ToolComponent(name="grype", rules=[_rule("CVE-2024-1", "grype text")]),
                ToolComponent(name="trivy", rules=[_rule("CVE-2024-1", "trivy text")]),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))["runs"][0]

        rules = {rule["id"]: rule for rule in doc["tool"]["driver"]["rules"]}
        assert set(rules) == {"CVE-2024-1", "trivy/CVE-2024-1"}
        assert rules["CVE-2024-1"]["shortDescription"]["text"] == "grype text"
        assert rules["trivy/CVE-2024-1"]["shortDescription"]["text"] == "trivy text"
        assert [r["ruleId"] for r in doc["results"]] == [
            "CVE-2024-1",
            "trivy/CVE-2024-1",
        ]

    @pytest.mark.parametrize("extension_name", ["Trivy", "TRIVY"])
    def test_an_extension_name_spelled_differently_from_its_scanner_still_collides(
        self, reporter, extension_name
    ):
        run = _run(
            [_result("CVE-2024-1", "grype"), _result("CVE-2024-1", "trivy")],
            [
                ToolComponent(name="grype", rules=[_rule("CVE-2024-1", "grype text")]),
                ToolComponent(
                    name=extension_name, rules=[_rule("CVE-2024-1", "trivy text")]
                ),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))["runs"][0]

        qualified_id = f"{extension_name}/CVE-2024-1"
        rules = {rule["id"]: rule for rule in doc["tool"]["driver"]["rules"]}
        assert set(rules) == {"CVE-2024-1", qualified_id}
        assert rules["CVE-2024-1"]["shortDescription"]["text"] == "grype text"
        assert rules[qualified_id]["shortDescription"]["text"] == "trivy text"
        assert [r["ruleId"] for r in doc["results"]] == ["CVE-2024-1", qualified_id]

    def test_the_ids_do_not_depend_on_the_order_of_the_extensions(self, reporter):
        def emitted(extension_order):
            run = _run(
                [_result("CVE-2024-1", name) for name in ("grype", "trivy")],
                [
                    ToolComponent(
                        name=name, rules=[_rule("CVE-2024-1", f"{name} text")]
                    )
                    for name in extension_order
                ],
            )
            doc = json.loads(reporter.report(_model(run)))["runs"][0]
            texts = {
                rule["id"]: rule["shortDescription"]["text"]
                for rule in doc["tool"]["driver"]["rules"]
            }
            # Each scanner's result, with the text of the rule it names.
            return texts, {
                result["message"]["text"]: texts[result["ruleId"]]
                for result in doc["results"]
            }

        forward = emitted(("grype", "trivy"))
        reversed_order = emitted(("trivy", "grype"))

        assert forward == reversed_order
        texts, by_result = forward
        assert texts["CVE-2024-1"] == "grype text"
        assert by_result == {"grype says": "grype text", "trivy says": "trivy text"}

    def test_one_rule_declared_alike_by_two_scanners_stays_one_rule(self, reporter):
        run = _run(
            [_result("R1", "a"), _result("R1", "b")],
            [
                ToolComponent(name="a", rules=[_rule("R1", "same text")]),
                ToolComponent(name="b", rules=[_rule("R1", "same text")]),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))["runs"][0]

        assert [rule["id"] for rule in doc["tool"]["driver"]["rules"]] == ["R1"]
        assert [r["ruleId"] for r in doc["results"]] == ["R1", "R1"]


class TestSuppressionState:
    @pytest.mark.parametrize("state", [State.rejected, State.underReview])
    def test_a_suppression_not_in_effect_does_not_exclude_the_result(
        self, reporter, state
    ):
        run = _run(
            [
                _result(
                    "R1",
                    "a",
                    suppressions=[Suppression(kind=Kind1.inSource, state=state)],
                )
            ],
            [],
        )

        doc = json.loads(reporter.report(_model(run)))["runs"][0]

        (emitted,) = doc["results"]
        assert emitted["ruleId"] == "R1"
        assert emitted["suppressions"][0]["state"] == state.value

    def test_an_accepted_suppression_still_excludes_the_result(self, reporter):
        run = _run(
            [
                _result(
                    "R1",
                    "a",
                    suppressions=[
                        Suppression(kind=Kind1.inSource, state=State.accepted)
                    ],
                )
            ],
            [],
        )

        doc = json.loads(reporter.report(_model(run)))["runs"][0]

        assert doc["results"] == []


class TestFingerprints:
    def test_fingerprints_are_kept(self, reporter):
        result = _result(
            "R1",
            "a",
            partialFingerprints={"primaryLocationLineHash": "abc:1"},
            fingerprints={"stable": "xyz"},
        )

        doc = json.loads(reporter.report(_model(_run([result], []))))["runs"][0]

        (emitted,) = doc["results"]
        assert emitted["partialFingerprints"] == {"primaryLocationLineHash": "abc:1"}
        assert emitted["fingerprints"] == {"stable": "xyz"}


class TestUploadLimits:
    def test_locations_are_cut_at_what_github_includes(self, reporter):
        result = _result("R1", "a")
        result.locations = [_location(f"src/f{i}.py", i + 1) for i in range(150)]

        doc = json.loads(reporter.report(_model(_run([result], []))))["runs"][0]

        assert len(doc["results"][0]["locations"]) == 100

    def test_tags_are_cut_at_what_github_includes(self, reporter):
        run = _run(
            [_result("R1", "a")],
            [
                ToolComponent(
                    name="a",
                    rules=[_rule("R1", "t", tags=[f"t{i}" for i in range(15)])],
                )
            ],
        )

        doc = json.loads(reporter.report(_model(run)))["runs"][0]

        (rule,) = doc["tool"]["driver"]["rules"]
        assert rule["properties"]["tags"] == [f"t{i}" for i in range(10)]

    def test_results_past_the_cap_are_the_least_severe(self, reporter, monkeypatch):
        monkeypatch.setattr(github_ghas_reporter, "_MAX_RESULTS_PER_RUN", 2)
        results = [
            Result(ruleId="NOTE", level=Level.note, message=Message(text="n")),
            Result(ruleId="ERROR", level=Level.error, message=Message(text="e")),
            Result(ruleId="WARNING", level=Level.warning, message=Message(text="w")),
        ]

        doc = json.loads(reporter.report(_model(_run(results, []))))["runs"][0]

        assert [r["ruleId"] for r in doc["results"]] == ["ERROR", "WARNING"]

    def test_a_critical_past_the_cap_survives_an_earlier_high(
        self, reporter, monkeypatch
    ):
        # CRITICAL and HIGH are both the SARIF level `error`; only the severity
        # the gate grades them at (issue_severity first) tells them apart.
        monkeypatch.setattr(github_ghas_reporter, "_MAX_RESULTS_PER_RUN", 1)
        results = [
            Result(
                ruleId="HIGH-ONE",
                level=Level.error,
                message=Message(text="h"),
                properties=PropertyBag(issue_severity="HIGH"),
            ),
            Result(
                ruleId="CRITICAL-ONE",
                level=Level.error,
                message=Message(text="c"),
                properties=PropertyBag(issue_severity="CRITICAL"),
            ),
        ]

        doc = json.loads(reporter.report(_model(_run(results, []))))["runs"][0]

        assert [r["ruleId"] for r in doc["results"]] == ["CRITICAL-ONE"]

    def test_a_rule_whose_results_were_all_cut_is_not_scored_from_them(
        self, reporter, monkeypatch
    ):
        monkeypatch.setattr(github_ghas_reporter, "_MAX_RESULTS_PER_RUN", 1)
        results = [
            Result(
                ruleId="CUT",
                level=Level.error,
                message=Message(text="h"),
                properties=PropertyBag(issue_severity="HIGH"),
            ),
            Result(
                ruleId="KEPT",
                level=Level.error,
                message=Message(text="c"),
                properties=PropertyBag(issue_severity="CRITICAL"),
            ),
        ]
        extensions = [
            ToolComponent(name="a", rules=[_rule("CUT", "c"), _rule("KEPT", "k")])
        ]

        doc = json.loads(reporter.report(_model(_run(results, extensions))))["runs"][0]

        assert [r["ruleId"] for r in doc["results"]] == ["KEPT"]
        scores = {
            rule["id"]: rule["properties"]["security-severity"]
            for rule in doc["tool"]["driver"]["rules"]
        }
        # CUT has no result in the file and no scanner score or default level,
        # so it takes the fallback, not the 8.0 its cut HIGH result would give.
        assert scores == {"KEPT": "9.5", "CUT": "6.0"}

    def test_rules_no_result_names_go_first_past_the_cap(self, reporter, monkeypatch):
        monkeypatch.setattr(github_ghas_reporter, "_MAX_RULES_PER_RUN", 2)
        run = _run(
            [_result("USED", "a")],
            [
                ToolComponent(
                    name="a",
                    rules=[
                        _rule("UNUSED-1", "u"),
                        _rule("USED", "u"),
                        _rule("UNUSED-2", "u"),
                    ],
                )
            ],
        )

        doc = json.loads(reporter.report(_model(run)))["runs"][0]

        ids = [rule["id"] for rule in doc["tool"]["driver"]["rules"]]
        assert ids[0] == "USED"
        assert len(ids) == 2
