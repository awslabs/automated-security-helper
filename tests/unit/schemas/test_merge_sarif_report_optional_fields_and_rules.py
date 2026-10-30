# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``merge_sarif_report`` reads the fields its own schema declares optional.

A SARIF file may write ``invocations``, ``inlineExternalProperties`` and
``properties`` as null, and the model validates each to None; the merge
extended or dereferenced them as lists and objects, raising TypeError or
AttributeError after the runs were already merged. Report-level ``tags``, a
field the schema describes as a set of distinct strings, were concatenated on
every merge. A result that named its rule by ``ruleIndex`` alone lost the
association when the index was dropped, and a ``rule`` reference kept an
``index`` and a ``toolComponent`` that point into the incoming run's arrays.
And a scanner's own ``tool.extensions``, which can carry the rules its results
name, were never folded in.
"""

from __future__ import annotations

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Run,
    SarifReport,
)

pytestmark = pytest.mark.unit


def _finding(rule_id: str | None = None, **extra) -> dict:
    result = {"message": {"text": "a finding"}}
    if rule_id is not None:
        result["ruleId"] = rule_id
    result.update(extra)
    return result


def _run(driver: str, results, invocations=None, rules=None, extensions=None) -> Run:
    tool = {"driver": {"name": driver}}
    if rules is not None:
        tool["driver"]["rules"] = rules
    if extensions is not None:
        tool["extensions"] = extensions
    return Run(tool=tool, results=results, invocations=invocations)


class TestNullOptionalFieldsMerge:
    def test_null_invocations_on_the_incoming_run_merge_as_none(self):
        aggregated = SarifReport(
            runs=[_run("aggregate", [], [{"executionSuccessful": True}])]
        )
        incoming = SarifReport(runs=[_run("tool", [_finding("T-1")], None)])
        assert incoming.runs[0].invocations is None

        aggregated.merge_sarif_report(incoming)

        assert [r.ruleId for r in aggregated.runs[0].results] == ["T-1"]
        assert len(aggregated.runs[0].invocations) == 1

    def test_null_report_level_lists_on_either_side_merge(self):
        aggregated = SarifReport.model_validate(
            {
                "runs": [_run("aggregate", [], []).model_dump(exclude_unset=True)],
                "inlineExternalProperties": None,
                "properties": None,
            }
        )
        assert aggregated.inlineExternalProperties is None
        assert aggregated.properties is None
        incoming = SarifReport.model_validate(
            {
                "runs": [
                    _run("tool", [_finding("T-1")], []).model_dump(exclude_unset=True)
                ],
                "inlineExternalProperties": None,
                "properties": None,
            }
        )

        aggregated.merge_sarif_report(incoming)

        assert [r.ruleId for r in aggregated.runs[0].results] == ["T-1"]

    def test_incoming_tags_reach_a_report_whose_properties_are_null(self):
        aggregated = SarifReport.model_validate(
            {
                "runs": [_run("aggregate", [], []).model_dump(exclude_unset=True)],
                "properties": None,
            }
        )
        incoming = SarifReport(
            runs=[_run("tool", [], [])], properties={"tags": ["scanner:tool"]}
        )

        aggregated.merge_sarif_report(incoming)

        assert aggregated.properties.tags == ["scanner:tool"]


class TestReportTagsAreDistinct:
    def test_a_tag_both_reports_carry_is_listed_once(self):
        aggregated = SarifReport(
            runs=[_run("aggregate", [], [])], properties={"tags": ["shared", "a"]}
        )
        incoming = SarifReport(
            runs=[_run("tool", [], [])], properties={"tags": ["shared", "b", "b"]}
        )

        aggregated.merge_sarif_report(incoming)

        assert aggregated.properties.tags == ["shared", "a", "b"]

    def test_merging_the_same_report_twice_adds_no_tag(self):
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(runs=[_run("tool", [], [])], properties={"tags": ["t"]})

        aggregated.merge_sarif_report(incoming)
        aggregated.merge_sarif_report(incoming)

        assert aggregated.properties.tags == ["t"]


class TestResultsKeepTheirRuleById:
    def test_a_result_named_by_rule_index_alone_gains_its_rule_id(self):
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[
                _run(
                    "tool",
                    [_finding(None, ruleIndex=1)],
                    [],
                    rules=[{"id": "T-0"}, {"id": "T-1"}],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        merged = aggregated.runs[0].results[0]
        assert merged.ruleId == "T-1"
        assert "ruleIndex" not in merged.model_fields_set

    def test_a_rule_reference_by_index_into_the_driver_gains_its_rule_id(self):
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[
                _run(
                    "tool",
                    [_finding(None, rule={"index": 0})],
                    [],
                    rules=[{"id": "T-0"}],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        merged = aggregated.runs[0].results[0]
        assert merged.ruleId == "T-0"
        # The reference carried neither id nor guid, so without its index it
        # names nothing and is dropped rather than left pointing into the
        # incoming run's rules.
        assert merged.rule is None

    def test_a_rule_reference_keeps_its_id_and_loses_the_run_scoped_indices(self):
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[
                _run(
                    "tool",
                    [
                        _finding(
                            "T-0",
                            rule={
                                "id": "T-0",
                                "index": 3,
                                "toolComponent": {"index": 2, "name": "pack"},
                            },
                        )
                    ],
                    [],
                    rules=[{"id": "T-0"}],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        merged = aggregated.runs[0].results[0]
        assert merged.ruleId == "T-0"
        reference = merged.rule.root.model_dump(exclude_unset=True)
        assert reference == {"id": "T-0"}

    def test_a_rule_index_with_a_tool_component_reads_that_components_rules(self):
        """SARIF 3.27.6: ruleIndex indexes the component rule.toolComponent names."""
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[
                _run(
                    "tool",
                    [_finding(None, ruleIndex=1, rule={"toolComponent": {"index": 0}})],
                    [],
                    rules=[{"id": "D-0"}, {"id": "D-1"}],
                    extensions=[
                        {"name": "pack", "rules": [{"id": "P-0"}, {"id": "P-1"}]}
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        assert aggregated.runs[0].results[0].ruleId == "P-1"

    def test_a_tool_component_named_without_an_index_is_found_by_name(self):
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[
                _run(
                    "tool",
                    [
                        _finding(
                            None, rule={"index": 1, "toolComponent": {"name": "pack"}}
                        )
                    ],
                    [],
                    rules=[{"id": "D-0"}, {"id": "D-1"}],
                    extensions=[
                        {"name": "pack", "rules": [{"id": "P-0"}, {"id": "P-1"}]}
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        assert aggregated.runs[0].results[0].ruleId == "P-1"

    def test_the_references_own_id_wins_over_the_driver_index(self):
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[
                _run(
                    "tool",
                    [_finding(None, ruleIndex=0, rule={"id": "R-named"})],
                    [],
                    rules=[{"id": "D-0"}],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        assert aggregated.runs[0].results[0].ruleId == "R-named"

    def test_a_component_this_run_does_not_carry_leaves_the_rule_id_unset(self):
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[
                _run(
                    "tool",
                    [_finding(None, ruleIndex=0, rule={"toolComponent": {"index": 7}})],
                    [],
                    rules=[{"id": "D-0"}],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        assert aggregated.runs[0].results[0].ruleId is None

    def test_a_result_with_a_rule_id_keeps_it(self):
        """The control: a result already named by id is left as it was."""
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[
                _run("tool", [_finding("T-9", ruleIndex=0)], [], rules=[{"id": "T-0"}])
            ]
        )

        aggregated.merge_sarif_report(incoming)

        assert aggregated.runs[0].results[0].ruleId == "T-9"


class TestTheIncomingRunsExtensionsAreFolded:
    def test_an_extension_of_the_incoming_run_joins_the_aggregate(self):
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[
                _run(
                    "tool",
                    [_finding("P-1")],
                    [],
                    rules=[],
                    extensions=[{"name": "rule-pack", "rules": [{"id": "P-1"}]}],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        names = [ext.name for ext in aggregated.runs[0].tool.extensions]
        assert names == ["tool", "rule-pack"]
        pack = aggregated.runs[0].tool.extensions[1]
        assert [rule.id for rule in pack.rules] == ["P-1"]
        # A copy, not the incoming object.
        assert pack is not incoming.runs[0].tool.extensions[0]

    def test_an_extension_already_present_unions_its_rules(self):
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        first = SarifReport(
            runs=[
                _run(
                    "tool",
                    [],
                    [],
                    extensions=[{"name": "rule-pack", "rules": [{"id": "P-1"}]}],
                )
            ]
        )
        second = SarifReport(
            runs=[
                _run(
                    "tool",
                    [],
                    [],
                    extensions=[
                        {"name": "rule-pack", "rules": [{"id": "P-1"}, {"id": "P-2"}]}
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(first)
        aggregated.merge_sarif_report(second)

        packs = [
            ext for ext in aggregated.runs[0].tool.extensions if ext.name == "rule-pack"
        ]
        assert len(packs) == 1
        assert [rule.id for rule in packs[0].rules] == ["P-1", "P-2"]
