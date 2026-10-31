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

from pathlib import Path

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

    @pytest.mark.parametrize(
        ("aggregate_side", "incoming_side", "expected"),
        [(None, 1, 1), (1, None, 1), (None, None, 0)],
        ids=["aggregate-null", "incoming-null", "both-null"],
    )
    def test_invocations_merge_from_either_null_side(
        self, aggregate_side, incoming_side, expected
    ):
        """The test above covers an incoming None into an aggregate list only;
        an aggregate None receiving a list is where an extend on None raises,
        and both None at once is the shape every ``_run_with_tables`` run has."""

        def invocations(side):
            if side is None:
                return None
            return [{"executionSuccessful": True} for _ in range(side)]

        aggregated = SarifReport(
            runs=[_run("aggregate", [], invocations(aggregate_side))]
        )
        incoming = SarifReport(
            runs=[_run("tool", [_finding("T-1")], invocations(incoming_side))]
        )

        aggregated.merge_sarif_report(incoming)

        assert [r.ruleId for r in aggregated.runs[0].results] == ["T-1"]
        assert len(aggregated.runs[0].invocations or []) == expected

    @pytest.mark.parametrize(
        ("aggregate_side", "incoming_side", "expected"),
        [
            (None, 1, 1),
            (1, None, 1),
            (None, None, 0),
        ],
        ids=["aggregate-null", "incoming-null", "both-null"],
    )
    def test_inline_external_properties_merge_from_either_null_side(
        self, aggregate_side, incoming_side, expected
    ):
        """The merged value is asserted, not only the results: a guard that
        skipped the field whenever the aggregate side was None would pass the
        incoming-null and both-null cases and still lose an incoming list over
        an aggregate None, which is what the aggregate-null case catches."""

        def report(driver, results, side):
            return SarifReport.model_validate(
                {
                    "runs": [_run(driver, results, []).model_dump(exclude_unset=True)],
                    "inlineExternalProperties": (
                        None
                        if side is None
                        else [{"version": "2.1.0"} for _ in range(side)]
                    ),
                }
            )

        aggregated = report("aggregate", [], aggregate_side)
        incoming = report("tool", [_finding("T-1")], incoming_side)

        aggregated.merge_sarif_report(incoming)

        assert [r.ruleId for r in aggregated.runs[0].results] == ["T-1"]
        merged = aggregated.inlineExternalProperties or []
        assert len(merged) == expected
        if incoming_side is not None:
            # A copy of the incoming item, not the item itself.
            item = incoming.inlineExternalProperties[0]
            assert merged[-1] is not item
            assert merged[-1].model_dump(exclude_none=True) == item.model_dump(
                exclude_none=True
            )

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

        # A copy, not the incoming bag: a later merge's tags must not reach the
        # report that was merged first.
        later = SarifReport(
            runs=[_run("other", [], [])], properties={"tags": ["other"]}
        )
        aggregated.merge_sarif_report(later)
        assert aggregated.properties.tags == ["scanner:tool", "other"]
        assert incoming.properties.tags == ["scanner:tool"]


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

    @pytest.mark.parametrize(
        ("finding", "extensions", "expected"),
        [
            (_finding(None, ruleIndex=1), None, "D-1"),
            (_finding(None, rule={"index": 1}), None, "D-1"),
            (
                _finding(
                    None, ruleIndex=1, rule={"index": -1, "toolComponent": {"index": 0}}
                ),
                [
                    {
                        "name": "pack",
                        "rules": [{"id": "P-0"}, {"id": "P-1"}, {"id": "P-2"}],
                    }
                ],
                "P-1",
            ),
            (
                _finding(None, rule={"index": 1, "toolComponent": {"name": "pack"}}),
                [
                    {
                        "name": "pack",
                        "rules": [{"id": "P-0"}, {"id": "P-1"}, {"id": "P-2"}],
                    }
                ],
                "P-1",
            ),
        ],
        ids=["ruleIndex", "rule.index", "component-by-index", "component-by-name"],
    )
    def test_a_middle_index_names_the_middle_rule(self, finding, extensions, expected):
        """Every positive case elsewhere reads the LAST rule of its array, which
        ``rules[-1]`` also returns, so code that indexed with SARIF's "no index"
        value of -1 passed them all. Three rules and the middle one here."""
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[
                _run(
                    "tool",
                    [finding],
                    [],
                    rules=[{"id": "D-0"}, {"id": "D-1"}, {"id": "D-2"}],
                    extensions=extensions,
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        assert aggregated.runs[0].results[0].ruleId == expected

    @pytest.mark.parametrize(
        "finding",
        [_finding(None), _finding(None, ruleIndex=-1), _finding(None, ruleIndex=5)],
        ids=["nothing-named", "index-minus-one", "index-past-the-rules"],
    )
    def test_a_result_naming_no_rule_keeps_no_rule_id(self, finding):
        """The negative controls: no id, SARIF's -1, and an index past the
        driver's rules each leave the id unset and raise no IndexError."""
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[_run("tool", [finding], [], rules=[{"id": "D-0"}, {"id": "D-1"}])]
        )

        aggregated.merge_sarif_report(incoming)

        assert aggregated.runs[0].results[0].ruleId is None

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
        # This driver is not the aggregate's, so the merge adds it to the
        # aggregate's extensions and T-0's descriptor lives there.
        extensions = aggregated.runs[0].tool.extensions
        assert [extension.name for extension in extensions] == ["tool"]
        assert [rule.id for rule in extensions[0].rules] == ["T-0"]
        # The reference carried neither id nor guid, so without its index it
        # names nothing and is dropped rather than left pointing into the
        # incoming run's rules. It named no component, which SARIF 3.52.7 reads
        # as the driver's, and it is left that way on purpose: the merge keeps
        # a component name only when the scanner wrote one. A result that names
        # its rule by ruleId alone carries no reference at all and reads as the
        # driver's in the same way, so the ruleId is the key that finds this
        # rule in the merged report. Naming the "tool" extension here would
        # attribute this one reference and none of the tool's other results.
        # A reference into an extension is the next test.
        assert merged.rule is None

    def test_a_reference_into_the_aggregates_own_driver_gains_its_rule_id(self):
        """The control for the test above: when the incoming driver is the
        aggregate's own, its rules join the driver, no extension is added, and a
        reference with no component reads as the driver's exactly."""
        aggregated = SarifReport(runs=[_run("tool", [], [])])
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
        assert merged.rule is None
        assert not aggregated.runs[0].tool.extensions
        assert [rule.id for rule in aggregated.runs[0].tool.driver.rules] == ["T-0"]

    def test_an_index_only_reference_into_an_extension_keeps_its_component(self):
        """The counterpart of the driver case above: a reference that names an
        extension by name, with an index and no id, gains the rule's id from the
        result and keeps the component's name. Dropped whole, the merged result
        carried the id with nothing saying which component it came from, and
        read as the driver's rule."""
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

        merged = aggregated.runs[0].results[0]
        assert merged.ruleId == "P-1"
        reference = merged.rule.root.model_dump(exclude_unset=True)
        assert reference["id"] == "P-1"
        assert reference["toolComponent"] == {"name": "pack"}
        assert "index" not in reference

    @staticmethod
    def _merged_reference(rule: dict, rule_id: str):
        """The merged result of one finding that states *rule_id* and names its
        rule by *rule*, from a run whose extension ``pack`` holds the rules
        ``P-0`` and ``CA2101``."""
        pack = {"name": "pack", "rules": [{"id": "P-0"}, {"id": "CA2101"}]}
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[
                _run(
                    "tool",
                    [_finding(rule_id, rule=rule)],
                    [],
                    rules=[{"id": "D-0"}],
                    extensions=[pack],
                )
            ]
        )
        aggregated.merge_sarif_report(incoming)
        return aggregated.runs[0].results[0]

    def test_a_reference_into_an_extension_takes_the_id_of_the_rule_its_index_names(
        self,
    ):
        """The scanner wrote its own ``ruleId`` (``X-9``) and a reference whose
        index names the extension's rule ``CA2101``. The reference means that
        rule, so it keeps ``CA2101``; the result's ruleId stays as written."""
        merged = self._merged_reference(
            {"index": 1, "toolComponent": {"name": "pack"}}, "X-9"
        )

        assert merged.ruleId == "X-9"
        reference = merged.rule.root.model_dump(exclude_unset=True)
        assert reference["id"] == "CA2101"
        assert reference["toolComponent"] == {"name": "pack"}

    def test_a_hierarchical_rule_id_does_not_become_the_references_id(self):
        """``CA2101/1`` is a sub-rule id some scanners write on the result; the
        component's rule is ``CA2101``, which is what the reference names."""
        merged = self._merged_reference(
            {"index": 1, "toolComponent": {"name": "pack"}}, "CA2101/1"
        )

        assert merged.ruleId == "CA2101/1"
        assert merged.rule.root.model_dump(exclude_unset=True)["id"] == "CA2101"

    def test_a_reference_into_a_component_the_run_lacks_is_dropped(self):
        """A reference that names an extension the incoming run does not carry
        points at nothing in the merged run, and the result's ruleId is not a
        reason to give it an id: it is dropped, as it was before the id was
        borrowed from the result."""
        merged = self._merged_reference(
            {"index": 0, "toolComponent": {"name": "ghost"}}, "X-9"
        )

        assert merged.ruleId == "X-9"
        assert merged.rule is None

    def test_an_index_that_names_no_rule_falls_back_to_the_results_rule_id(self):
        """The control: the component is the run's own and the index runs past
        its rules, so the result's ruleId is the only id there is."""
        merged = self._merged_reference(
            {"index": 5, "toolComponent": {"name": "pack"}}, "X-9"
        )

        reference = merged.rule.root.model_dump(exclude_unset=True)
        assert reference["id"] == "X-9"
        assert reference["toolComponent"] == {"name": "pack"}

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
        assert reference["id"] == "T-0"
        assert "index" not in reference
        # The component reference loses its index, which counted a position in
        # the incoming run's extensions, and keeps its name: a reference with no
        # component reads as the driver's (SARIF 3.52.7), which after the merge is
        # the aggregate's own, so dropping it whole re-attributed the rule.
        assert reference["toolComponent"] == {"name": "pack"}
        # The match is exact on purpose: the nested reference holds its name and
        # nothing else, so a guid or index carried over as None would fail it.
        # The dump is of the fields the rebuilt reference was given, and the
        # merge hands it only the keys that held a value.

    def test_an_index_only_component_reference_takes_the_components_name(self):
        """A component reference with an index alone pointed into the incoming
        run's extensions; dropping it whole made the rule read as the DRIVER's
        (SARIF 3.52.7) when it came from an extension. The name is read from
        the run's tool before the index goes."""
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[
                _run(
                    "tool",
                    [
                        _finding(
                            "T-0", rule={"id": "T-0", "toolComponent": {"index": 0}}
                        )
                    ],
                    [],
                    extensions=[{"name": "pack", "rules": [{"id": "T-0"}]}],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        reference = (
            aggregated.runs[0].results[0].rule.root.model_dump(exclude_unset=True)
        )
        assert reference["id"] == "T-0"
        assert reference["toolComponent"] == {"name": "pack"}

    def test_a_component_reference_naming_only_an_index_is_dropped(self):
        """The control: with no name and no guid, and an index past the run's
        extensions (it carries none), the component reference names nothing the
        aggregate can read, so it goes with its index."""
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[
                _run(
                    "tool",
                    [
                        _finding(
                            "T-0", rule={"id": "T-0", "toolComponent": {"index": 1}}
                        )
                    ],
                    [],
                    rules=[{"id": "T-0"}],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        reference = (
            aggregated.runs[0].results[0].rule.root.model_dump(exclude_unset=True)
        )
        assert reference["id"] == "T-0"
        assert "toolComponent" not in reference

    def test_a_rule_index_with_a_tool_component_reads_that_components_rules(self):
        """SARIF 3.27.6: ruleIndex indexes the component rule.toolComponent names.

        A reportingDescriptorReference carries one of index, guid or id (the
        schema's anyOf), so a reference that only names the component spells its
        own index as -1, SARIF's absent value, and ruleIndex is the index.
        """
        aggregated = SarifReport(runs=[_run("aggregate", [], [])])
        incoming = SarifReport(
            runs=[
                _run(
                    "tool",
                    [
                        _finding(
                            None,
                            ruleIndex=1,
                            rule={"index": -1, "toolComponent": {"index": 0}},
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
                    [
                        _finding(
                            None,
                            ruleIndex=0,
                            rule={"index": -1, "toolComponent": {"index": 7}},
                        )
                    ],
                    [],
                    rules=[{"id": "D-0"}],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        assert aggregated.runs[0].results[0].ruleId is None

    def test_a_rule_references_set_fields_survive_and_its_unset_ones_stay_unset(
        self,
    ):
        """The merged copy is built from a full dump of the result, which names
        every field of the reference, the unset ones as None; the copy must not
        read those as set, and must keep the ones the scanner did set."""
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
                                "index": 0,
                                "properties": {"tags": ["kept"]},
                            },
                        )
                    ],
                    [],
                    rules=[{"id": "T-0"}],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        reference = aggregated.runs[0].results[0].rule.root
        assert reference.model_fields_set == {"id", "properties"}
        assert reference.properties.tags == ["kept"]

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


def _located(uri=None, index=None, uri_base_id=None, **extra) -> dict:
    artifact: dict = {}
    if uri is not None:
        artifact["uri"] = uri
    if index is not None:
        artifact["index"] = index
    if uri_base_id is not None:
        artifact["uriBaseId"] = uri_base_id
    location = {"physicalLocation": {"artifactLocation": artifact}}
    location.update(extra)
    return _finding("T-1", locations=[location])


def _run_with_tables(
    driver: str,
    results,
    artifacts=None,
    bases=None,
    logical=None,
    steps=None,
    extensions=None,
    web_requests=None,
    addresses=None,
    taxonomies=None,
    web_responses=None,
) -> Run:
    """A run whose own tables the folded results used to point into."""
    fields: dict = {"tool": {"driver": {"name": driver}}, "results": results}
    if extensions is not None:
        fields["tool"]["extensions"] = extensions
    if taxonomies is not None:
        fields["taxonomies"] = taxonomies
    if artifacts is not None:
        fields["artifacts"] = [{"location": {"uri": uri}} for uri in artifacts]
    if logical is not None:
        fields["logicalLocations"] = logical
    if steps is not None:
        fields["threadFlowLocations"] = steps
    if web_requests is not None:
        fields["webRequests"] = web_requests
    if web_responses is not None:
        fields["webResponses"] = web_responses
    if addresses is not None:
        fields["addresses"] = addresses
    if bases is not None:
        # A plain string is the base's uri; a dict is the whole definition, for
        # a base that sits on another (``{"uri": "src/", "uriBaseId": "REPOROOT"}``).
        fields["originalUriBaseIds"] = {
            key: (value if isinstance(value, dict) else {"uri": value})
            for key, value in bases.items()
        }
    return Run(**fields)


def _first_artifact_location(report: SarifReport, position: int = 0):
    result = report.runs[0].results[position]
    return result.locations[0].physicalLocation.root.artifactLocation


class TestFoldedResultsLeaveTheirRunsTablesBehind:
    """A later run's results are folded into runs[0], which has other tables.

    ``ruleIndex`` was already dropped for this reason. The artifact index, the
    logical-location index and the ``uriBaseId`` pointed into the incoming run's
    ``artifacts``, ``logicalLocations`` and ``originalUriBaseIds`` just the same.
    """

    def test_an_artifact_named_by_index_alone_takes_its_uri_from_its_own_run(self):
        aggregated = SarifReport(
            runs=[_run_with_tables("aggregate", [], artifacts=["first/a.py"])]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables("tool", [_located(index=0)], artifacts=["second/b.py"])
            ]
        )

        aggregated.merge_sarif_report(incoming)

        location = _first_artifact_location(aggregated)
        assert location.uri == "second/b.py"
        assert location.index in (None, -1)

    def test_a_located_artifact_loses_the_index_and_keeps_its_uri(self):
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool", [_located(uri="src/x.py", index=0)], artifacts=["src/x.py"]
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        location = _first_artifact_location(aggregated)
        assert location.uri == "src/x.py"
        assert location.index in (None, -1)

    def test_a_base_id_the_two_runs_define_differently_is_expanded(self):
        aggregated = SarifReport(
            runs=[
                _run_with_tables(
                    "aggregate", [], bases={"SRCROOT": "file:///repo-one/"}
                )
            ]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [_located(uri="src/x.py", uri_base_id="SRCROOT")],
                    bases={"SRCROOT": "file:///repo-two/"},
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        location = _first_artifact_location(aggregated)
        assert location.uri == "file:///repo-two/src/x.py"
        assert location.uriBaseId is None
        # The aggregate's own definition is untouched.
        assert aggregated.runs[0].originalUriBaseIds["SRCROOT"].uri == (
            "file:///repo-one/"
        )

    def test_a_base_id_only_the_incoming_run_defines_is_expanded_not_folded(self):
        """Folding the definition into the aggregate's table set the id for every
        run that used it without defining it, so the uri is expanded instead and
        the aggregate's table stays as it was."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [_located(uri="src/x.py", uri_base_id="TARGET")],
                    bases={"TARGET": "file:///target/"},
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        location = _first_artifact_location(aggregated)
        assert location.uri == "file:///target/src/x.py"
        assert location.uriBaseId is None
        assert aggregated.runs[0].originalUriBaseIds is None

    def test_a_later_run_using_the_id_without_defining_it_is_not_re_rooted(self):
        """The shape behind the fold: scanner A defines TARGET, scanner B uses it
        without defining it. With A's definition copied into the aggregate, B's
        result read A's root. B's location is left as written, over no table."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        defines = SarifReport(
            runs=[
                _run_with_tables(
                    "tool-a",
                    [_located(uri="a.py", uri_base_id="TARGET")],
                    bases={"TARGET": "file:///tool-a-root/"},
                )
            ]
        )
        uses = SarifReport(
            runs=[
                _run_with_tables("tool-b", [_located(uri="b.py", uri_base_id="TARGET")])
            ]
        )

        aggregated.merge_sarif_report(defines)
        aggregated.merge_sarif_report(uses)

        location = _first_artifact_location(aggregated, position=1)
        assert (location.uri, location.uriBaseId) == ("b.py", "TARGET")
        assert aggregated.runs[0].originalUriBaseIds is None

    def test_a_chain_that_differs_below_an_equal_first_link_is_expanded(self):
        """Two SRCROOTs spelled alike that sit on different REPOROOTs name
        different places; comparing the first link alone read them as equal."""
        aggregated = SarifReport(
            runs=[
                _run_with_tables(
                    "aggregate",
                    [],
                    bases={
                        "SRCROOT": {"uri": "src/", "uriBaseId": "REPOROOT"},
                        "REPOROOT": "file:///repo-one/",
                    },
                )
            ]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [_located(uri="x.py", uri_base_id="SRCROOT")],
                    bases={
                        "SRCROOT": {"uri": "src/", "uriBaseId": "REPOROOT"},
                        "REPOROOT": "file:///repo-two/",
                    },
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        location = _first_artifact_location(aggregated)
        assert location.uri == "file:///repo-two/src/x.py"
        assert location.uriBaseId is None
        assert aggregated.runs[0].originalUriBaseIds["REPOROOT"].uri == (
            "file:///repo-one/"
        )

    def test_a_chain_both_runs_define_alike_is_kept(self):
        """The control: the same two links on both sides keep the id."""
        chain = {
            "SRCROOT": {"uri": "src/", "uriBaseId": "REPOROOT"},
            "REPOROOT": "file:///repo/",
        }
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [], bases=chain)])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool", [_located(uri="x.py", uri_base_id="SRCROOT")], bases=chain
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        location = _first_artifact_location(aggregated)
        assert (location.uri, location.uriBaseId) == ("x.py", "SRCROOT")

    @pytest.mark.parametrize(
        ("bases", "expected"),
        [
            pytest.param(
                {"SRCROOT": {"uri": "src/", "uriBaseId": "SRCROOT"}},
                ("x.py", "SRCROOT"),
                id="self-reference",
            ),
            pytest.param(
                {
                    "A": {"uri": "a/", "uriBaseId": "B"},
                    "B": {"uri": "b/", "uriBaseId": "A"},
                },
                ("x.py", "A"),
                id="two-link-cycle",
            ),
            pytest.param(
                {"SRCROOT": {"uri": "src/", "uriBaseId": "GONE"}},
                ("src/x.py", "GONE"),
                id="dangling-link",
            ),
        ],
    )
    def test_a_malformed_base_chain_does_not_abort_the_merge(self, bases, expected):
        """A scanner's SARIF can define a base that names itself, two bases that
        name each other, or a base on one the run never defines. The walk over
        the chain keeps a visited set, so each ends: the merge finishes, the
        result is kept, and the location is left as written when the chain cannot
        be expanded, or expanded as far as it goes (a dangling link keeps its
        last id). A walker without the set would loop on the first two."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        start = next(iter(bases))
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool", [_located(uri="x.py", uri_base_id=start)], bases=bases
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        assert len(aggregated.runs[0].results) == 1
        location = _first_artifact_location(aggregated)
        assert (location.uri, location.uriBaseId) == expected

    def test_a_longer_chain_in_the_aggregate_than_in_the_incoming_run_is_expanded(
        self,
    ):
        """The reverse of the chain that differs below an equal first link: the
        aggregate's SRCROOT sits on a REPOROOT and the incoming run's stands
        alone. They name the same place by different routes, but a definition
        that differs is not the same base here, so the incoming location is
        expanded from its own definition and the aggregate's table is left as
        it was."""
        aggregated = SarifReport(
            runs=[
                _run_with_tables(
                    "aggregate",
                    [],
                    bases={
                        "SRCROOT": {"uri": "src/", "uriBaseId": "REPOROOT"},
                        "REPOROOT": "file:///repo/",
                    },
                )
            ]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [_located(uri="x.py", uri_base_id="SRCROOT")],
                    bases={"SRCROOT": "file:///repo/src/"},
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        location = _first_artifact_location(aggregated)
        assert location.uri == "file:///repo/src/x.py"
        assert location.uriBaseId is None
        assert aggregated.runs[0].originalUriBaseIds["REPOROOT"].uri == (
            "file:///repo/"
        )

    def test_a_base_without_a_trailing_slash_is_expanded_with_one(self):
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [_located(uri="src/x.py", uri_base_id="SRCROOT")],
                    bases={"SRCROOT": "file:///repo-two"},
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        location = _first_artifact_location(aggregated)
        assert location.uri == "file:///repo-two/src/x.py"
        assert location.uriBaseId is None

    def test_a_base_with_no_uri_both_runs_declare_is_kept(self):
        """SARIF lets a base be declared without a uri, for the consumer to
        supply; two identical declarations read as the same base and the id
        stays on the location."""
        declared = {"SRCROOT": {"description": {"text": "the consumer's root"}}}
        aggregated = SarifReport(
            runs=[_run_with_tables("aggregate", [], bases=declared)]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [_located(uri="src/x.py", uri_base_id="SRCROOT")],
                    bases=declared,
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        location = _first_artifact_location(aggregated)
        assert (location.uri, location.uriBaseId) == ("src/x.py", "SRCROOT")

    def test_a_base_with_no_uri_only_the_incoming_run_declares_is_left_as_written(
        self,
    ):
        """Nothing to expand with and nothing is added to the aggregate's table,
        so the location keeps its id as the scanner wrote it."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [_located(uri="src/x.py", uri_base_id="SRCROOT")],
                    bases={"SRCROOT": {"description": {"text": "the consumer's root"}}},
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        location = _first_artifact_location(aggregated)
        assert (location.uri, location.uriBaseId) == ("src/x.py", "SRCROOT")
        assert aggregated.runs[0].originalUriBaseIds is None

    def test_a_base_id_both_runs_define_alike_is_kept(self):
        aggregated = SarifReport(
            runs=[_run_with_tables("aggregate", [], bases={"SRCROOT": "file:///r/"})]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [_located(uri="src/x.py", uri_base_id="SRCROOT")],
                    bases={"SRCROOT": "file:///r/"},
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        location = _first_artifact_location(aggregated)
        assert (location.uri, location.uriBaseId) == ("src/x.py", "SRCROOT")

    def test_a_logical_location_keeps_its_name_and_loses_its_index(self):
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _located(
                            uri="src/x.py",
                            logicalLocations=[{"name": "handler", "index": 3}],
                        )
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        logical = aggregated.runs[0].results[0].locations[0].logicalLocations[0]
        assert logical.name == "handler"
        assert logical.index in (None, -1)

    def test_an_index_only_logical_location_takes_its_row_from_the_runs_table(self):
        """SARIF 3.33.3: an index alone means the run's cached row. Dropping the
        index without reading the row left a logical location with no name."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [_located(uri="src/x.py", logicalLocations=[{"index": 1}])],
                    logical=[
                        {"name": "other"},
                        {
                            "name": "handler",
                            "fullyQualifiedName": "pkg.handler",
                            "kind": "function",
                            "parentIndex": 0,
                        },
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        logical = aggregated.runs[0].results[0].locations[0].logicalLocations[0]
        assert (logical.name, logical.fullyQualifiedName, logical.kind) == (
            "handler",
            "pkg.handler",
            "function",
        )
        assert logical.index in (None, -1)
        assert logical.parentIndex in (None, -1)

    def test_an_inline_logical_name_wins_and_the_row_fills_the_rest(self):
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _located(
                            uri="src/x.py",
                            logicalLocations=[{"name": "inline", "index": 0}],
                        )
                    ],
                    logical=[{"name": "cached", "kind": "function"}],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        logical = aggregated.runs[0].results[0].locations[0].logicalLocations[0]
        assert (logical.name, logical.kind) == ("inline", "function")

    def test_an_index_only_thread_flow_step_takes_its_row_from_the_runs_table(self):
        """SARIF 3.38.2, the same shape: a code flow written as indices alone
        became a list of steps with no location."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            codeFlows=[
                                {"threadFlows": [{"locations": [{"index": 0}]}]}
                            ],
                        )
                    ],
                    steps=[
                        {
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/step.py"}
                                }
                            },
                            "module": "m",
                        }
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        step = aggregated.runs[0].results[0].codeFlows[0].threadFlows[0].locations[0]
        artifact = step.location.physicalLocation.root.artifactLocation
        assert (artifact.uri, step.module) == ("src/step.py", "m")
        assert step.index in (None, -1)

    def test_an_index_only_step_takes_the_rows_defaulted_fields_too(self):
        """A step's ``kinds`` and ``taxa`` default to ``[]``, its ``executionOrder``
        to -1 and its ``importance`` to "important", and the dumped step carries
        those defaults as values, not None; a fill that read only None as unset
        left the row's kinds, taxa, order and importance behind."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            codeFlows=[
                                {"threadFlows": [{"locations": [{"index": 0}]}]}
                            ],
                        )
                    ],
                    steps=[
                        {
                            "module": "m",
                            "kinds": ["call", "taint"],
                            "taxa": [{"id": "T-9"}],
                            "executionOrder": 3,
                            "importance": "essential",
                        }
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        step = aggregated.runs[0].results[0].codeFlows[0].threadFlows[0].locations[0]
        assert step.module == "m"
        assert step.kinds == ["call", "taint"]
        assert [taxon.root.id for taxon in step.taxa] == ["T-9"]
        assert step.executionOrder == 3
        assert step.importance == "essential"

    def test_an_inline_steps_own_values_win_over_the_row(self):
        """The control: a value the step states itself is kept, default or not
        in shape, and only the fields it leaves at their defaults take the row's."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            codeFlows=[
                                {
                                    "threadFlows": [
                                        {
                                            "locations": [
                                                {
                                                    "index": 0,
                                                    "kinds": ["return"],
                                                    "executionOrder": 5,
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                        )
                    ],
                    steps=[
                        {
                            "module": "m",
                            "kinds": ["call"],
                            "executionOrder": 3,
                            "importance": "unimportant",
                        }
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        step = aggregated.runs[0].results[0].codeFlows[0].threadFlows[0].locations[0]
        assert (step.kinds, step.executionOrder) == (["return"], 5)
        assert (step.module, step.importance) == ("m", "unimportant")

    def test_an_inline_step_that_states_a_default_reads_as_unset(self):
        """The documented edge of the fill: the dumped step carries a field it
        never set as its default, so a step that STATES the default (an
        ``executionOrder`` of -1, SARIF's own "no order" value, or an empty
        ``kinds``) cannot be told from one that left it out, and takes the row's
        value. A step stating a value that is not the default keeps it, which is
        the control: 0 is a real order and is not replaced."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])

        def step_with(**stated):
            return SarifReport(
                runs=[
                    _run_with_tables(
                        "tool",
                        [
                            _finding(
                                "T-1",
                                codeFlows=[
                                    {
                                        "threadFlows": [
                                            {"locations": [{"index": 0, **stated}]}
                                        ]
                                    }
                                ],
                            )
                        ],
                        steps=[
                            {"module": "m", "kinds": ["call"], "executionOrder": 3}
                        ],
                    )
                ]
            )

        aggregated.merge_sarif_report(step_with(executionOrder=-1, kinds=[]))
        aggregated.merge_sarif_report(step_with(executionOrder=0))

        stated_default, stated_zero = (
            result.codeFlows[0].threadFlows[0].locations[0]
            for result in aggregated.runs[0].results
        )
        assert (stated_default.executionOrder, stated_default.kinds) == (3, ["call"])
        assert (stated_zero.executionOrder, stated_zero.kinds) == (0, ["call"])

    def test_an_index_only_address_takes_the_rows_absolute_address(self):
        """``absoluteAddress`` defaults to -1, so the dumped address carried -1 as
        a value and a None-only fill left the row's offset behind while taking
        its name."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            locations=[{"physicalLocation": {"address": {"index": 0}}}],
                        )
                    ],
                    addresses=[{"absoluteAddress": 4096, "name": ".text"}],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        address = (
            aggregated.runs[0].results[0].locations[0].physicalLocation.root.address
        )
        assert (address.absoluteAddress, address.name) == (4096, ".text")
        assert address.index in (None, -1)

    def test_a_cached_steps_artifact_index_is_resolved_too(self):
        """The row read in can itself name its file by index into run.artifacts;
        the detach that follows resolves it as it does an inline location."""
        aggregated = SarifReport(
            runs=[_run_with_tables("aggregate", [], artifacts=["first/a.py"])]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            codeFlows=[
                                {"threadFlows": [{"locations": [{"index": 0}]}]}
                            ],
                        )
                    ],
                    artifacts=["second/step.py"],
                    steps=[
                        {
                            "location": {
                                "physicalLocation": {"artifactLocation": {"index": 0}}
                            }
                        }
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        step = aggregated.runs[0].results[0].codeFlows[0].threadFlows[0].locations[0]
        artifact = step.location.physicalLocation.root.artifactLocation
        assert artifact.uri == "second/step.py"
        assert artifact.index in (None, -1)

    def test_a_fixs_artifact_change_named_by_index_takes_its_uri(self):
        """The detach reached the primary, related and code-flow locations only;
        a fix, an attachment, a stack frame, a graph node or a provenance source
        that named its file by index still pointed into the incoming run."""
        aggregated = SarifReport(
            runs=[_run_with_tables("aggregate", [], artifacts=["first/a.py"])]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            fixes=[
                                {
                                    "artifactChanges": [
                                        {
                                            "artifactLocation": {"index": 0},
                                            "replacements": [
                                                {"deletedRegion": {"startLine": 1}}
                                            ],
                                        }
                                    ]
                                }
                            ],
                        )
                    ],
                    artifacts=["second/fix.py"],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        change = aggregated.runs[0].results[0].fixes[0].artifactChanges[0]
        assert change.artifactLocation.uri == "second/fix.py"
        assert change.artifactLocation.index in (None, -1)

    def test_an_attachments_location_named_by_index_takes_its_uri(self):
        aggregated = SarifReport(
            runs=[_run_with_tables("aggregate", [], artifacts=["first/a.py"])]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [_finding("T-1", attachments=[{"artifactLocation": {"index": 0}}])],
                    artifacts=["second/shot.png"],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        attachment = aggregated.runs[0].results[0].attachments[0]
        assert attachment.artifactLocation.uri == "second/shot.png"
        assert attachment.artifactLocation.index in (None, -1)

    def test_a_stack_frames_location_named_by_index_takes_its_uri(self):
        aggregated = SarifReport(
            runs=[_run_with_tables("aggregate", [], artifacts=["first/a.py"])]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            stacks=[
                                {
                                    "frames": [
                                        {
                                            "location": {
                                                "physicalLocation": {
                                                    "artifactLocation": {"index": 0}
                                                }
                                            }
                                        }
                                    ]
                                }
                            ],
                        )
                    ],
                    artifacts=["second/frame.py"],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        frame = aggregated.runs[0].results[0].stacks[0].frames[0]
        artifact = frame.location.physicalLocation.root.artifactLocation
        assert artifact.uri == "second/frame.py"
        assert artifact.index in (None, -1)

    def test_a_graph_nodes_location_named_by_index_takes_its_uri(self):
        aggregated = SarifReport(
            runs=[_run_with_tables("aggregate", [], artifacts=["first/a.py"])]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            graphs=[
                                {
                                    "nodes": [
                                        {
                                            "id": "n1",
                                            "location": {
                                                "physicalLocation": {
                                                    "artifactLocation": {"index": 0}
                                                }
                                            },
                                        }
                                    ]
                                }
                            ],
                        )
                    ],
                    artifacts=["second/node.py"],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        node = aggregated.runs[0].results[0].graphs[0].nodes[0]
        artifact = node.location.physicalLocation.root.artifactLocation
        assert artifact.uri == "second/node.py"
        assert artifact.index in (None, -1)

    def test_a_provenance_conversion_source_named_by_index_takes_its_uri(self):
        aggregated = SarifReport(
            runs=[_run_with_tables("aggregate", [], artifacts=["first/a.py"])]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            provenance={
                                "conversionSources": [
                                    {"artifactLocation": {"index": 0}}
                                ]
                            },
                        )
                    ],
                    artifacts=["second/source.sarif"],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        source = aggregated.runs[0].results[0].provenance.conversionSources[0]
        assert source.root.artifactLocation.uri == "second/source.sarif"
        assert source.root.artifactLocation.index in (None, -1)

    def test_a_taxon_named_by_index_gains_its_id_and_loses_the_indices(self):
        """A taxon reference's index points into the taxa of the component its
        toolComponent names, and that reference's own index into the incoming
        run's extensions; neither position exists in the aggregate. The id is
        read from the incoming run and both indices are dropped; the name
        stays, since it names the component by content."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            taxa=[
                                {
                                    "index": 1,
                                    "toolComponent": {"index": 0, "name": "cwe"},
                                }
                            ],
                        )
                    ],
                    extensions=[
                        {"name": "cwe", "taxa": [{"id": "CWE-1"}, {"id": "CWE-79"}]}
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        taxon = aggregated.runs[0].results[0].taxa[0].root
        assert taxon.id == "CWE-79"
        assert taxon.index in (None, -1)
        assert taxon.toolComponent.name == "cwe"
        assert taxon.toolComponent.index in (None, -1)

    def test_a_taxon_whose_component_is_named_by_index_alone_keeps_the_name(self):
        """The component reference carried an index and nothing else, so the
        detach dropped it whole and the taxon read as the driver's while its id
        was read from the extension; the extension's name is taken first."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1", taxa=[{"index": 1, "toolComponent": {"index": 0}}]
                        )
                    ],
                    extensions=[
                        {"name": "cwe", "taxa": [{"id": "CWE-1"}, {"id": "CWE-79"}]}
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        taxon = aggregated.runs[0].results[0].taxa[0].root
        assert taxon.id == "CWE-79"
        assert taxon.toolComponent.name == "cwe"
        assert taxon.toolComponent.index in (None, -1)

    def test_a_taxon_whose_component_index_names_nothing_loses_the_reference(self):
        """The control: an index past the run's extensions names no component,
        so the reference goes, as before."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            taxa=[{"id": "CWE-79", "toolComponent": {"index": 3}}],
                        )
                    ],
                    extensions=[{"name": "cwe", "taxa": [{"id": "CWE-79"}]}],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        taxon = aggregated.runs[0].results[0].taxa[0].root
        assert taxon.id == "CWE-79"
        assert taxon.toolComponent is None

    def test_a_taxon_is_read_from_the_runs_taxonomies_not_its_extensions(self):
        """A result's taxa are categories of a taxonomy, so the component
        reference's index counts positions in ``run.taxonomies``. The run also
        carries an extension at the same position; reading the reference against
        it credited the taxon to the extension with the extension's id."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            taxa=[{"index": 1, "toolComponent": {"index": 0}}],
                        )
                    ],
                    extensions=[
                        {"name": "plugin", "taxa": [{"id": "P-0"}, {"id": "P-1"}]}
                    ],
                    taxonomies=[
                        {"name": "CWE", "taxa": [{"id": "CWE-1"}, {"id": "CWE-79"}]}
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        taxon = aggregated.runs[0].results[0].taxa[0].root
        assert taxon.id == "CWE-79"
        assert taxon.toolComponent.name == "CWE"
        assert taxon.toolComponent.index in (None, -1)

    @staticmethod
    def _merged_taxa(taxa: list, extensions: list):
        """The taxa of the one merged result, from a run that carries the
        taxonomy ``CWE`` (taxa ``CWE-1``, ``CWE-79``) and *extensions*."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [_finding("T-1", taxa=taxa)],
                    extensions=extensions,
                    taxonomies=[
                        {"name": "CWE", "taxa": [{"id": "CWE-1"}, {"id": "CWE-79"}]}
                    ],
                )
            ]
        )
        aggregated.merge_sarif_report(incoming)
        return aggregated.runs[0].results[0].taxa

    def test_a_reference_naming_an_extension_is_not_read_from_a_taxonomy(self):
        """``{"index": 0, "name": "plugin"}`` in a run with a taxonomy at 0 and
        an extension called ``plugin``: the name says the reference means the
        extension, and reading the index against the taxonomy paired the plugin's
        name with CWE's taxon. A reference whose name is the taxonomy's, beside
        it, is still read by its index."""
        extensions = [{"name": "plugin", "taxa": [{"id": "P-0"}, {"id": "P-1"}]}]

        named_plugin = self._merged_taxa(
            [{"index": 1, "toolComponent": {"index": 0, "name": "plugin"}}], extensions
        )
        named_cwe = self._merged_taxa(
            [{"index": 1, "toolComponent": {"index": 0, "name": "CWE"}}], extensions
        )

        assert [(t.root.id, t.root.toolComponent.name) for t in named_plugin] == [
            ("P-1", "plugin")
        ]
        assert [(t.root.id, t.root.toolComponent.name) for t in named_cwe] == [
            ("CWE-79", "CWE")
        ]

    def test_an_index_past_the_taxonomies_is_not_read_against_the_extensions(self):
        """The run has one taxonomy, so a component index of 1 counted a position
        that is not there. Read again as a position in the extensions it credited
        the taxon to the second one; the reference now names nothing and is
        dropped. Named by name, the extension is still found."""
        extensions = [
            {"name": "A", "taxa": [{"id": "A-0"}, {"id": "A-1"}]},
            {"name": "B", "taxa": [{"id": "B-0"}, {"id": "B-1"}]},
        ]

        by_index = self._merged_taxa(
            [{"index": 1, "toolComponent": {"index": 1}}], extensions
        )
        by_name = self._merged_taxa(
            [{"index": 1, "toolComponent": {"index": 1, "name": "B"}}], extensions
        )

        assert not by_index
        assert [(t.root.id, t.root.toolComponent.name) for t in by_name] == [
            ("B-1", "B")
        ]

    def test_the_taxonomy_a_kept_taxon_names_is_carried_into_the_aggregate(self):
        """The kept taxon reference names ``CWE`` once its index is dropped, so
        the run it lands in has to hold a ``CWE`` taxonomy with the taxon in it;
        a name checked against nothing in the merged run was the gap. The
        aggregate holds a copy, not the incoming object."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            taxa=[{"index": 1, "toolComponent": {"index": 0}}],
                        )
                    ],
                    taxonomies=[
                        {"name": "CWE", "taxa": [{"id": "CWE-1"}, {"id": "CWE-79"}]}
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        run = aggregated.runs[0]
        taxon = run.results[0].taxa[0].root
        assert taxon.toolComponent.name == "CWE"
        assert [item.name for item in run.taxonomies] == ["CWE"]
        assert [item.id for item in run.taxonomies[0].taxa] == ["CWE-1", "CWE-79"]
        assert run.taxonomies[0] is not incoming.runs[0].taxonomies[0]

    def test_a_taxonomy_both_runs_carry_is_listed_once_with_both_runs_taxa(self):
        """The same taxonomy by name, in the aggregate and in the incoming run,
        is one entry holding the taxa of both, each id once; a taxonomy of
        another name joins beside it, and merging the same report again adds
        nothing."""
        aggregated = SarifReport(
            runs=[
                _run_with_tables(
                    "aggregate",
                    [],
                    taxonomies=[{"name": "CWE", "taxa": [{"id": "CWE-1"}]}],
                )
            ]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [],
                    taxonomies=[
                        {"name": "CWE", "taxa": [{"id": "CWE-1"}, {"id": "CWE-79"}]},
                        {"name": "OWASP", "taxa": [{"id": "A01"}]},
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)
        aggregated.merge_sarif_report(incoming)

        taxonomies = aggregated.runs[0].taxonomies
        assert [item.name for item in taxonomies] == ["CWE", "OWASP"]
        assert [item.id for item in taxonomies[0].taxa] == ["CWE-1", "CWE-79"]
        assert [item.id for item in taxonomies[1].taxa] == ["A01"]

    def test_a_taxon_naming_nothing_by_id_or_guid_is_dropped(self):
        """An index past the end of the named taxonomy leaves the reference
        with neither an id nor a guid once the indices are dropped; it names no taxon,
        so the merged result does not keep it. The control beside it names its
        taxon by id and stays."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            taxa=[
                                {"index": 9, "toolComponent": {"index": 0}},
                                {"id": "CWE-79", "toolComponent": {"index": 0}},
                            ],
                        )
                    ],
                    taxonomies=[{"name": "CWE", "taxa": [{"id": "CWE-79"}]}],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        taxa = aggregated.runs[0].results[0].taxa
        assert [taxon.root.id for taxon in taxa] == ["CWE-79"]

    def test_a_web_request_named_by_index_takes_its_row_from_the_runs_table(self):
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [_finding("T-1", webRequest={"index": 0})],
                    web_requests=[
                        {"protocol": "http", "method": "GET", "target": "/x"}
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        request = aggregated.runs[0].results[0].webRequest
        assert (request.method, request.target) == ("GET", "/x")
        assert request.index in (None, -1)

    def test_a_web_response_named_by_index_takes_its_row_from_the_runs_table(self):
        """The counterpart of the web request above, read from ``webResponses``:
        the walk handles the two keys alike, and each has its own table."""
        aggregated = SarifReport(runs=[_run_with_tables("aggregate", [])])
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [_finding("T-1", webResponse={"index": 0})],
                    web_responses=[
                        {"protocol": "http", "statusCode": 404, "reasonPhrase": "gone"}
                    ],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        response = aggregated.runs[0].results[0].webResponse
        assert (response.statusCode, response.reasonPhrase) == (404, "gone")
        assert response.index in (None, -1)

    def test_an_analysis_target_named_by_index_takes_its_uri_from_its_own_run(self):
        """``analysisTarget`` is an artifact location like the ones under the
        result's locations: an index alone points into the incoming run's
        artifacts, and the aggregate's first run has other ones."""
        aggregated = SarifReport(
            runs=[_run_with_tables("aggregate", [], artifacts=["first/a.py"])]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [_finding("T-1", analysisTarget={"index": 0})],
                    artifacts=["second/target.py"],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        target = aggregated.runs[0].results[0].analysisTarget
        assert target.uri == "second/target.py"
        assert target.index in (None, -1)

    def test_a_property_bag_key_spelled_like_a_field_is_left_as_written(self):
        """The control: a property bag is the scanner's own text, not a place
        the walk reads references from."""
        aggregated = SarifReport(
            runs=[_run_with_tables("aggregate", [], artifacts=["first/a.py"])]
        )
        incoming = SarifReport(
            runs=[
                _run_with_tables(
                    "tool",
                    [
                        _finding(
                            "T-1",
                            properties={"artifactLocation": {"index": 0}},
                        )
                    ],
                    artifacts=["second/b.py"],
                )
            ]
        )

        aggregated.merge_sarif_report(incoming)

        bag = aggregated.runs[0].results[0].properties
        assert bag.model_dump(exclude_none=True)["artifactLocation"] == {"index": 0}

    def test_the_first_run_adopted_whole_keeps_its_own_indices(self):
        """The control: an adopted run carries its tables, so nothing is detached."""
        aggregated = SarifReport(runs=[])
        incoming = SarifReport(
            runs=[
                _run_with_tables("tool", [_located(index=0)], artifacts=["second/b.py"])
            ]
        )

        aggregated.merge_sarif_report(incoming)

        location = _first_artifact_location(aggregated)
        assert location.index == 0
        assert aggregated.runs[0].artifacts[0].location.uri == "second/b.py"


class TestTheIncomingRunsExtensionsAreFolded:
    def test_a_captured_scanner_report_folds_into_an_aggregate_as_an_extension(
        self,
    ):
        """A real scanner's SARIF (cfn-guard, captured under tests/test_data):
        its driver joins the aggregate's extensions and every result keeps its
        ruleId, the shape cli.merge relies on when two aggregates meet."""
        captured = (
            Path(__file__).resolve().parents[2]
            / "test_data"
            / "scanners"
            / "cfn_lint_guard"
            / "captured"
            / "cfn-guard-3.2.1-wa-Security-Pillar-insecure.sarif"
        )
        incoming = SarifReport.model_validate_json(captured.read_text(encoding="utf-8"))
        rule_ids = [result.ruleId for result in incoming.runs[0].results]
        assert rule_ids and all(rule_ids)
        aggregated = SarifReport(runs=[_run("ASH", [], [])])

        aggregated.merge_sarif_report(incoming)
        aggregated.merge_sarif_report(incoming)

        names = [ext.name for ext in aggregated.runs[0].tool.extensions]
        assert names.count(incoming.runs[0].tool.driver.name) == 1
        merged_rule_ids = [result.ruleId for result in aggregated.runs[0].results]
        assert merged_rule_ids == rule_ids + rule_ids

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
        # The union was made on a copy: the first report's pack still lists its
        # own rule only, so the rules list was not shared with the aggregate.
        assert [rule.id for rule in first.runs[0].tool.extensions[0].rules] == ["P-1"]
