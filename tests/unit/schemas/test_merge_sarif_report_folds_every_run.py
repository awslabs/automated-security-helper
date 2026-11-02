# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``merge_sarif_report`` folds every run of an incoming report, and nothing twice.

Why this file exists
--------------------
``SarifReport.merge_sarif_report`` read ``sarif_report.runs[0]`` and nothing
else, so a scanner's SARIF with more than one run lost every later run's
results on the way into the aggregate that the summary, the reports and the exit
code read, while the per-scanner counts, which read every run, still counted
them. The same method indexed ``self.runs[0]`` after a check for ``None`` only,
so merging into a report whose runs list was empty raised ``IndexError``, and
the branch meant to adopt the incoming run would have added its results and
invocations twice had it been reached. Appending a rule to an extension whose
rules list is ``None`` raised ``AttributeError``, which cfn-lint produces for a
clean or an all-failed target. And each result was rebuilt from a full
``model_dump``, which marks every field as set, so a result that stated no level
came back with the default level set and ``resolve_missing_levels`` could no
longer give it the level its rule's ``defaultConfiguration`` names. The first
cure for that, a dump of the set fields only, dropped what code had appended in
place to a default list (pydantic marks a field set on construction or
assignment, never on an append), so the dump is full again and only ``level``
keeps its unset state.
"""

from __future__ import annotations

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Location,
    PropertyBag,
    Run,
    SarifReport,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import attach_scanner_details
from automated_security_helper.utils.severity_ladder import resolve_missing_levels

pytestmark = pytest.mark.unit


def _finding(rule_id: str) -> dict:
    return {"ruleId": rule_id, "message": {"text": f"finding {rule_id}"}}


def _run(driver: str, results, invocations=None, rules=None) -> Run:
    tool = {"driver": {"name": driver}}
    if rules is not None:
        tool["driver"]["rules"] = rules
    return Run(tool=tool, results=results, invocations=invocations)


def _rule_ids(report: SarifReport) -> list[str]:
    return [result.ruleId for result in report.runs[0].results]


def test_every_run_of_the_incoming_report_is_folded_in():
    aggregated = SarifReport(runs=[_run("aggregate", [], [])])
    incoming = SarifReport(
        runs=[
            _run("first-tool", [_finding("A-1")], [{"executionSuccessful": True}]),
            _run(
                "second-tool",
                [_finding("B-1"), _finding("B-2")],
                [{"executionSuccessful": True}],
            ),
        ]
    )

    aggregated.merge_sarif_report(incoming)

    assert len(aggregated.runs) == 1
    assert _rule_ids(aggregated) == ["A-1", "B-1", "B-2"]
    assert [ext.name for ext in aggregated.runs[0].tool.extensions] == [
        "first-tool",
        "second-tool",
    ]
    assert len(aggregated.runs[0].invocations) == 2


def test_an_empty_runs_list_adopts_the_incoming_run_once():
    aggregated = SarifReport(runs=[])
    incoming = SarifReport(
        runs=[_run("recorder", [_finding("R-1")], [{"executionSuccessful": True}])]
    )

    aggregated.merge_sarif_report(incoming)

    assert len(aggregated.runs) == 1
    assert aggregated.runs[0].tool.driver.name == "recorder"
    # Once each: the adopted run's own copy is not added a second time.
    assert _rule_ids(aggregated) == ["R-1"]
    assert len(aggregated.runs[0].invocations) == 1

    # The adopted run is a copy: editing it leaves the incoming report as it was.
    adopted = aggregated.runs[0]
    adopted.tool.driver.name = "renamed"
    adopted.results[0].ruleId = "renamed"
    adopted.invocations[0].executionSuccessful = False
    assert incoming.runs[0].tool.driver.name == "recorder"
    assert incoming.runs[0].results[0].ruleId == "R-1"
    assert incoming.runs[0].invocations[0].executionSuccessful is True


def test_an_empty_runs_list_given_a_two_run_report_adopts_one_and_folds_the_other():
    """Where the "added twice" bug would come back: the first run is adopted
    whole and the loop must not fold it again, while the second run is folded
    into it."""
    aggregated = SarifReport(runs=[])
    incoming = SarifReport(
        runs=[
            _run("first-tool", [_finding("A-1")], [{"executionSuccessful": True}]),
            _run(
                "second-tool",
                [_finding("B-1"), _finding("B-2")],
                [{"executionSuccessful": True}],
            ),
        ]
    )

    aggregated.merge_sarif_report(incoming)

    assert len(aggregated.runs) == 1
    assert _rule_ids(aggregated) == ["A-1", "B-1", "B-2"]
    assert len(aggregated.runs[0].invocations) == 2
    assert aggregated.runs[0].tool.driver.name == "first-tool"
    assert [ext.name for ext in aggregated.runs[0].tool.extensions] == ["second-tool"]


def test_the_same_tool_merged_twice_into_an_empty_aggregate_is_listed_once():
    # The first merge adopts the run, so the tool becomes runs[0].tool.driver; the
    # second must not list it again as an extension, and its rules union into
    # the driver.
    aggregated = SarifReport(runs=[])
    first = SarifReport(
        runs=[_run("scanner", [_finding("S-1")], [], rules=[{"id": "S-1"}])]
    )
    second = SarifReport(
        runs=[_run("scanner", [_finding("S-2")], [], rules=[{"id": "S-2"}])]
    )

    aggregated.merge_sarif_report(first)
    aggregated.merge_sarif_report(second)

    run = aggregated.runs[0]
    assert run.tool.driver.name == "scanner"
    assert not run.tool.extensions, run.tool.extensions
    assert [rule.id for rule in run.tool.driver.rules] == ["S-1", "S-2"]
    assert _rule_ids(aggregated) == ["S-1", "S-2"]


def test_a_driver_listing_one_rule_id_twice_adds_it_once():
    aggregated = SarifReport(runs=[_run("aggregate", [], [])])
    aggregated.runs[0].tool.extensions = [
        ToolComponent(name="scanner", rules=[{"id": "S-0"}])
    ]
    incoming = SarifReport(
        runs=[
            _run(
                "scanner",
                [_finding("S-1")],
                [],
                rules=[{"id": "S-1"}, {"id": "S-1"}, {"id": "S-0"}],
            )
        ]
    )

    aggregated.merge_sarif_report(incoming)

    assert [rule.id for rule in aggregated.runs[0].tool.extensions[0].rules] == [
        "S-0",
        "S-1",
    ]


def test_merging_does_not_alias_the_incoming_report():
    # ash merge promises not to mutate its inputs: the aggregate's invocations,
    # extensions and rules must be copies, so editing the aggregate afterwards
    # leaves the merged report as it was.
    aggregated = SarifReport(runs=[_run("aggregate", [], [])])
    aggregated.runs[0].tool.extensions = [
        ToolComponent(name="shared", rules=[{"id": "SH-0"}])
    ]
    incoming = SarifReport(
        runs=[
            _run("shared", [], [{"executionSuccessful": True}], rules=[{"id": "SH-1"}]),
            _run("other", [], [{"executionSuccessful": True}], rules=[{"id": "O-1"}]),
        ]
    )

    aggregated.merge_sarif_report(incoming)

    run = aggregated.runs[0]
    run.invocations[0].executionSuccessful = False
    run.invocations[1].executionSuccessful = False
    run.tool.extensions[0].rules[1].name = "renamed"
    run.tool.extensions[1].name = "renamed-extension"

    assert incoming.runs[0].invocations[0].executionSuccessful is True
    assert incoming.runs[1].invocations[0].executionSuccessful is True
    assert incoming.runs[0].tool.driver.rules[0].name is None
    assert incoming.runs[1].tool.driver.name == "other"


def test_rules_are_added_to_an_extension_that_had_none():
    aggregated = SarifReport(runs=[_run("aggregate", [], [])])
    # The model's default is an empty list; a SARIF file that writes
    # ``"rules": null`` gives None, which is the shape this pins.
    aggregated.runs[0].tool.extensions = [ToolComponent(name="cfn-lint", rules=None)]
    assert aggregated.runs[0].tool.extensions[0].rules is None, (
        "the extension must start with no rules list"
    )
    incoming = SarifReport(
        runs=[_run("cfn-lint", [_finding("E3012")], [], rules=[{"id": "E3012"}])]
    )

    aggregated.merge_sarif_report(incoming)

    extension = aggregated.runs[0].tool.extensions[0]
    assert [rule.id for rule in extension.rules] == ["E3012"]
    assert _rule_ids(aggregated) == ["E3012"]


def test_a_result_that_stated_no_level_still_takes_its_rules_default_level():
    aggregated = SarifReport(runs=[_run("aggregate", [], [])])
    incoming = SarifReport(
        runs=[
            _run(
                "scanner",
                [_finding("S-1")],
                [],
                rules=[{"id": "S-1", "defaultConfiguration": {"level": "error"}}],
            )
        ]
    )
    assert "level" not in incoming.runs[0].results[0].model_fields_set

    aggregated.merge_sarif_report(incoming)

    merged = aggregated.runs[0].results[0]
    # Still unset after the merge, so the resolver below reads the rule.
    assert "level" not in merged.model_fields_set
    resolve_missing_levels(aggregated)
    assert str(getattr(merged.level, "value", merged.level)) == "error"


def test_what_code_appended_to_a_results_default_list_survives():
    # pydantic marks a field set on construction or assignment, never on an
    # append, so a merge that dumped only the set fields lost these: a tag
    # appended to a fresh PropertyBag and a location appended to the default
    # relatedLocations list.
    aggregated = SarifReport(runs=[_run("aggregate", [], [])])
    incoming = SarifReport(runs=[_run("scanner", [_finding("S-1")], [])])
    result = incoming.runs[0].results[0]
    result.properties = PropertyBag()
    result.properties.tags.append("scanner")
    result.relatedLocations.append(
        Location.model_validate({"message": {"text": "see also"}})
    )

    aggregated.merge_sarif_report(incoming)

    merged = aggregated.runs[0].results[0]
    assert merged.properties.tags == ["scanner"]
    assert [loc.message.root.text for loc in merged.relatedLocations] == ["see also"]


def test_what_code_appended_to_an_adopted_runs_default_list_survives():
    aggregated = SarifReport(runs=[])
    incoming = SarifReport(runs=[_run("scanner", [_finding("S-1")], [])])
    incoming.runs[0].properties = PropertyBag()
    incoming.runs[0].properties.tags.append("adopted")

    aggregated.merge_sarif_report(incoming)

    assert aggregated.runs[0].properties.tags == ["adopted"]


def test_the_scan_paths_scanner_details_survive_the_merge():
    # The scan path runs attach_scanner_details right before merge_sarif_report.
    # It assigns the tags list before appending to it, so the field is set and
    # survives either dump; this pins the real pattern alongside the append case.
    aggregated = SarifReport(runs=[_run("aggregate", [], [])])
    incoming = SarifReport(
        runs=[_run("bandit", [_finding("B-1")], [{"executionSuccessful": True}])]
    )
    attach_scanner_details(incoming, scanner_name="bandit", scanner_version="1.0")

    aggregated.merge_sarif_report(incoming)

    merged = aggregated.runs[0].results[0]
    assert merged.properties.tags == ["bandit"]
    assert merged.properties.scanner_name == "bandit"
    assert merged.properties.scanner_version == "1.0"
