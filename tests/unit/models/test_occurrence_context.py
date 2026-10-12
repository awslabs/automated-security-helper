# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Preserve curated occurrence evidence before aggregation changes run tables."""

import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models import flat_vulnerability
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.cli.mcp_tools import mcp_explain_finding
from automated_security_helper.utils.occurrence_context import (
    valid_context,
    persisted_context,
)

CONTEXT = "ash_occurrence_context"
MARKER = "ash_occurrence_context_version"


def _report(results, **run_fields):
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "scanner"}},
                    "results": results,
                    **run_fields,
                }
            ],
        }
    )


def _result():
    return {
        "ruleId": "RULE",
        "message": {"text": "same"},
        "properties": {"scanner_name": "scanner"},
    }


def _flat(report):
    return AshAggregatedResults(sarif=report).to_flat_vulnerabilities()


@pytest.mark.parametrize(
    "kind",
    [
        "artifact",
        "target",
        "address",
        "address-parent",
        "logical",
        "logical-parent",
        "artifact-parent",
        "rule",
    ],
)
def test_run_local_indices_resolve_only_referenced_source_evidence(kind):
    reports = []
    for value in ("one", "two"):
        result = _result()
        run = {}
        if kind in ("artifact", "target", "artifact-parent"):
            run["artifacts"] = [{"location": {"uri": value + ".py"}}]
            if kind == "target":
                result["analysisTarget"] = {"index": 0}
            else:
                result["locations"] = [
                    {"physicalLocation": {"artifactLocation": {"index": 0}}}
                ]
            if kind == "artifact-parent":
                run["artifacts"] = [
                    {
                        "location": {"uri": "child"},
                        "parentIndex": 1,
                        "offset": 0,
                        "length": 10,
                    },
                    {"location": {"uri": value}},
                ]
        elif kind.startswith("address"):
            run["addresses"] = [{"absoluteAddress": 4096 if value == "one" else 8192}]
            address = (
                {"index": 0}
                if kind == "address"
                else {"parentIndex": 0, "offsetFromParent": -10}
            )
            result["locations"] = [{"physicalLocation": {"address": address}}]
        elif kind.startswith("logical"):
            run["logicalLocations"] = [{"name": value}]
            logical = (
                {"index": 0}
                if kind == "logical"
                else {"name": "method", "parentIndex": 0}
            )
            result["locations"] = [{"logicalLocations": [logical]}]
        else:
            result.pop("ruleId")
            result["ruleIndex"] = 0
            run["tool"] = {"driver": {"name": "scanner", "rules": [{"id": value}]}}
        reports.append(_report([result], **run))
    assert _flat(reports[0])[0].id != _flat(reports[1])[0].id
    model = AshAggregatedResults()
    originals = [report.model_dump(mode="json") for report in reports]
    for report in reports:
        model.sarif.merge_sarif_report(report)
    assert [report.model_dump(mode="json") for report in reports] == originals
    saved = AshAggregatedResults.from_json(model.model_dump_json())
    assert len({flat.id for flat in saved.to_flat_vulnerabilities()}) == 2
    remerged = AshAggregatedResults()
    remerged.sarif.merge_sarif_report(saved.sarif, include_driver=False)
    assert [flat.id for flat in remerged.to_flat_vulnerabilities()] == [
        flat.id for flat in saved.to_flat_vulnerabilities()
    ]


@pytest.mark.parametrize(
    "kind", ["index-only", "duplicate-id", "extension", "same-driver-tables"]
)
def test_merge_preserves_rule_and_safe_message_context(kind, tmp_path, monkeypatch):
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    source_reports = []
    for index in (0, 1):
        result = _result()
        result["message"] = {"id": "msg", "arguments": [str(index)]}
        result["properties"]["review_source"] = index
        rules = [
            {
                "id": "FIRST" if kind == "index-only" else "RULE",
                "messageStrings": {"msg": {"text": "first {0}"}},
            },
            {
                "id": "SECOND" if kind == "index-only" else "RULE",
                "messageStrings": {"msg": {"text": "second {0}"}},
            },
        ]
        tool = {"driver": {"name": "scanner", "rules": rules}}
        if kind in ("index-only", "duplicate-id"):
            result.pop("ruleId")
            result["ruleIndex"] = index
        elif kind == "extension":
            result["rule"] = {
                "id": "RULE",
                "toolComponent": {"index": 0, "name": "plugin"},
            }
            tool = {
                "driver": {"name": "scanner"},
                "extensions": [{"name": "plugin", "rules": [rules[0]]}],
            }
        else:
            tool["driver"]["rules"] = [
                {
                    "id": "RULE",
                    "messageStrings": {"msg": {"text": f"source-{index} {{0}}"}},
                }
            ]
            result["message"]["arguments"] = ["same"]
        source_reports.append(_report([result], tool=tool))
    model = AshAggregatedResults()
    for report in source_reports:
        model.sarif.merge_sarif_report(report)
    path = tmp_path / "ash_aggregated_results.json"
    path.write_text(model.model_dump_json())
    restored = AshAggregatedResults.from_json(path.read_text())
    flat = restored.to_flat_vulnerabilities()
    answer = mcp_explain_finding(flat[1].id, results_path=str(tmp_path))
    assert answer["success"] is True
    assert answer["finding"]["scanner_metadata"]["properties"]["review_source"] == 1
    assert len({item.id for item in flat}) == 2


def test_hierarchical_rule_ids_and_name_only_default_driver_lookup():
    tool = {
        "driver": {
            "name": "scanner",
            "rules": [{"id": "RULE", "messageStrings": {"msg": {"text": "Issue {0}"}}}],
        },
        "extensions": [{"name": "scanner"}],
    }
    for hierarchical in (True, False):
        results = [
            {
                **_result(),
                "ruleId": "RULE/sub" if hierarchical else "RULE",
                "ruleIndex": 0,
                "rule": {"id": "RULE", "toolComponent": {"name": "scanner"}},
                "message": {"id": "msg", "arguments": [value]},
            }
            for value in ("one", "two")
        ]
        assert len({flat.id for flat in _flat(_report(results, tool=tool))}) == 2


@pytest.mark.parametrize(
    "quote, args",
    [
        ("'", ["synthetic'private-value-only"]),
        ('"', ['synthetic"private-value-only']),
        ("'", ["synthetic\nprivate-value-only"]),
        ("'", ["synthetic'", "private-value-only"]),
        ("'", ["'", "private-value-only"]),
    ],
)
def test_template_secret_span_masks_before_substitution_can_change_boundaries(
    monkeypatch, quote, args
):
    template = (
        "Possible hardcoded password: "
        + quote
        + "".join("{" + str(index) + "}" for index in range(len(args)))
        + quote
    )
    captured = []
    original = flat_vulnerability.hashlib.sha256

    def capture(value):
        captured.append(value.decode())
        return original(value)

    monkeypatch.setattr(flat_vulnerability.hashlib, "sha256", capture)
    report = _report(
        [
            {
                **_result(),
                "ruleId": "B105",
                "message": {"text": template, "arguments": args},
            }
        ]
    )
    flat = _flat(report)[0]
    assert "private-value-only" not in captured[0]
    assert json.loads(flat.raw_data)["message"]["arguments"] == args


def test_producer_context_is_discarded_and_valid_context_survives_noncanonical_remerge():
    result = {
        **_result(),
        "message": {"id": "missing"},
        "properties": {CONTEXT: {"version": 1, "opaque_id": "forged"}},
    }
    report = _report([result])
    before = report.model_dump(mode="json")
    model = AshAggregatedResults(sarif=_report([]))
    model.sarif.merge_sarif_report(report, include_driver=False)
    assert report.model_dump(mode="json") == before
    merged = model.sarif.runs[0]
    assert getattr(merged.properties, MARKER) == 1
    context = getattr(merged.results[0].properties, CONTEXT)
    assert "opaque_id" not in context
    saved = AshAggregatedResults.from_json(model.model_dump_json())
    second = AshAggregatedResults(sarif=_report([]))
    second.sarif.merge_sarif_report(saved.sarif, include_driver=False)
    assert (
        second.to_flat_vulnerabilities()[0].id == saved.to_flat_vulnerabilities()[0].id
    )


def test_cycles_out_of_range_and_unreferenced_table_entries_do_not_change_identity():
    result = {
        **_result(),
        "locations": [{"physicalLocation": {"address": {"index": 0}}}],
    }
    report = _report([result], addresses=[{"name": "parent", "parentIndex": 0}])
    control = _flat(report)[0].id
    report.runs[0].addresses.append(
        report.runs[0].addresses[0].model_copy(update={"name": "unreferenced"})
    )
    assert _flat(report)[0].id == control
    invalid = _report(
        [
            {
                **_result(),
                "locations": [{"physicalLocation": {"address": {"index": 100}}}],
            }
        ],
        addresses=[{"name": "parent"}],
    )
    assert _flat(invalid)[0].id


def test_referenced_uri_base_chain_scopes_relative_artifacts_across_merge():
    result = {
        **_result(),
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py", "uriBaseId": "ROOT"}
                }
            }
        ],
    }
    reports = [
        _report(
            [result], originalUriBaseIds={"ROOT": {"uri": f"file:///project-{value}/"}}
        )
        for value in ("one", "two")
    ]
    assert _flat(reports[0])[0].id != _flat(reports[1])[0].id
    model = AshAggregatedResults()
    for report in reports:
        model.sarif.merge_sarif_report(report)
    restored = AshAggregatedResults.from_json(model.model_dump_json())
    assert len({flat.id for flat in restored.to_flat_vulnerabilities()}) == 2


def test_first_marker_transition_curates_nonempty_target_and_deep_parent_chains():
    result = {
        **_result(),
        "locations": [{"physicalLocation": {"address": {"index": 0}}}],
    }
    parents = [{"name": "child", "parentIndex": index + 1} for index in range(70)] + [
        {"name": "root-one"}
    ]
    target = _report([result], addresses=parents)
    before = _flat(target)[0].id
    source = _report([result], addresses=[{"name": "root-two"}])
    target.merge_sarif_report(source, include_driver=False)
    flats = _flat(target)
    assert flats[0].id == before
    assert flats[0].id != flats[1].id
    other = _report([result], addresses=[*parents[:-1], {"name": "other-root"}])
    assert before != _flat(other)[0].id


@pytest.mark.parametrize(
    "context",
    [
        {"version": True, "message": {"state": "resolved", "text": "FORGED"}},
        {"version": 1, "unknown": "FORGED"},
        {
            "version": 1,
            "message": {
                "state": "resolved",
                "text": "FORGED",
                "arguments": ["private"],
            },
        },
        {"version": 1, "locations": [{"location": {"region": {"startLine": 0}}}]},
        {"version": 1, "locations": [{"location": {"region": {"startColumn": 0}}}]},
        {
            "version": 1,
            "locations": [{"location": {"address": {"absoluteAddress": -1}}}],
        },
        {"version": 1, "rule_index": True},
        {"version": 1, "rule_index": 1.0},
        {
            "version": 1,
            "locations": [
                {
                    "location": {
                        "logical": [
                            {"name": "safe", "properties": {"private": "FORGED"}}
                        ]
                    }
                }
            ],
        },
    ],
)
def test_invalid_nested_context_is_rejected_as_a_whole(context):
    assert not valid_context(context)
    report = _report(
        [
            {
                **_result(),
                "message": {"id": "msg", "arguments": ["one"]},
                "properties": {CONTEXT: context},
            }
        ],
        properties={MARKER: 1},
        tool={
            "driver": {
                "name": "scanner",
                "globalMessageStrings": {"msg": {"text": "False {0}"}},
            }
        },
    )
    assert persisted_context(report.runs[0].results[0], report.runs[0]) is None
    first = _flat(report)[0].id
    report.runs[0].results[0].message.root.arguments = ["two"]
    assert _flat(report)[0].id == first


def test_unavailable_marked_context_and_ash_named_raw_producer_do_not_gain_templates():
    unresolved = {
        "version": 1,
        "message": {"state": "unavailable", "text": "", "id": "msg"},
    }
    result = {
        **_result(),
        "message": {"id": "msg", "arguments": ["one"]},
        "properties": {CONTEXT: unresolved, "scanner_name": "scanner"},
    }
    tool = {
        "driver": {
            "name": "AWS Labs - Automated Security Helper",
            "globalMessageStrings": {"msg": {"text": "False {0}"}},
        }
    }
    marked = _report([result], properties={MARKER: 1}, tool=tool)
    first = _flat(marked)[0].id
    marked.runs[0].results[0].message.root.arguments = ["two"]
    assert _flat(marked)[0].id == first
    raw = _report(
        [result],
        tool={
            "driver": {"name": "AWS Labs - Automated Security Helper"},
            "extensions": [
                {
                    "name": "scanner",
                    "globalMessageStrings": {"msg": {"text": "Actual {0}"}},
                }
            ],
        },
    )
    assert persisted_context(raw.runs[0].results[0], raw.runs[0]) is None
    source_id = _flat(raw)[0].id
    raw.runs[0].results[0].message.root.arguments = ["two"]
    assert _flat(raw)[0].id != source_id


def test_hierarchical_secret_rule_and_long_malformed_quoted_template_are_safe(
    monkeypatch,
):
    captured = []
    original = flat_vulnerability.hashlib.sha256

    def capture(value):
        captured.append(value.decode())
        return original(value)

    monkeypatch.setattr(flat_vulnerability.hashlib, "sha256", capture)
    for template in (
        "Possible hardcoded password: '{0}'",
        "Possible hardcoded password: '" + "\\" * 10000 + "{0}",
    ):
        report = _report(
            [
                {
                    **_result(),
                    "ruleId": "B105/sub",
                    "message": {
                        "text": template,
                        "arguments": ["synthetic'private-value-only"],
                    },
                }
            ]
        )
        _flat(report)
    assert all("private-value-only" not in seed for seed in captured)


@pytest.mark.parametrize("change", ["text", "arguments", "secret"])
def test_current_inline_message_wins_over_saved_source_rendering(change, monkeypatch):
    rule_id = "B105" if change == "secret" else "RULE"
    template = (
        "Possible hardcoded password: '{0}'" if change == "secret" else "Issue {0}"
    )
    result = {
        **_result(),
        "ruleIndex": 0,
        "message": {"text": template, "arguments": ["one"]},
    }
    result.pop("ruleId")
    source = _report(
        [result], tool={"driver": {"name": "scanner", "rules": [{"id": rule_id}]}}
    )
    model = AshAggregatedResults()
    model.sarif.merge_sarif_report(source)
    original_id = model.to_flat_vulnerabilities()[0].id
    payload = json.loads(model.model_dump_json())
    message = payload["sarif"]["runs"][0]["results"][0]["message"]
    if change == "text":
        message["text"] = "Changed issue {0}"
    else:
        message["arguments"] = [
            "synthetic'private-value-only" if change == "secret" else "two"
        ]
    captured = []
    original = flat_vulnerability.hashlib.sha256

    def capture(value):
        captured.append(value.decode())
        return original(value)

    monkeypatch.setattr(flat_vulnerability.hashlib, "sha256", capture)
    restored = AshAggregatedResults.from_json(json.dumps(payload))
    assert restored.to_flat_vulnerabilities()[0].id != original_id
    assert all("private-value-only" not in seed for seed in captured)


def test_ruleless_direct_used_arguments_keep_source_identity_when_marker_turns_on():
    result = {
        "message": {"text": "Issue {0}", "arguments": ["one"]},
        "properties": {"scanner_name": "scanner"},
    }
    target = _report([result])
    before = _flat(target)[0].id
    source = _report([{**_result(), "message": {"id": "missing"}}])
    target.merge_sarif_report(source, include_driver=False)
    assert _flat(target)[0].id == before
    target.runs[0].results[0].message.root.arguments = ["two"]
    assert _flat(target)[0].id != before


@pytest.mark.parametrize("owner", ["rule", "component"])
def test_guid_hex_casing_does_not_prevent_local_lookup(owner):
    guid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    rule = {
        "id": "RULE",
        "guid": guid,
        "messageStrings": {"msg": {"text": "Issue {0}"}},
    }
    tool = {"driver": {"name": "scanner", "guid": guid, "rules": [rule]}}
    reference = (
        {"id": "RULE", "guid": guid.upper()}
        if owner == "rule"
        else {"id": "RULE", "toolComponent": {"guid": guid.upper()}}
    )
    results = [
        {**_result(), "rule": reference, "message": {"id": "msg", "arguments": [value]}}
        for value in ("one", "two")
    ]
    assert len({flat.id for flat in _flat(_report(results, tool=tool))}) == 2
