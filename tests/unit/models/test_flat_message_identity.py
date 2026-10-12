# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Resolve SARIF plain message evidence for identity without changing display."""

import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.models import flat_vulnerability
from automated_security_helper.utils import occurrence_context


def _flat(
    message, rule_id="RULE", reference=None, driver=None, extensions=None, props=None
):
    result = {"message": message, "properties": props or {}}
    if rule_id is not None:
        result["ruleId"] = rule_id
    if reference is not None:
        result["rule"] = reference
    report = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": driver or {"name": "scanner"},
                        "extensions": extensions or [],
                    },
                    "results": [result],
                }
            ],
        }
    )
    before = report.model_dump(mode="json")
    flat = AshAggregatedResults(sarif=report).to_flat_vulnerabilities()[0]
    assert report.model_dump(mode="json") == before
    assert (
        json.loads(flat.raw_data)["message"]
        == report.runs[0]
        .results[0]
        .model_dump(mode="json", exclude_none=True)["message"]
    )
    return flat


def test_direct_arguments_affect_identity_but_not_display_or_unused_arguments():
    first = _flat({"text": "Issue {0}", "arguments": ["one", "unused-a"]})
    second = _flat({"text": "Issue {0}", "arguments": ["two", "unused-b"]})
    assert first.id != second.id
    assert first.description == second.description == "Issue {0}"
    assert first.id == _flat({"text": "Issue one"}).id
    assert (
        first.id
        == _flat({"text": "Issue {0}", "arguments": ["one", "changed-unused"]}).id
    )


@pytest.mark.parametrize("global_table", [False, True])
@pytest.mark.parametrize("extension", [False, True])
def test_rule_and_global_lookup_in_driver_or_explicit_extension(
    global_table, extension
):
    component = {
        "name": "scanner",
        "rules": [{"id": "RULE", "messageStrings": {"msg": {"text": "Issue {0}"}}}],
        "globalMessageStrings": {"msg": {"text": "Global {0}"}},
    }
    if global_table:
        component["rules"][0]["messageStrings"] = {}
    reference = (
        {"id": "RULE", "toolComponent": {"name": "scanner", "index": 0}}
        if extension
        else None
    )
    kwargs = (
        {
            "reference": reference,
            "driver": {"name": "aggregate"},
            "extensions": [component],
        }
        if extension
        else {"driver": component}
    )
    first = _flat({"id": "msg", "arguments": ["one"]}, **kwargs)
    second = _flat({"id": "msg", "arguments": ["two"]}, **kwargs)
    assert first.id != second.id
    assert first.description == second.description == ""


def test_implicit_merged_extension_lookup_uses_unambiguous_scanner_attribution():
    extension = {
        "name": "scanner",
        "rules": [{"id": "RULE", "messageStrings": {"msg": {"text": "Issue {0}"}}}],
    }
    kwargs = {
        "driver": {"name": "AWS Labs - Automated Security Helper"},
        "extensions": [extension],
        "props": {"scanner_name": "scanner"},
    }
    assert (
        _flat({"id": "msg", "arguments": ["one"]}, **kwargs).id
        != _flat({"id": "msg", "arguments": ["two"]}, **kwargs).id
    )


def test_message_id_fallback_distinguishes_unavailable_messages_without_raw_args():
    assert (
        _flat({"id": "one", "arguments": ["private"]}).id
        != _flat({"id": "two", "arguments": ["private"]}).id
    )
    assert (
        _flat({"id": "one", "arguments": ["private"]}).id
        == _flat({"id": "one", "arguments": ["other"]}).id
    )


def test_safe_braces_and_missing_arguments_are_not_general_formatting():
    assert (
        _flat({"text": "Issue {{literal}} {0}", "arguments": ["one"]}).id
        == _flat({"text": "Issue {literal} one"}).id
    )
    assert (
        _flat({"text": "Issue {1}", "arguments": ["unused"]}).id
        == _flat({"text": "Issue {1}", "arguments": ["changed"]}).id
    )
    assert (
        _flat({"text": "Issue {0.__class__}", "arguments": ["unused"]}).id
        == _flat({"text": "Issue {0.__class__}", "arguments": ["changed"]}).id
    )


def test_mismatching_component_and_rule_references_do_not_guess_templates():
    component = {
        "name": "scanner",
        "rules": [{"id": "RULE", "messageStrings": {"msg": {"text": "Issue {0}"}}}],
    }
    for reference in (
        {"id": "other", "index": 0},
        {"id": "RULE", "toolComponent": {"name": "wrong", "index": 0}},
    ):
        kwargs = {
            "driver": {"name": "aggregate"},
            "extensions": [component],
            "reference": reference,
        }
        assert (
            _flat({"id": "msg", "arguments": ["one"]}, **kwargs).id
            == _flat({"id": "msg", "arguments": ["two"]}, **kwargs).id
        )


def test_rendered_b105_message_is_masked_as_a_whole_with_reference_rule_id(monkeypatch):
    captured = []
    original = flat_vulnerability.hashlib.sha256

    def capture(value):
        captured.append(value.decode())
        return original(value)

    monkeypatch.setattr(flat_vulnerability.hashlib, "sha256", capture)
    _flat(
        {
            "text": "Possible hardcoded password: '{0}{1}'",
            "arguments": ["synthetic-", "private-value"],
        },
        rule_id=None,
        reference={"id": "B105"},
    )
    assert "synthetic-" not in captured[0]
    assert "private-value" not in captured[0]
    assert "Possible hardcoded password" in captured[0]


def test_actual_merge_keeps_lookup_in_the_scanner_extension():
    model = AshAggregatedResults()
    report = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "scanner",
                            "rules": [
                                {
                                    "id": "RULE",
                                    "messageStrings": {"msg": {"text": "Issue {0}"}},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "RULE",
                            "ruleIndex": 0,
                            "message": {"id": "msg", "arguments": [value]},
                            "properties": {"scanner_name": "scanner"},
                        }
                        for value in ("one", "two")
                    ],
                }
            ],
        }
    )
    model.sarif.merge_sarif_report(report)
    assert model.sarif.runs[0].tool.extensions[0].name == "scanner"
    restored = AshAggregatedResults.from_json(model.model_dump_json())
    assert len({flat.id for flat in restored.to_flat_vulnerabilities()}) == 2


def test_description_whitespace_aliases_have_equal_identity():
    assert _flat({"text": "same"}).id == _flat({"text": " same "}).id


def test_inline_plain_text_skips_all_rule_and_component_lookup(monkeypatch):
    def refused(*args):
        raise AssertionError("Ordinary direct text must not scan run tables")

    monkeypatch.setattr(occurrence_context, "_owning_component", refused)
    assert _flat({"text": "same"}).description == "same"


def test_rule_table_precedes_global_and_direct_text_precedes_both():
    driver = {
        "name": "scanner",
        "rules": [{"id": "RULE", "messageStrings": {"msg": {"text": "Rule {0}"}}}],
        "globalMessageStrings": {"msg": {"text": "Global {0}"}},
    }
    first = _flat({"id": "msg", "arguments": ["one"]}, driver=driver)
    changed = json.loads(json.dumps(driver))
    changed["globalMessageStrings"]["msg"]["text"] = "Changed global {0}"
    assert first.id == _flat({"id": "msg", "arguments": ["one"]}, driver=changed).id
    assert (
        _flat({"text": "inline", "id": "msg"}, driver=driver).id
        == _flat({"text": "inline", "id": "msg"}, driver=changed).id
    )


def test_ambiguous_extensions_and_invalid_reference_indices_leave_args_unused():
    component = {
        "name": "scanner",
        "globalMessageStrings": {"msg": {"text": "Issue {0}"}},
    }
    for reference, extensions in [
        (None, [component, component]),
        ({"id": "RULE", "toolComponent": {"index": 20}}, [component]),
    ]:
        kwargs = {
            "driver": {"name": "AWS Labs - Automated Security Helper"},
            "extensions": extensions,
            "reference": reference,
            "props": {"scanner_name": "scanner"},
        }
        assert (
            _flat({"id": "msg", "arguments": ["one"]}, **kwargs).id
            == _flat({"id": "msg", "arguments": ["two"]}, **kwargs).id
        )


def test_direct_factory_without_context_accepts_id_only_message():
    from automated_security_helper.schemas.sarif_schema_model import Result

    result = Result.model_validate(
        {"message": {"id": "missing", "arguments": ["unused"]}}
    )
    assert (
        flat_vulnerability.FlatVulnerability.from_sarif_result(
            result, "scanner", "SAST"
        ).description
        == ""
    )
