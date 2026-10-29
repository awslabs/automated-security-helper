# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A SARIF message stays out of a lone finding's id, and display is unchanged.

The message reaches the finding identity only as the occurrence digest, which
tells apart results of one run that share a key. It is the message as the result
carries it, so a message given by id and arguments is not resolved against a rule
or component table, and its arguments are never formatted into a template.
"""

import json
import re

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.models import flat_vulnerability
from automated_security_helper.utils import finding_identity, occurrence_context

pytestmark = pytest.mark.unit


def _flats(
    messages,
    rule_id="RULE",
    reference=None,
    driver=None,
    extensions=None,
    props=None,
    source_unchanged=True,
):
    """The flattened findings of one run that holds one result per message.

    Flattening leaves the report alone, except that a secret rule's message text
    is masked in the report itself, so a test of such a rule turns the check off.
    """
    results = []
    for message in messages:
        result = {"message": message, "properties": props or {}}
        if rule_id is not None:
            result["ruleId"] = rule_id
        if reference is not None:
            result["rule"] = reference
        results.append(result)
    report = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": driver or {"name": "scanner"},
                        "extensions": extensions or [],
                    },
                    "results": results,
                }
            ],
        }
    )
    before = report.model_dump(mode="json")
    flats = AshAggregatedResults(sarif=report).to_flat_vulnerabilities()
    if source_unchanged:
        assert report.model_dump(mode="json") == before
    for flat, result in zip(flats, report.runs[0].results):
        assert (
            json.loads(flat.raw_data)["message"]
            == result.model_dump(mode="json", exclude_none=True)["message"]
        )
    return flats


def _flat(message, **kwargs):
    return _flats([message], **kwargs)[0]


def test_direct_arguments_do_not_affect_identity_or_display():
    first = _flat({"text": "Issue {0}", "arguments": ["one", "unused-a"]})
    second = _flat({"text": "Issue {0}", "arguments": ["two", "unused-b"]})
    assert first.id == second.id
    assert first.description == second.description == "Issue {0}"
    assert first.id == _flat({"text": "Issue one"}).id
    assert (
        first.id
        == _flat({"text": "Issue {0}", "arguments": ["one", "changed-unused"]}).id
    )


@pytest.mark.parametrize("global_table", [False, True])
@pytest.mark.parametrize("extension", [False, True])
def test_arguments_of_a_message_id_do_not_affect_identity_in_any_lookup_table(
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
    assert first.id == second.id
    assert first.description == second.description == ""


def test_implicit_merged_extension_does_not_affect_identity():
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
        == _flat({"id": "msg", "arguments": ["two"]}, **kwargs).id
    )


def test_message_ids_and_arguments_never_change_a_lone_findings_id():
    ids = {
        _flat({"id": "one", "arguments": ["private"]}).id,
        _flat({"id": "two", "arguments": ["private"]}).id,
        _flat({"id": "one", "arguments": ["other"]}).id,
        _flat({"text": "plain"}).id,
    }
    assert len(ids) == 1


def test_message_text_is_not_formatted_with_its_arguments():
    for text, arguments in (
        ("Issue {{literal}} {0}", ["one"]),
        ("Issue {1}", ["unused"]),
        ("Issue {0.__class__}", ["unused"]),
    ):
        flat = _flat({"text": text, "arguments": arguments})
        assert flat.description == text


def test_results_that_share_a_key_are_told_apart_by_their_message_text():
    same = _flats([{"text": "same"}, {"text": "same"}])
    different = _flats([{"text": "same"}, {"text": "different"}])
    assert same[0].id != same[1].id
    # The first result's own message is unchanged, so its id is too.
    assert different[0].id == same[0].id
    assert different[1].id not in (same[0].id, same[1].id)


def test_results_with_no_message_text_are_told_apart_by_order_alone():
    flats = _flats(
        [
            {"id": "one", "arguments": ["a"]},
            {"id": "two", "arguments": ["b"]},
        ]
    )
    assert [flat.description for flat in flats] == ["", ""]
    assert flats[0].id != flats[1].id


def test_message_arguments_never_reach_the_identity_hash_input(monkeypatch):
    captured = []
    original = finding_identity.hashlib.sha256

    def capture(value):
        captured.append(value.decode())
        return original(value)

    monkeypatch.setattr(finding_identity.hashlib, "sha256", capture)
    _flat(
        {
            "text": "Possible hardcoded password: '{0}{1}'",
            "arguments": ["synthetic-", "private-value"],
        },
        rule_id=None,
        reference={"id": "B105"},
        source_unchanged=False,
    )
    assert captured
    assert all("synthetic-" not in seed for seed in captured)
    assert all("private-value" not in seed for seed in captured)
    assert any("Possible hardcoded password" in seed for seed in captured)


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


def test_direct_factory_without_context_accepts_id_only_message():
    from automated_security_helper.schemas.sarif_schema_model import Result

    result = Result.model_validate(
        {"message": {"id": "missing", "arguments": ["unused"]}}
    )
    flat = flat_vulnerability.FlatVulnerability.from_sarif_result(
        result, "scanner", "SAST"
    )
    assert flat.description == ""
    assert re.fullmatch(r"scanner-unknown-[0-9a-f]{12}", flat.id)
