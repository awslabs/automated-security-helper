# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""snyk code's rule ``properties.cwe`` reaches the flat ``cwe_id`` column.

``snyk code test --sarif`` names a rule's CWE in ``properties.cwe`` (a list such
as ``["CWE-798"]``); its tags are language and category words. The shared flat
reader (``utils/taxonomy_ids``) reads tags only and, by its own contract, leaves
a scanner that encodes a CWE another way to normalize its SARIF in its adapter.
These rows pin that the snyk adapter does, under the attach rules: adapter-local
source (the rule's own ``cwe``), fail-closed on a value it cannot read exactly,
and attached under the existing tags key the flat reader already consumes.

The first row is the characterization of the gap: the same document through the
flat reader with no normalization reads ``cwe_id`` as None.
"""

from __future__ import annotations

import copy

import pytest

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    normalize_rule_cwe_into_tags,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit


def snyk_document(rule_properties):
    """A document shaped like ``snyk code test --sarif``: the CWE on the rule."""
    rule = {
        "id": "python/HardcodedSecret",
        "shortDescription": {"text": "HardcodedSecret"},
    }
    if rule_properties is not None:
        rule["properties"] = rule_properties
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "SnykCode", "rules": [rule]}},
                "results": [
                    {
                        "ruleId": "python/HardcodedSecret",
                        "level": "error",
                        "message": {"text": "Hardcoded secret"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def flat_cwe(document):
    report = SarifReport.model_validate(document)
    run = report.runs[0]
    return FlatVulnerability.from_sarif_result(
        run.results[0], tool_name="snyk-code", tool_type="SAST", run=run
    ).cwe_id


NATIVE = {"tags": ["Python", "Security"], "cwe": ["CWE-798"]}


def test_without_normalization_the_native_cwe_is_none():
    """The gap: the shared reader reads tags only."""
    assert flat_cwe(snyk_document(NATIVE)) is None


def test_normalized_native_cwe_reaches_the_flat_column():
    document = normalize_rule_cwe_into_tags(snyk_document(NATIVE))
    assert flat_cwe(document) == "CWE-798"


def test_several_cwes_keep_their_order_and_the_other_tags_stay():
    document = normalize_rule_cwe_into_tags(
        snyk_document({"tags": ["Python"], "cwe": ["CWE-78", "cwe-88", "CWE-78"]})
    )
    rule = document["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["tags"][0] == "Python"
    assert flat_cwe(document) == "CWE-78, CWE-88"


def test_a_rule_with_no_tags_key_gets_one():
    document = normalize_rule_cwe_into_tags(snyk_document({"cwe": ["CWE-79"]}))
    assert flat_cwe(document) == "CWE-79"


def test_a_cwe_already_tagged_is_not_added_twice():
    document = normalize_rule_cwe_into_tags(
        snyk_document({"tags": ["external/cwe/cwe-798"], "cwe": ["CWE-798"]})
    )
    tags = document["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert tags == ["external/cwe/cwe-798"]


def test_the_native_cwe_value_is_left_where_snyk_put_it():
    document = normalize_rule_cwe_into_tags(snyk_document(NATIVE))
    properties = document["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
    assert properties["cwe"] == ["CWE-798"]


@pytest.mark.parametrize(
    "properties",
    [
        None,
        {},
        {"tags": ["Python"]},
        {"cwe": None},
        {"cwe": "CWE-798"},
        {"cwe": {"id": "CWE-798"}},
        {"cwe": []},
        {"cwe": ["not-a-cwe"]},
        {"cwe": ["CWE-"]},
        {"cwe": ["CWE-798 and more"]},
        {"cwe": [798]},
    ],
    ids=lambda p: repr(p),
)
def test_a_value_it_cannot_read_exactly_attaches_nothing(properties):
    original = snyk_document(properties)
    document = normalize_rule_cwe_into_tags(copy.deepcopy(original))
    assert document == original
    assert flat_cwe(document) is None


def test_one_unreadable_entry_does_not_hide_the_readable_ones():
    document = normalize_rule_cwe_into_tags(
        snyk_document({"cwe": ["CWE-798", "garbage", None]})
    )
    assert flat_cwe(document) == "CWE-798"


@pytest.mark.parametrize(
    "document", [None, [], "x", {}, {"runs": None}, {"runs": ["x"]}, {"runs": [{}]}]
)
def test_a_document_of_another_shape_is_returned_unchanged(document):
    expected = copy.deepcopy(document)
    assert normalize_rule_cwe_into_tags(document) == expected
