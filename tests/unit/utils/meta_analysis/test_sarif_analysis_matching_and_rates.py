# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Matching and statistics in ``sarif_analysis``.

``field_preservation_rate`` was the match rate under another name, so a scanner
whose every matched result had lost critical fields still read 1.0. Two original
report keys that normalize to one scanner name reset each other's statistics. A
result naming its rule through ``rule.id`` alone never matched; two results naming
no rule at all matched on location alone; an aggregated result of another scanner
with the same rule id and location was a match; and a first location given as JSON
null raised AttributeError out of the whole check.
"""

import pytest

from automated_security_helper.utils.meta_analysis.sarif_analysis import (
    extract_location_info,
    find_matching_result,
    validate_sarif_aggregation,
)

pytestmark = pytest.mark.unit


def _result(rule_id, uri, line, text="finding", **extra):
    result = {
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line, "endLine": line},
                }
            }
        ],
        **extra,
    }
    if rule_id is not None:
        result["ruleId"] = rule_id
    return result


def _report(*results):
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "t"}}, "results": list(results)}],
    }


def test_the_preservation_rate_counts_fields_not_matches():
    original = {"bandit": _report(_result("R1", "a.py", 3, level="error", kind="fail"))}
    aggregated = _report(_result("R1", "a.py", 3))

    stats = validate_sarif_aggregation(original, aggregated)["match_statistics"][
        "bandit"
    ]

    assert stats["match_rate"] == 1.0
    # Seven leaves compared (ruleId, message.text, the location's uri, startLine
    # and endLine, level, kind); level and kind are gone: 5 of 7 preserved.
    assert stats["fields_compared"] == 7
    assert stats["fields_missing"] == 2
    assert stats["field_preservation_rate"] == pytest.approx(5 / 7)


def test_a_full_match_with_every_field_kept_reads_one():
    original = {"bandit": _report(_result("R1", "a.py", 3))}
    aggregated = _report(_result("R1", "a.py", 3))

    stats = validate_sarif_aggregation(original, aggregated)["match_statistics"][
        "bandit"
    ]

    assert stats["match_rate"] == 1.0
    assert stats["field_preservation_rate"] == 1.0


def test_two_keys_normalizing_to_one_scanner_add_up():
    original = {
        "Bandit": _report(_result("R1", "a.py", 3)),
        "bandit": _report(_result("R2", "b.py", 7)),
    }
    aggregated = _report(_result("R1", "a.py", 3), _result("R2", "b.py", 7))

    results = validate_sarif_aggregation(original, aggregated)

    stats = results["match_statistics"]["bandit"]
    assert stats["total_results"] == 2
    assert stats["matched_results"] == 2
    assert results["summary"]["total_findings"] == 2


def test_a_rule_named_through_rule_id_alone_matches():
    original = _result(None, "a.py", 3, rule={"id": "R1", "index": 0})
    aggregated = [_result(None, "a.py", 3, rule={"id": "R1", "index": 4})]

    assert find_matching_result(original, aggregated) is aggregated[0]
    # And a result that names rule R2 is not it.
    assert find_matching_result(original, [_result("R2", "a.py", 3)]) is None


def test_results_naming_no_rule_need_equal_messages_too():
    original = _result(None, "a.py", 3, text="one")
    other_message = [_result(None, "a.py", 3, text="two")]
    same_message = [_result(None, "a.py", 3, text="one")]

    # Matched on location alone before.
    assert find_matching_result(original, other_message) is None
    assert find_matching_result(original, same_message) is same_message[0]


def test_another_scanners_result_at_the_same_place_is_not_a_match():
    original = _result("R1", "a.py", 3)
    aggregated = [
        _result("R1", "a.py", 3, properties={"scanner_name": "semgrep"}),
        _result("R1", "a.py", 3, properties={"scanner_name": "bandit"}),
    ]

    assert (
        find_matching_result(original, aggregated, scanner_name="bandit")
        is (aggregated[1])
    )
    # Without a scanner to compare, the first candidate stands.
    assert find_matching_result(original, aggregated) is aggregated[0]
    # The scanner names are compared normalized: the report's "Bandit" is "bandit".
    assert (
        find_matching_result(original, aggregated, scanner_name="Bandit")
        is (aggregated[1])
    )


def test_a_null_first_location_is_no_location():
    # Raised AttributeError ("'NoneType' object has no attribute 'get'") before.
    assert extract_location_info({"ruleId": "R1", "locations": [None]}) == {
        "file_path": None,
        "start_line": None,
        "end_line": None,
    }
    assert (
        extract_location_info(
            {"ruleId": "R1", "locations": [{"physicalLocation": None}]}
        )["file_path"]
        is None
    )
    assert find_matching_result({"ruleId": "R1", "locations": [None]}, []) is None
