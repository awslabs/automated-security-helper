# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The field-path grammar and the value comparison of ``field_mapping``.

Paths were built by joining raw keys with ``.`` and ``[N]`` and read by splitting
on ``.`` and the first ``[``, so a key holding a ``.`` or ``[`` could not be looked
up, a second index on one segment (``m[0][1]``) was ignored, ``[]`` never resolved,
and a null intermediate read as a present deeper field. ``extract_field_paths``
dropped its context when a path was given, replaced a caller's accumulator entry,
and never descended into a list nested in a list. ``categorize_field_importance``
matched substrings in a fixed order, ``should_include_field`` normalized only
``[0]``, and ``are_values_equivalent`` compared list elements by hash and read two
messages differing only in slash direction as one.
"""

import pytest

from automated_security_helper.utils.meta_analysis.field_mapping import (
    are_values_equivalent,
    categorize_field_importance,
    compare_result_fields,
    comparable_field_paths,
    extract_field_paths,
    format_key,
    get_value_from_path,
    join_path,
    jq_path,
    parse_field_path,
    should_include_field,
)

pytestmark = pytest.mark.unit


class TestTheGrammar:
    def test_a_key_holding_a_dot_or_bracket_is_bracket_quoted(self):
        assert format_key("ruleId") == "ruleId"
        assert format_key("matchBasedId/v1.2") == '["matchBasedId/v1.2"]'
        assert format_key("a[0]") == '["a[0]"]'
        assert format_key("") == '[""]'
        assert join_path("properties", "a.b") == 'properties["a.b"]'
        assert join_path("", "a.b") == '["a.b"]'

    def test_a_quoted_key_and_several_indices_parse(self):
        assert parse_field_path('runs[0].results[].a["b.c"][2]') == [
            ("key", "runs"),
            ("index", 0),
            ("key", "results"),
            ("any", None),
            ("key", "a"),
            ("key", "b.c"),
            ("index", 2),
        ]
        assert parse_field_path("m[0][1]") == [
            ("key", "m"),
            ("index", 0),
            ("index", 1),
        ]
        assert parse_field_path("[0].x") == [("index", 0), ("key", "x")]

    def test_a_malformed_path_is_none(self):
        assert parse_field_path("") is None
        assert parse_field_path("a..b") is None
        assert parse_field_path("a[x]") is None
        assert parse_field_path("a[0") is None
        assert parse_field_path("a.") is None

    def test_a_non_identifier_key_is_quoted_for_jq(self):
        assert jq_path("runs[].results[].ruleId") == ".runs[].results[].ruleId"
        assert jq_path('runs[].results[].fingerprints["bandit/v1"]') == (
            '.runs[].results[].fingerprints["bandit/v1"]'
        )
        assert jq_path("runs[0].tool.driver-name") == '.runs[0].tool["driver-name"]'
        # A bare ["x"] is an array literal to jq; a leading bracket is indexed.
        assert jq_path('["a.b"].c') == '.["a.b"].c'
        assert jq_path("[0].c") == ".[0].c"


class TestExtractFieldPaths:
    def test_a_context_prefixes_a_given_path(self):
        paths = extract_field_paths({"a": 1}, path="p", context_path="c")

        # The context was dropped whenever a path was given.
        assert "c.p.a" in paths

    def test_a_callers_accumulator_keeps_its_earlier_types_and_scanners(self):
        paths = {"a": {"type": {"int"}, "scanners": {"bandit"}}}

        extract_field_paths({"a": "x"}, paths=paths)

        assert paths["a"]["type"] == {"int", "str"}
        assert paths["a"]["scanners"] == {"bandit"}

    def test_a_list_nested_in_a_list_is_walked(self):
        paths = extract_field_paths({"m": [[1, {"k": 2}]]})

        assert "m[0][0]" in paths
        assert "m[0][1].k" in paths

    def test_a_dotted_key_round_trips_through_get_value_from_path(self):
        obj = {"fingerprints": {"matchBasedId/v1.2": "abc"}}

        paths = extract_field_paths(obj)

        (path,) = [p for p in paths if p != "fingerprints"]
        assert path == 'fingerprints["matchBasedId/v1.2"]'
        assert get_value_from_path(obj, path) == {"exists": True, "value": "abc"}


class TestGetValueFromPath:
    def test_a_second_index_on_one_segment_is_read(self):
        obj = {"m": [[10, 11], [20, 21]]}

        assert get_value_from_path(obj, "m[0][1]") == {"exists": True, "value": 11}
        assert get_value_from_path(obj, "m[1][0]") == {"exists": True, "value": 20}

    def test_any_element_exists_when_some_element_holds_the_rest(self):
        obj = {"runs": [{"results": [{"a": 1}, {"ruleId": "R"}]}]}

        assert get_value_from_path(obj, "runs[].results[].ruleId") == {
            "exists": True,
            "value": "R",
        }
        assert get_value_from_path(obj, "runs[].results[].missing")["exists"] is False

    def test_a_null_intermediate_holds_no_deeper_field(self):
        obj = {"a": None}

        assert get_value_from_path(obj, "a") == {"exists": True, "value": None}
        # Read as present (with a null value) before.
        assert get_value_from_path(obj, "a.b") == {"exists": False, "value": None}


class TestCategorizeFieldImportance:
    def test_a_field_under_a_context_container_is_important(self):
        assert (
            categorize_field_importance(
                "runs[].results[].relatedLocations[].physicalLocation.region.startLine"
            )
            == "important"
        )
        assert (
            categorize_field_importance(
                "codeFlows[0].threadFlows[0].locations[0].location.message.text"
            )
            == "important"
        )
        assert categorize_field_importance(
            "fixes[0].artifactChanges[0].artifactLocation.uri"
        ) == ("important")

    def test_a_key_that_merely_contains_a_critical_name_is_not_critical(self):
        assert (
            categorize_field_importance("properties.levelOfDetail") == "informational"
        )
        assert categorize_field_importance("properties.region_name") == "informational"
        assert categorize_field_importance("runs[].results[].level") == "critical"


class TestShouldIncludeField:
    def test_every_index_reads_as_any_element(self):
        assert should_include_field("runs[1].results[0].ruleId") is True
        assert should_include_field("runs[0].results[1].ruleIndex") is False
        assert should_include_field("runs[2].tool.driver.name") is False


class TestAreValuesEquivalent:
    def test_list_elements_follow_the_scalar_rules(self):
        assert not are_values_equivalent([1], [True])
        assert not are_values_equivalent(1, True)
        assert are_values_equivalent([1, 2], [2, 1])
        assert not are_values_equivalent([1, 1, 2], [1, 2, 2])

    def test_an_integer_and_a_float_of_one_value_are_equal_everywhere(self):
        assert are_values_equivalent(50, 50.0)
        assert are_values_equivalent([50], [50.0])
        assert are_values_equivalent({"rank": 50}, {"rank": 50.0})

    def test_dicts_in_a_list_compare_by_content_not_key_order(self):
        assert are_values_equivalent([{"a": 1, "b": 2}], [{"b": 2, "a": 1}])
        assert not are_values_equivalent([{"a": 1}], [{"a": 2}])

    def test_strings_differing_in_slash_direction_are_different(self):
        assert not are_values_equivalent("a\\b", "a/b")
        assert not are_values_equivalent(["a\\b"], ["a/b"])

    def test_a_location_uri_is_still_compared_as_a_path(self):
        original = {
            "ruleId": "R1",
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "src\\a.py"}}}
            ],
        }
        aggregated = {
            "ruleId": "R1",
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "src/a.py"}}}
            ],
        }

        assert compare_result_fields(original, aggregated) == []


def test_comparable_field_paths_leaves_out_the_expected_transformations():
    result = {"ruleId": "R1", "ruleIndex": 3, "analysisTarget": {"uri": "a"}, "x": 1}

    assert comparable_field_paths(result) == ["ruleId", "x"]
