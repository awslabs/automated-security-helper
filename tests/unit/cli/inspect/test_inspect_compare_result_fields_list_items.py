"""compare_result_fields treats the items of an expected transformation as expected.

EXPECTED_TRANSFORMATIONS names fields the aggregation changes on purpose, such as
``properties.tags``. extract_field_paths writes a list's items as indexed paths
(``properties.tags[0]``), which neither equal the entry nor start with the entry
and a dot, so every tag of a consolidated tag list was reported as a missing field.
"""

from unittest.mock import patch

import pytest

from automated_security_helper.cli.inspect.compare_result_fields import (
    compare_result_fields,
)

pytestmark = pytest.mark.unit

EXTRACT = (
    "automated_security_helper.cli.inspect.compare_result_fields.extract_field_paths"
)


@patch(EXTRACT)
def test_list_items_of_an_expected_transformation_are_not_missing(mock_extract):
    mock_extract.side_effect = [
        {"properties.tags[0]": {}, "properties.tags[1]": {}, "ruleIndex": {}},
        {},
    ]

    assert compare_result_fields({}, {}) == []


@patch(EXTRACT)
def test_items_of_a_field_nested_under_an_expected_transformation_are_not_missing(
    mock_extract,
):
    mock_extract.side_effect = [{"tool.driver.rules[0].id": {}}, {}]

    assert compare_result_fields({}, {}) == []


@patch(
    "automated_security_helper.cli.inspect.compare_result_fields.categorize_field_importance"
)
@patch(
    "automated_security_helper.cli.inspect.compare_result_fields.get_value_from_path"
)
@patch(EXTRACT)
def test_a_field_whose_name_merely_starts_like_an_entry_is_still_reported(
    mock_extract, mock_get_value, mock_categorize
):
    """Control: "properties.tagsets" is another field, not an item or child of
    "properties.tags", so it is reported when the aggregated result lacks it."""
    mock_extract.side_effect = [{"properties.tagsets": {}}, {}]
    mock_get_value.return_value = {"value": ["a"]}
    mock_categorize.return_value = "informational"

    missing = compare_result_fields({}, {})

    assert [field["path"] for field in missing] == ["properties.tagsets"]


@patch(
    "automated_security_helper.cli.inspect.compare_result_fields.is_expected_transformation"
)
@patch(EXTRACT)
def test_the_expected_transformations_are_decided_by_the_meta_analysis_predicate(
    mock_extract, mock_is_expected
):
    """The loop asks the meta-analysis module's own predicate, so the two never
    read EXPECTED_TRANSFORMATIONS two different ways: a path the predicate calls
    expected is not reported, whatever the list says."""
    mock_extract.side_effect = [{"locations[0].physicalLocation": {}}, {}]
    mock_is_expected.return_value = True

    assert compare_result_fields({}, {}) == []
    mock_is_expected.assert_called_once_with("locations[0].physicalLocation")
