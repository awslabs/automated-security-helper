"""Tests for compare_result_fields module."""

from unittest.mock import patch

from automated_security_helper.cli.inspect.compare_result_fields import (
    compare_result_fields,
)


class TestCompareResultFields:
    """Tests for compare_result_fields function."""

    @patch(
        "automated_security_helper.cli.inspect.compare_result_fields.extract_field_paths"
    )
    @patch(
        "automated_security_helper.cli.inspect.compare_result_fields.get_value_from_path"
    )
    @patch(
        "automated_security_helper.cli.inspect.compare_result_fields.categorize_field_importance"
    )
    def test_returns_missing_fields(
        self, mock_categorize, mock_get_value, mock_extract
    ):
        """Fields in original but not in aggregated are reported as missing."""
        mock_extract.side_effect = [
            {"ruleId": {}, "message.text": {}},  # orig_paths
            {"ruleId": {}},  # agg_paths (missing message.text)
        ]
        mock_get_value.return_value = {"value": "some description"}
        mock_categorize.return_value = "high"

        result = compare_result_fields({"ruleId": "R1"}, {"ruleId": "R1"})

        assert len(result) == 1
        assert result[0]["path"] == "message.text"
        assert result[0]["original_value"] == "some description"
        assert result[0]["importance"] == "high"

    @patch(
        "automated_security_helper.cli.inspect.compare_result_fields.extract_field_paths"
    )
    def test_no_missing_fields(self, mock_extract):
        """When aggregated has all fields, empty list is returned."""
        mock_extract.side_effect = [
            {"ruleId": {}, "level": {}},
            {"ruleId": {}, "level": {}},
        ]

        result = compare_result_fields({}, {})
        assert result == []

    @patch(
        "automated_security_helper.cli.inspect.compare_result_fields.extract_field_paths"
    )
    def test_skips_properties_path(self, mock_extract):
        """The 'properties' and '.properties' paths are skipped."""
        mock_extract.side_effect = [
            {"properties": {}, ".properties": {}, "level": {}},
            {"level": {}},  # missing properties paths
        ]

        result = compare_result_fields({}, {})
        # properties and .properties should be skipped even though missing from agg
        assert result == []

    @patch(
        "automated_security_helper.cli.inspect.compare_result_fields.extract_field_paths"
    )
    def test_skips_expected_transformations(self, mock_extract):
        """Paths matching EXPECTED_TRANSFORMATIONS are skipped."""
        mock_extract.side_effect = [
            {"ruleIndex": {}, "tool.driver": {}, "tool.driver.name": {}},
            {},  # none present in agg
        ]

        result = compare_result_fields({}, {})
        # All three should be skipped (ruleIndex exact, tool.driver exact,
        # tool.driver.name starts with tool.driver.)
        assert result == []

    @patch(
        "automated_security_helper.cli.inspect.compare_result_fields.extract_field_paths"
    )
    @patch(
        "automated_security_helper.cli.inspect.compare_result_fields.get_value_from_path"
    )
    @patch(
        "automated_security_helper.cli.inspect.compare_result_fields.categorize_field_importance"
    )
    def test_multiple_missing_fields(
        self, mock_categorize, mock_get_value, mock_extract
    ):
        """Multiple missing fields are all returned."""
        mock_extract.side_effect = [
            {"a": {}, "b": {}, "c": {}},
            {"a": {}},
        ]
        mock_get_value.return_value = {"value": "val"}
        mock_categorize.return_value = "low"

        result = compare_result_fields({}, {})
        assert len(result) == 2
        paths = {r["path"] for r in result}
        assert paths == {"b", "c"}
