"""Unit tests for get_value_from_path module to increase coverage."""

import pytest

from automated_security_helper.utils.meta_analysis.get_value_from_path import get_value_from_path


def test_get_value_from_path_simple_dict():
    """Test get_value_from_path with simple dictionary."""
    data = {"key1": "value1", "key2": "value2"}

    # Test getting existing keys
    assert get_value_from_path(data, "key1") == "value1"
    assert get_value_from_path(data, "key2") == "value2"

    # Test getting non-existent key
    assert get_value_from_path(data, "key3") is None

    # Test with default value
    assert get_value_from_path(data, "key3", default="default") == "default"


def test_get_value_from_path_nested_dict():
    """Test get_value_from_path with nested dictionary."""
    data = {
        "level1": {
            "level2": {
                "level3": "value"
            }
        }
    }

    # Test getting nested value with dot notation
    assert get_value_from_path(data, "level1.level2.level3") == "value"

    # Test getting intermediate level
    assert get_value_from_path(data, "level1.level2") == {"level3": "value"}

    # Test getting non-existent nested key
    assert get_value_from_path(data, "level1.level2.level4") is None
    assert get_value_from_path(data, "level1.level3") is None

    # Test with default value
    assert get_value_from_path(data, "level1.level3", default="default") == "default"


def test_get_value_from_path_with_lists():
    """Test get_value_from_path with lists."""
    data = {
        "items": [
            {"id": 1, "name": "Item 1"},
            {"id": 2, "name": "Item 2"},
            {"id": 3, "name": "Item 3"}
        ]
    }

    # Test getting list
    assert len(get_value_from_path(data, "items")) == 3

    # Test getting item from list by index
    assert get_value_from_path(data, "items[0]") == {"id": 1, "name": "Item 1"}
    assert get_value_from_path(data, "items[1]") == {"id": 2, "name": "Item 2"}

    # Test getting property from list item
    assert get_value_from_path(data, "items[0].id") == 1
    assert get_value_from_path(data, "items[1].name") == "Item 2"

    # Test with out-of-bounds index
    assert get_value_from_path(data, "items[10]") is None

    # Test with invalid index
    assert get_value_from_path(data, "items[invalid]") is None


def test_get_value_from_path_with_none_data():
    """Test get_value_from_path with None data."""
    assert get_value_from_path(None, "key") is None
    assert get_value_from_path(None, "key", default="default") == "default"


def test_get_value_from_path_with_non_dict_data():
    """Test get_value_from_path with non-dictionary data."""
    # Test with string
    assert get_value_from_path("string", "key") is None

    # Test with list
    assert get_value_from_path([1, 2, 3], "key") is None

    # Test with number
    assert get_value_from_path(123, "key") is None


def test_get_value_from_path_with_empty_path():
    """Test get_value_from_path with empty path."""
    data = {"key": "value"}

    # Empty path should return the original data
    assert get_value_from_path(data, "") == data
    assert get_value_from_path(data, None) == data