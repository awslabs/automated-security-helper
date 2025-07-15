"""Test coverage for get_value_from_path function."""

from automated_security_helper.utils.meta_analysis.get_value_from_path import (
    get_value_from_path,
)


def test_get_value_from_path_simple_dict():
    """Test get_value_from_path with simple dictionary."""
    data = {"key1": "value1", "key2": "value2"}

    # Test getting existing keys
    result = get_value_from_path(data, "key1")
    assert result["exists"] is True
    assert result["value"] == "value1"

    result = get_value_from_path(data, "key2")
    assert result["exists"] is True
    assert result["value"] == "value2"

    # Test getting non-existent key
    result = get_value_from_path(data, "key3")
    assert result["exists"] is False
    assert result["value"] is None


def test_get_value_from_path_nested_dict():
    """Test get_value_from_path with nested dictionary."""
    data = {"level1": {"level2": {"level3": "value"}}}

    # Test getting nested value with dot notation
    result = get_value_from_path(data, "level1.level2.level3")
    assert result["exists"] is True
    assert result["value"] == "value"

    # Test getting intermediate level
    result = get_value_from_path(data, "level1.level2")
    assert result["exists"] is True
    assert result["value"] == {"level3": "value"}

    # Test getting non-existent nested key
    result = get_value_from_path(data, "level1.level2.level4")
    assert result["exists"] is False
    assert result["value"] is None

    result = get_value_from_path(data, "level1.level3")
    assert result["exists"] is False
    assert result["value"] is None


def test_get_value_from_path_with_lists():
    """Test get_value_from_path with lists."""
    data = {
        "items": [
            {"id": 1, "name": "Item 1"},
            {"id": 2, "name": "Item 2"},
            {"id": 3, "name": "Item 3"},
        ]
    }

    # Test getting list
    result = get_value_from_path(data, "items")
    assert result["exists"] is True
    assert len(result["value"]) == 3

    # Test getting item from list by index
    result = get_value_from_path(data, "items[0]")
    assert result["exists"] is True
    assert result["value"] == {"id": 1, "name": "Item 1"}

    result = get_value_from_path(data, "items[1]")
    assert result["exists"] is True
    assert result["value"] == {"id": 2, "name": "Item 2"}

    # Test getting property from list item
    result = get_value_from_path(data, "items[0].id")
    assert result["exists"] is True
    assert result["value"] == 1

    result = get_value_from_path(data, "items[1].name")
    assert result["exists"] is True
    assert result["value"] == "Item 2"

    # Test with out-of-bounds index
    result = get_value_from_path(data, "items[10]")
    assert result["exists"] is True  # Array exists but index is out of bounds
    assert result["value"] is None

    # Test with invalid index
    result = get_value_from_path(data, "items[invalid]")
    assert result["exists"] is False
    assert result["value"] is None


def test_get_value_from_path_with_none_data():
    """Test get_value_from_path with None data."""
    # This should handle None data gracefully
    result = get_value_from_path(None, "key")
    assert result["exists"] is False
    assert result["value"] is None


def test_get_value_from_path_with_non_dict_data():
    """Test get_value_from_path with non-dictionary data."""
    # Test with string
    result = get_value_from_path("string", "key")
    assert result["exists"] is False
    assert result["value"] is None

    # Test with number
    result = get_value_from_path(123, "key")
    assert result["exists"] is False
    assert result["value"] is None


def test_get_value_from_path_with_empty_path():
    """Test get_value_from_path with empty path."""
    data = {"key": "value"}

    # Empty path should return False for exists
    result = get_value_from_path(data, "")
    assert result["exists"] is False
    assert result["value"] is None
