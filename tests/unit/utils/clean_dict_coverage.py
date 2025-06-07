"""Unit tests for clean_dict module to increase coverage."""

import pytest

from automated_security_helper.utils.clean_dict import clean_dict


def test_clean_dict_with_none_values():
    """Test clean_dict with None values."""
    # Create test dictionary with None values
    test_dict = {
        "key1": "value1",
        "key2": None,
        "key3": "value3",
        "key4": None
    }

    # Clean the dictionary
    result = clean_dict(test_dict)

    # Verify None values are removed
    assert "key1" in result
    assert "key2" not in result
    assert "key3" in result
    assert "key4" not in result
    assert result["key1"] == "value1"
    assert result["key3"] == "value3"


def test_clean_dict_with_empty_values():
    """Test clean_dict with empty values."""
    # Create test dictionary with empty values
    test_dict = {
        "key1": "value1",
        "key2": "",
        "key3": [],
        "key4": {},
        "key5": "value5"
    }

    # Clean the dictionary
    result = clean_dict(test_dict)

    # Verify empty values are removed
    assert "key1" in result
    assert "key2" not in result
    assert "key3" not in result
    assert "key4" not in result
    assert "key5" in result
    assert result["key1"] == "value1"
    assert result["key5"] == "value5"


def test_clean_dict_with_nested_dicts():
    """Test clean_dict with nested dictionaries."""
    # Create test dictionary with nested dictionaries
    test_dict = {
        "key1": "value1",
        "key2": {
            "nested1": "nested_value1",
            "nested2": None,
            "nested3": {
                "deep1": "deep_value1",
                "deep2": None
            }
        },
        "key3": None
    }

    # Clean the dictionary
    result = clean_dict(test_dict)

    # Verify None values are removed at all levels
    assert "key1" in result
    assert "key2" in result
    assert "key3" not in result
    assert "nested1" in result["key2"]
    assert "nested2" not in result["key2"]
    assert "nested3" in result["key2"]
    assert "deep1" in result["key2"]["nested3"]
    assert "deep2" not in result["key2"]["nested3"]


def test_clean_dict_with_lists():
    """Test clean_dict with lists."""
    # Create test dictionary with lists
    test_dict = {
        "key1": "value1",
        "key2": [
            {"item1": "value1", "item2": None},
            {"item3": "value3", "item4": ""}
        ],
        "key3": []
    }

    # Clean the dictionary
    result = clean_dict(test_dict)

    # Verify None and empty values are removed
    assert "key1" in result
    assert "key2" in result
    assert "key3" not in result
    assert len(result["key2"]) == 2
    assert "item1" in result["key2"][0]
    assert "item2" not in result["key2"][0]
    assert "item3" in result["key2"][1]
    assert "item4" not in result["key2"][1]


def test_clean_dict_with_empty_result():
    """Test clean_dict that results in an empty dictionary."""
    # Create test dictionary where all values will be removed
    test_dict = {
        "key1": None,
        "key2": "",
        "key3": [],
        "key4": {}
    }

    # Clean the dictionary
    result = clean_dict(test_dict)

    # Verify result is an empty dictionary
    assert result == {}