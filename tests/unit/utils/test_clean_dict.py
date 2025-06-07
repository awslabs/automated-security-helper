"""Unit tests for clean_dict.py."""

import pytest
from automated_security_helper.utils.clean_dict import clean_dict


def test_clean_dict_with_none_values():
    """Test clean_dict removes None values from dictionaries."""
    input_dict = {
        "key1": "value1",
        "key2": None,
        "key3": "value3"
    }

    result = clean_dict(input_dict)

    assert "key1" in result
    assert "key3" in result
    assert "key2" not in result
    assert result["key1"] == "value1"
    assert result["key3"] == "value3"


def test_clean_dict_with_nested_dict():
    """Test clean_dict removes None values from nested dictionaries."""
    input_dict = {
        "key1": "value1",
        "key2": {
            "nested1": "nested_value1",
            "nested2": None
        }
    }

    result = clean_dict(input_dict)

    assert "key1" in result
    assert "key2" in result
    assert "nested1" in result["key2"]
    assert "nested2" not in result["key2"]


def test_clean_dict_with_list():
    """Test clean_dict processes lists correctly."""
    input_dict = {
        "key1": "value1",
        "key2": [
            "item1",
            None,
            "item3",
            {"subkey1": "subvalue1", "subkey2": None}
        ]
    }

    result = clean_dict(input_dict)

    assert "key1" in result
    assert "key2" in result
    # The current implementation doesn't remove None items from lists
    # It only processes the items recursively
    assert len(result["key2"]) == 4
    assert result["key2"][0] == "item1"
    assert result["key2"][1] is None
    assert result["key2"][2] == "item3"
    assert "subkey1" in result["key2"][3]
    assert "subkey2" not in result["key2"][3]


def test_clean_dict_with_non_dict_input():
    """Test clean_dict handles non-dictionary inputs correctly."""
    # Test with string
    assert clean_dict("test_string") == "test_string"

    # Test with number
    assert clean_dict(42) == 42

    # Test with None
    assert clean_dict(None) is None

    # Test with empty list
    assert clean_dict([]) == []

    # Test with empty dict
    assert clean_dict({}) == {}