from automated_security_helper.utils.meta_analysis.get_value_from_path import (
    get_value_from_path,
)


def test_get_value_from_path_empty_path():
    """Test get_value_from_path with an empty path."""
    obj = {"key": "value"}
    result = get_value_from_path(obj, "")

    assert result["exists"] is False
    assert result["value"] is None


def test_get_value_from_path_nonexistent_field():
    """Test get_value_from_path with a nonexistent field."""
    obj = {"key": "value"}
    result = get_value_from_path(obj, "nonexistent")

    assert result["exists"] is False
    assert result["value"] is None


def test_get_value_from_path_null_value():
    """Test get_value_from_path with a field that has a null value."""
    obj = {"key": None}
    result = get_value_from_path(obj, "key")

    assert result["exists"] is True
    assert result["value"] is None


def test_get_value_from_path_array_index_out_of_bounds():
    """Test get_value_from_path with an array index that is out of bounds."""
    obj = {"array": [1, 2, 3]}
    result = get_value_from_path(obj, "array[5]")

    assert result["exists"] is True
    assert result["value"] is None


def test_get_value_from_path_invalid_array_index():
    """Test get_value_from_path with an invalid array index."""
    obj = {"array": [1, 2, 3]}
    result = get_value_from_path(obj, "array[invalid]")

    assert result["exists"] is False
    assert result["value"] is None


def test_get_value_from_path_null_array():
    """Test get_value_from_path with a null array."""
    obj = {"array": None}
    result = get_value_from_path(obj, "array[0]")

    assert result["exists"] is False
    assert result["value"] is None
