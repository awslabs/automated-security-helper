from automated_security_helper.utils.meta_analysis.get_value_from_path import (
    get_value_from_path,
)


def test_get_value_from_path_simple():
    """Test getting value from a simple path."""
    obj = {"name": "test", "value": 123}

    assert get_value_from_path(obj, "name") == {"exists": True, "value": "test"}
    assert get_value_from_path(obj, "value") == {"exists": True, "value": 123}
    assert get_value_from_path(obj, "missing") == {"exists": False, "value": None}


def test_get_value_from_path_nested():
    """Test getting value from a nested path."""
    obj = {"user": {"name": "test", "profile": {"age": 30}}}

    assert get_value_from_path(obj, "user.name") == {"exists": True, "value": "test"}
    assert get_value_from_path(obj, "user.profile.age") == {"exists": True, "value": 30}
    assert get_value_from_path(obj, "user.email") == {"exists": False, "value": None}
    assert get_value_from_path(obj, "company.name") == {"exists": False, "value": None}


def test_get_value_from_path_with_arrays():
    """Test getting value from a path with arrays."""
    obj = {"items": [{"id": 1, "name": "item1"}, {"id": 2, "name": "item2"}]}

    # First array element
    assert get_value_from_path(obj, "items[0].id") == {"exists": True, "value": 1}
    assert get_value_from_path(obj, "items[0].name") == {
        "exists": True,
        "value": "item1",
    }

    # Second array element
    assert get_value_from_path(obj, "items[1].id") == {"exists": True, "value": 2}
    assert get_value_from_path(obj, "items[1].name") == {
        "exists": True,
        "value": "item2",
    }

    # Out of bounds
    assert get_value_from_path(obj, "items[2].id") == {"exists": True, "value": None}

    # Invalid index
    assert get_value_from_path(obj, "items[a].id") == {"exists": False, "value": None}
