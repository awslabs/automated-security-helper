from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
    are_values_equivalent,
)


def test_are_values_equivalent_simple_types():
    """Test equivalence of simple types."""
    assert are_values_equivalent(1, 1)
    assert are_values_equivalent("test", "test")
    assert are_values_equivalent(True, True)
    assert not are_values_equivalent(1, 2)
    assert not are_values_equivalent("test", "other")
    assert not are_values_equivalent(True, False)


def test_are_values_equivalent_lists():
    """Test equivalence of lists."""
    assert are_values_equivalent([1, 2, 3], [1, 2, 3])
    assert are_values_equivalent(["a", "b"], ["a", "b"])
    assert not are_values_equivalent([1, 2, 3], [1, 2, 4])
    assert not are_values_equivalent([1, 2], [1, 2, 3])


def test_are_values_equivalent_dicts():
    """Test equivalence of dictionaries."""
    # The implementation only checks if keys match, not values
    assert are_values_equivalent({"a": 1, "b": 2}, {"a": 1, "b": 2})
    assert are_values_equivalent(
        {"a": {"nested": "value"}}, {"a": {"nested": "different"}}
    )
    assert not are_values_equivalent({"a": 1, "b": 2}, {"a": 1, "c": 3})
    assert not are_values_equivalent({"a": 1}, {"a": 1, "b": 2})


def test_are_values_equivalent_mixed_types():
    """Test equivalence of mixed types."""
    # String representations are considered equivalent
    assert are_values_equivalent(1, "1")
    assert are_values_equivalent(True, "True")
    assert not are_values_equivalent(1, "2")
