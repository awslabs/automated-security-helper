from automated_security_helper.utils.meta_analysis.extract_field_paths import (
    extract_field_paths,
)


def test_extract_field_paths_simple_dict():
    """Test extracting field paths from a simple dictionary."""
    test_obj = {"name": "test", "value": 123, "nested": {"key": "value"}}

    paths = {}
    extract_field_paths(test_obj, paths=paths)

    assert "name" in paths
    assert "value" in paths
    assert "nested.key" in paths


def test_extract_field_paths_with_arrays():
    """Test extracting field paths from objects with arrays."""
    test_obj = {"items": [{"id": 1, "name": "item1"}, {"id": 2, "name": "item2"}]}

    paths = {}
    extract_field_paths(test_obj, paths=paths)

    # The implementation uses indexed notation [0] instead of []
    assert "items[0].id" in paths
    assert "items[0].name" in paths


def test_extract_field_paths_with_context():
    """Test extracting field paths with context path."""
    test_obj = {"result": {"id": "test-id", "details": {"severity": "high"}}}

    paths = {}
    extract_field_paths(test_obj, context_path="sarif", paths=paths)

    # The implementation appends context to each path
    assert "sarif.result.id" in paths
    assert "sarif.result.details.severity" in paths
