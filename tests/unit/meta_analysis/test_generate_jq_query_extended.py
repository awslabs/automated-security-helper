import pytest
from automated_security_helper.utils.meta_analysis.generate_jq_query import generate_jq_query


def test_generate_jq_query_complex_nested_path():
    """Test generate_jq_query with a complex nested path."""
    field_path = "runs[0].results[0].locations[0].physicalLocation.region.startLine"
    query = generate_jq_query(field_path)

    # The query should select objects where the specified field exists
    assert "select" in query
    assert "runs" in query
    assert "physicalLocation.region.startLine" in query


def test_generate_jq_query_simple_field():
    """Test generate_jq_query with a simple field."""
    field_path = "version"
    query = generate_jq_query(field_path)

    # The query should select objects where the version field exists
    assert query == '. | select(has("version")) | select(.version != null)'


def test_generate_jq_query_with_array_notation():
    """Test generate_jq_query with array notation."""
    field_path = "runs[0].tool.driver.rules[0].id"
    query = generate_jq_query(field_path)

    # The query should select objects where the specified field exists
    assert "select" in query
    assert "runs" in query
    assert "tool.driver.rules" in query