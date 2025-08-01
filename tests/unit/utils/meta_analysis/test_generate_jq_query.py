from automated_security_helper.utils.meta_analysis.generate_jq_query import (
    generate_jq_query,
)


def test_generate_jq_query_simple_path():
    """Test generating jq query for a simple path."""
    path = "version"
    query = generate_jq_query(path)
    expected = '. | select(has("version")) | select(.version != null)'
    assert query == expected


def test_generate_jq_query_nested_path():
    """Test generating jq query for a nested path."""
    path = "runs.tool.driver.name"
    query = generate_jq_query(path)
    expected = '. | select(has("runs")) | select(.runs.tool.driver.name != null)'
    assert query == expected


def test_generate_jq_query_with_array():
    """Test generating jq query for a path with array notation."""
    path = "runs[].results[].ruleId"
    query = generate_jq_query(path)
    expected = ". | select(.runs[] | select(.results[] | select(.ruleId != null)))"
    assert query == expected


def test_generate_jq_query_complex_path():
    """Test generating jq query for a complex path."""
    path = "runs[].results[].locations[].physicalLocation.artifactLocation.uri"
    query = generate_jq_query(path)
    expected = ". | select(.runs[] | select(.results[] | select(.locations[] | select(.physicalLocation.artifactLocation.uri != null))))"
    assert query == expected
