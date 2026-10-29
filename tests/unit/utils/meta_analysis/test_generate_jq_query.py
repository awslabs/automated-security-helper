import pytest

from automated_security_helper.utils.meta_analysis.reporting import (
    generate_jq_query,
)

pytestmark = pytest.mark.unit


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


def test_an_array_path_never_asks_has_for_a_bracketed_key():
    """``has("runs[]")`` names a key no document holds, so the JQ command the HTML
    report offered returned nothing for almost every field: every array path
    gets the nested-select form, not only the few spelled out before."""
    query = generate_jq_query("runs[].results[].level")

    assert 'runs[]"' not in query
    assert query == ". | select(.runs[] | select(.results[] | select(.level != null)))"


def test_an_indexed_path_reads_as_its_array_form():
    assert generate_jq_query("runs[0].results[3].kind") == generate_jq_query(
        "runs[].results[].kind"
    )
