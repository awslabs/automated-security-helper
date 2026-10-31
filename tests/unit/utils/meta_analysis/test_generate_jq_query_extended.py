import pytest

from automated_security_helper.utils.meta_analysis.reporting import (
    generate_jq_query,
)

pytestmark = pytest.mark.unit


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


def test_a_path_that_ends_in_an_array_tests_the_elements():
    """``tags[]`` has no key after its array, so the condition on each element
    is the element itself. The empty path rendered `` != null`` here, which jq
    refuses to compile, so every field path ending in ``[]`` gave an example
    that could not run."""
    assert (
        generate_jq_query("runs[].results[].tags[]")
        == ".runs[].results[] | select(any(.tags[]; . != null))"
    )
    assert (
        generate_jq_query("runs[].results[].locations[].logicalLocations[]")
        == ".runs[].results[] | select(any(.locations[]; "
        "any(.logicalLocations[]; . != null)))"
    )


@pytest.mark.parametrize(
    ("field_path", "expected"),
    [
        (
            "$schema",
            '. | select(has("$schema")) | select(.["$schema"] != null)',
        ),
        (
            "runs[].results[].properties.security-severity",
            '.runs[].results[] | select(.properties["security-severity"] != null)',
        ),
        (
            "runs[].tool.driver.rules[].properties.security-severity",
            '.runs[].tool.driver.rules[] | select(.properties["security-severity"] != null)',
        ),
    ],
    ids=["document-key", "result-key", "rule-key"],
)
def test_a_key_that_is_not_a_jq_identifier_is_bracket_quoted(field_path, expected):
    """``$schema`` and ``security-severity`` are keys SARIF files carry; a bare
    ``.$schema`` or ``.security-severity`` does not compile."""
    assert generate_jq_query(field_path) == expected
