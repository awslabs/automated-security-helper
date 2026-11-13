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
    """A bare ``runs`` key is the runs array: ``.runs.tool`` indexed the array
    with a field name, a jq runtime error on every SARIF document."""
    path = "runs.tool.driver.name"
    query = generate_jq_query(path)
    expected = ".runs[] | select(.tool.driver.name != null)"
    assert query == expected


def test_generate_jq_query_with_array():
    """The query outputs the findings that carry the field. The old nested
    ``select(.runs[] | select(...))`` fed a generator to select, which printed
    the whole document once per matching result."""
    path = "runs[].results[].ruleId"
    query = generate_jq_query(path)
    expected = ".runs[].results[] | select(.ruleId != null)"
    assert query == expected


def test_generate_jq_query_complex_path():
    """An array below the results is tested with any(), one boolean per finding."""
    path = "runs[].results[].locations[].physicalLocation.artifactLocation.uri"
    query = generate_jq_query(path)
    expected = ".runs[].results[] | select(any(.locations[]; .physicalLocation.artifactLocation.uri != null))"
    assert query == expected


def test_an_array_path_never_asks_has_for_a_bracketed_key():
    """``has("runs[]")`` names a key no document holds, so the JQ command the HTML
    report offered returned nothing for almost every field: every array path
    streams the results, not only the few spelled out before."""
    query = generate_jq_query("runs[].results[].level")

    assert 'runs[]"' not in query
    assert query == ".runs[].results[] | select(.level != null)"


def test_an_indexed_path_reads_as_its_array_form():
    assert generate_jq_query("runs[0].results[3].kind") == generate_jq_query(
        "runs[].results[].kind"
    )


def test_a_path_under_another_array_streams_that_array():
    assert generate_jq_query("runs[].tool.driver.rules[].id") == (
        ".runs[].tool.driver.rules[] | select(.id != null)"
    )
    assert generate_jq_query("runs[].invocations[].executionSuccessful") == (
        ".runs[].invocations[] | select(.executionSuccessful != null)"
    )


def test_a_result_relative_path_is_read_under_the_results():
    """The validation reports result-relative paths (message.text); a query
    that asked the document for has("message") found nothing."""
    assert generate_jq_query("message.text") == (
        ".runs[].results[] | select(.message.text != null)"
    )
    assert generate_jq_query("locations[0].physicalLocation.region.startLine") == (
        ".runs[].results[] | select(any(.locations[]; .physicalLocation.region.startLine != null))"
    )


def test_a_key_that_is_not_a_jq_identifier_is_quoted():
    """A fingerprint key such as bandit/v1 spliced as a bare .key failed to compile."""
    assert generate_jq_query('runs[].results[].fingerprints["bandit/v1"]') == (
        '.runs[].results[] | select(.fingerprints["bandit/v1"] != null)'
    )
    assert generate_jq_query("runs[].results[].it's") == (
        '.runs[].results[] | select(.["it\'s"] != null)'
    )
    assert generate_jq_query("runs[].tool.driver-name") == (
        '.runs[] | select(.tool["driver-name"] != null)'
    )
