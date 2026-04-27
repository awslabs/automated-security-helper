from automated_security_helper.utils.meta_analysis.normalize_path import normalize_path


def test_normalize_path_simple():
    """Test normalizing a simple path."""
    assert normalize_path("version") == "version"
    assert normalize_path("name") == "name"


def test_normalize_path_nested():
    """Test normalizing a nested SARIF field path preserves full dotted structure."""
    assert normalize_path("tool.driver.name") == "tool.driver.name"
    assert normalize_path("message.text") == "message.text"


def test_normalize_path_with_arrays():
    """Test normalizing paths strips array indices but keeps full structure."""
    assert normalize_path("runs[0].results[0].ruleId") == "runs.results.ruleId"
    assert normalize_path("runs[].results[].ruleId") == "runs.results.ruleId"


def test_normalize_path_complex():
    """Test normalizing complex paths strips indices, keeps full dotted path."""
    assert (
        normalize_path(
            "runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri"
        )
        == "runs.results.locations.physicalLocation.artifactLocation.uri"
    )
