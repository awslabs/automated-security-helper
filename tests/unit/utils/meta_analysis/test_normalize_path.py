from automated_security_helper.utils.meta_analysis.normalize_path import normalize_path


def test_normalize_path_simple():
    """Test normalizing a simple path."""
    assert normalize_path("version") == "version"
    assert normalize_path("name") == "name"


def test_normalize_path_nested():
    """Test normalizing a nested path."""
    assert normalize_path("tool.driver.name") == "name"
    assert normalize_path("message.text") == "text"


def test_normalize_path_with_arrays():
    """Test normalizing paths with array notation."""
    assert normalize_path("runs[0].results[0].ruleId") == "ruleId"
    assert normalize_path("runs[].results[].ruleId") == "ruleId"


def test_normalize_path_complex():
    """Test normalizing complex paths."""
    assert (
        normalize_path(
            "runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri"
        )
        == "uri"
    )
