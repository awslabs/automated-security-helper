from automated_security_helper.utils.meta_analysis.should_include_field import (
    should_include_field,
)


def test_should_include_field_empty_path():
    """Test should_include_field with an empty path."""
    assert should_include_field("") is False


def test_should_include_field_runs_results():
    """Test should_include_field with paths under runs[].results."""
    assert should_include_field("runs[0].results[0].ruleId") is True
    assert should_include_field("runs[0].results[0].message.text") is True
    assert (
        should_include_field(
            "runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri"
        )
        is True
    )


def test_should_include_field_excluded_patterns():
    """Test should_include_field with excluded patterns."""
    assert should_include_field("$schema") is False
    assert should_include_field("runs[0].tool.driver.name") is False
    assert should_include_field("runs[0].results[0].ruleIndex") is False
    assert should_include_field("runs[0].invocations[0].commandLine") is False
    assert should_include_field("version") is False


def test_should_include_field_normalized_paths():
    """Test should_include_field with normalized paths."""
    assert should_include_field("runs.results.ruleId") is True
    assert should_include_field("runs[].results[].ruleId") is True


def test_should_include_field_other_paths():
    """Test should_include_field with other paths that should be excluded."""
    assert should_include_field("properties.schema") is False
    assert should_include_field("runs[0].language") is False
    assert should_include_field("runs[0].conversion.tool.driver.name") is False
