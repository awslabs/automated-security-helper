from automated_security_helper.utils.meta_analysis.should_include_field import (
    should_include_field,
)


def test_should_include_field():
    """Test determining if a field should be included in analysis."""
    # Fields that should be included
    assert should_include_field("runs[0].results[0].ruleId") is True
    assert should_include_field("runs[0].results[0].message.text") is True
    assert (
        should_include_field("runs[0].results[0].locations[0].physicalLocation") is True
    )

    # Fields that should be excluded
    assert should_include_field("$schema") is False
    assert should_include_field("properties.guid") is False
    assert should_include_field("runs[0].invocations[0].executionSuccessful") is False
    assert should_include_field("runs[0].tool.driver.name") is False
    assert should_include_field("version") is False

    # Edge cases
    assert should_include_field("") is False
    assert should_include_field(None) is False
