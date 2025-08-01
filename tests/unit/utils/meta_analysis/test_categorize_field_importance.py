from automated_security_helper.utils.meta_analysis.categorize_field_importance import (
    categorize_field_importance,
)


def test_categorize_field_importance():
    """Test categorizing field importance based on path."""
    # Critical fields
    assert categorize_field_importance("runs[].results[].ruleId") == "critical"
    assert categorize_field_importance("runs[].results[].message.text") == "critical"
    assert categorize_field_importance("runs[].results[].level") == "critical"

    # Important fields
    assert (
        categorize_field_importance(
            "runs[].results[].locations[].physicalLocation.artifactLocation.uri"
        )
        == "critical"
    )  # Contains 'artifactLocation'
    assert categorize_field_importance("runs[].results[].kind") == "important"
    assert categorize_field_importance("runs[].results[].baselineState") == "important"

    # Informational fields
    assert categorize_field_importance("runs[].tool.driver.name") == "informational"
    assert (
        categorize_field_importance("runs[].results[].properties.tags")
        == "informational"
    )

    # Default case
    assert categorize_field_importance("some.unknown.path") == "informational"
