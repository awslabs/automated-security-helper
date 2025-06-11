from automated_security_helper.utils.meta_analysis.get_reporter_mappings import (
    get_reporter_mappings,
)


def test_get_reporter_mappings():
    """Test getting reporter mappings."""
    mappings = get_reporter_mappings()

    # Check that the function returns a dictionary
    assert isinstance(mappings, dict)

    # Check that the dictionary contains expected keys
    assert "asff" in mappings
    assert "ocsf" in mappings
    assert "csv" in mappings
    assert "flat-json" in mappings

    # Check that the mappings contain expected fields
    asff_mapping = mappings["asff"]
    assert "runs[].results[].ruleId" in asff_mapping
    assert "runs[].results[].message.text" in asff_mapping
    assert "runs[].results[].level" in asff_mapping
