from automated_security_helper.utils.meta_analysis.merge_field_paths import (
    merge_field_paths,
)


def test_merge_field_paths():
    """Test merging field paths from multiple sources."""
    # Setup test data
    paths1 = {
        "version": {"type": {"str"}, "scanners": {"scanner1"}},
        "runs[0].tool.driver.name": {"type": {"str"}, "scanners": {"scanner1"}},
    }

    paths2 = {
        "version": {"type": {"str"}, "scanners": {"scanner2"}},
        "runs[0].results[0].ruleId": {"type": {"str"}, "scanners": {"scanner2"}},
    }

    paths3 = {
        "runs[0].tool.driver.version": {"type": {"str"}, "scanners": {"scanner3"}}
    }

    # Test function
    merged = merge_field_paths([paths1, paths2, paths3])

    # Verify results
    assert "version" in merged
    assert "runs[0].tool.driver.name" in merged
    assert "runs[0].results[0].ruleId" in merged
    assert "runs[0].tool.driver.version" in merged

    # Check that types and scanners were merged
    assert merged["version"]["type"] == {"str"}
    assert merged["version"]["scanners"] == {"scanner1", "scanner2"}

    assert merged["runs[0].tool.driver.name"]["scanners"] == {"scanner1"}
    assert merged["runs[0].results[0].ruleId"]["scanners"] == {"scanner2"}
    assert merged["runs[0].tool.driver.version"]["scanners"] == {"scanner3"}
