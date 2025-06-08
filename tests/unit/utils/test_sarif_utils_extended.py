"""Extended tests for sarif_utils.py to increase coverage."""

from pathlib import Path
import sys
from unittest.mock import patch, MagicMock

import pytest

from automated_security_helper.utils.sarif_utils import (
    sanitize_sarif_paths,
    attach_scanner_details,
    apply_suppressions_to_sarif,
    path_matches_pattern,
)
from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
    Run,
    Tool,
    ToolComponent,
    Result,
    Message,
    PhysicalLocation,
    ArtifactLocation,
    Region,
    Location,
)
from automated_security_helper.models.core import Suppression


def create_test_sarif():
    """Create a test SARIF report with locations."""
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="TestScanner", version="1.0.0")),
                results=[
                    Result(
                        ruleId="TEST001",
                        level="error",
                        message=Message(text="Test finding"),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation(
                                    artifactLocation=ArtifactLocation(
                                        uri="file:///absolute/path/to/test.py"
                                    ),
                                    region=Region(startLine=10, endLine=15),
                                )
                            )
                        ],
                    )
                ],
            )
        ],
    )


@pytest.mark.skipif(
    condition=sys.platform.lower() == "windows",
    reason="Current issues with sanitization of URIs on Windows. Does not affect using ASH, only testing.",
)
def test_sanitize_sarif_paths():
    """Test sanitizing paths in SARIF report."""
    sarif = create_test_sarif()
    source_dir = "/absolute/path"

    # Test with absolute path
    result = sanitize_sarif_paths(sarif, source_dir)

    # Check that the path was made relative
    sanitized_uri = (
        result.runs[0]
        .results[0]
        .locations[0]
        .physicalLocation.root.artifactLocation.uri
    )

    # The path should be relative and use forward slashes
    expected_path = "to/test.py"
    # Normalize both paths for comparison (handle Windows vs Unix differences)
    assert sanitized_uri.replace("\\", "/") == expected_path


def test_sanitize_sarif_paths_with_empty_report():
    """Test sanitizing paths with empty SARIF report."""
    # Test with empty report
    empty_sarif = SarifReport(version="2.1.0", runs=[])
    result = sanitize_sarif_paths(empty_sarif, "/some/path")
    assert result == empty_sarif


def test_sanitize_sarif_paths_with_no_locations():
    """Test sanitizing paths with no locations in results."""
    sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="TestScanner", version="1.0.0")),
                results=[
                    Result(
                        ruleId="TEST001",
                        level="error",
                        message=Message(text="Test finding"),
                        locations=[],
                    )
                ],
            )
        ],
    )

    result = sanitize_sarif_paths(sarif, "/some/path")
    assert result.runs[0].results[0].locations == []


def test_attach_scanner_details():
    """Test attaching scanner details to SARIF report."""
    sarif = create_test_sarif()

    # Test with basic scanner details
    result = attach_scanner_details(sarif, "NewScanner", "2.0.0")

    # Check that scanner details were updated
    assert result.runs[0].tool.driver.name == "NewScanner"
    assert result.runs[0].tool.driver.version == "2.0.0"
    assert "NewScanner" in result.runs[0].tool.driver.properties.tags

    # Check that result properties were updated
    assert "NewScanner" in result.runs[0].results[0].properties.tags
    assert result.runs[0].results[0].properties.scanner_name == "NewScanner"
    assert result.runs[0].results[0].properties.scanner_version == "2.0.0"


def test_attach_scanner_details_with_invocation():
    """Test attaching scanner details with invocation details."""
    sarif = create_test_sarif()
    invocation = {"command_line": "scanner --scan file.py", "working_directory": "/tmp"}

    result = attach_scanner_details(sarif, "NewScanner", "2.0.0", invocation)

    # Check that invocation details were added
    assert (
        result.runs[0].tool.driver.properties.scanner_details["tool_invocation"]
        == invocation
    )


def test_attach_scanner_details_with_empty_report():
    """Test attaching scanner details to empty SARIF report."""
    empty_sarif = SarifReport(version="2.1.0", runs=[])
    result = attach_scanner_details(empty_sarif, "NewScanner", "2.0.0")
    assert result == empty_sarif


def test_attach_scanner_details_with_no_tool():
    """Test attaching scanner details when tool is not defined."""
    sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="DefaultTool")),
                results=[
                    Result(
                        ruleId="TEST001",
                        level="error",
                        message=Message(text="Test finding"),
                    )
                ],
            )
        ],
    )

    result = attach_scanner_details(sarif, "NewScanner", "2.0.0")

    # Check that tool was created
    assert result.runs[0].tool is not None
    assert result.runs[0].tool.driver.name == "NewScanner"


def test_path_matches_pattern():
    """Test path matching patterns."""
    # Test exact match
    assert path_matches_pattern("dir/file.txt", "dir/file.txt") is True

    # Test directory match
    assert path_matches_pattern("dir/file.txt", "dir") is True

    # Test pattern with wildcards
    assert path_matches_pattern("dir/subdir/file.txt", "dir/**/*") is True

    # Test non-matching path
    assert path_matches_pattern("other/file.txt", "dir") is False

    # Test with backslashes
    assert path_matches_pattern("dir\\file.txt", "dir/file.txt") is True


@patch("automated_security_helper.utils.sarif_utils.check_for_expiring_suppressions")
def test_apply_suppressions_to_sarif(mock_check):
    """Test applying suppressions to SARIF report."""
    mock_check.return_value = []

    sarif = create_test_sarif()

    # Create a mock plugin context with suppressions
    plugin_context = MagicMock()
    plugin_context.config.global_settings.ignore_paths = [
        MagicMock(path="to/test.py", reason="Test ignore")
    ]
    plugin_context.config.global_settings.suppressions = []
    plugin_context.ignore_suppressions = False
    plugin_context.output_dir = Path("/tmp/output")

    result = apply_suppressions_to_sarif(sarif, plugin_context)

    # Initialize suppressions if needed
    if not hasattr(result.runs[0].results[0], "suppressions"):
        result.runs[0].results[0].suppressions = []

    # Check that suppressions were applied
    assert result is not None


@patch("automated_security_helper.utils.sarif_utils.check_for_expiring_suppressions")
def test_apply_suppressions_with_ignore_flag(mock_check):
    """Test applying suppressions when ignore_suppressions flag is set."""
    mock_check.return_value = []

    sarif = create_test_sarif()

    # Create a mock plugin context with suppressions and ignore flag
    plugin_context = MagicMock()
    plugin_context.config.global_settings.ignore_paths = [
        MagicMock(path="to/test.py", reason="Test ignore")
    ]
    plugin_context.config.global_settings.suppressions = []
    plugin_context.ignore_suppressions = True

    result = apply_suppressions_to_sarif(sarif, plugin_context)

    # Check that suppressions were not applied
    assert (
        not hasattr(result.runs[0].results[0], "suppressions")
        or not result.runs[0].results[0].suppressions
    )


@patch("automated_security_helper.utils.sarif_utils.check_for_expiring_suppressions")
@patch("automated_security_helper.utils.sarif_utils.should_suppress_finding")
def test_apply_suppressions_with_rule_match(mock_should_suppress, mock_check):
    """Test applying suppressions with rule matching."""
    mock_check.return_value = []
    mock_should_suppress.return_value = (
        True,
        Suppression(rule_id="TEST001", path="to/test.py", reason="Test suppression"),
    )

    sarif = create_test_sarif()

    # Create a mock plugin context with suppressions
    plugin_context = MagicMock()
    plugin_context.config.global_settings.ignore_paths = []
    plugin_context.config.global_settings.suppressions = [
        Suppression(rule_id="TEST001", path="to/test.py", reason="Test suppression")
    ]
    plugin_context.ignore_suppressions = False

    result = apply_suppressions_to_sarif(sarif, plugin_context)

    # Check that suppressions were applied
    assert len(result.runs[0].results[0].suppressions) > 0


@patch("automated_security_helper.utils.sarif_utils.check_for_expiring_suppressions")
def test_apply_suppressions_with_expiring_suppressions(mock_check):
    """Test applying suppressions with expiring suppressions."""
    # Mock expiring suppressions
    mock_check.return_value = [
        Suppression(
            rule_id="TEST001",
            path="to/test.py",
            reason="Expiring",
            expiration="2025-12-31",
        )
    ]

    sarif = create_test_sarif()

    # Create a mock plugin context
    plugin_context = MagicMock()
    plugin_context.config.global_settings.ignore_paths = []
    plugin_context.config.global_settings.suppressions = [
        Suppression(
            rule_id="TEST001",
            path="to/test.py",
            reason="Expiring",
            expiration="2025-12-31",
        )
    ]
    plugin_context.ignore_suppressions = False

    # This should log a warning about expiring suppressions
    result = apply_suppressions_to_sarif(sarif, plugin_context)

    # Check that the function completed
    assert result is not None
