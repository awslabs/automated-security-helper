"""Tests for SARIF suppression processing."""

from pathlib import Path

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import Suppression, IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
    Run,
    Tool,
    ToolComponent,
    Result,
    Message,
    Location,
    PhysicalLocation2,
    ArtifactLocation,
    Region,
)
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif


class TestSarifSuppressions:
    """Tests for SARIF suppression processing."""

    def test_apply_suppressions_to_sarif_with_rule_match(self):
        """Test applying suppressions to SARIF report with rule ID match."""
        # Create a test SARIF report
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="Test Scanner",
                            version="1.0.0",
                        )
                    ),
                    results=[
                        Result(
                            ruleId="RULE-123",
                            message=Message(text="Test finding"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(
                                            uri="src/example.py"
                                        ),
                                        region=Region(
                                            startLine=10,
                                            endLine=15,
                                        ),
                                    )
                                )
                            ],
                        ),
                        Result(
                            ruleId="RULE-456",
                            message=Message(text="Another test finding"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(
                                            uri="src/other.py"
                                        ),
                                        region=Region(
                                            startLine=20,
                                            endLine=25,
                                        ),
                                    )
                                )
                            ],
                        ),
                    ],
                )
            ],
        )

        # Create a test plugin context with suppressions
        config = AshConfig(
            project_name="test-project",
            global_settings={
                "suppressions": [
                    Suppression(
                        rule_id="RULE-123",
                        file_path="src/example.py",
                        reason="Test suppression",
                    )
                ]
            },
        )

        plugin_context = PluginContext(
            source_dir=Path("/tmp/source"),
            output_dir=Path("/tmp/output"),
            config=config,
        )

        # Apply suppressions
        result = apply_suppressions_to_sarif(sarif_report, plugin_context)

        # Check that the first finding is suppressed
        assert result.runs[0].results[0].suppressions is not None
        assert len(result.runs[0].results[0].suppressions) == 1
        assert result.runs[0].results[0].suppressions[0].kind == "external"
        assert (
            "Test suppression"
            in result.runs[0].results[0].suppressions[0].justification
        )

        # Check that the second finding is not suppressed
        assert (
            result.runs[0].results[1].suppressions is None
            or len(result.runs[0].results[1].suppressions) == 0
        )

    def test_apply_suppressions_to_sarif_with_file_and_line_match(self):
        """Test applying suppressions to SARIF report with file path and line match."""
        # Create a test SARIF report
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="Test Scanner",
                            version="1.0.0",
                        )
                    ),
                    results=[
                        Result(
                            ruleId="RULE-123",
                            message=Message(text="Test finding"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(
                                            uri="src/example.py"
                                        ),
                                        region=Region(
                                            startLine=10,
                                            endLine=15,
                                        ),
                                    )
                                )
                            ],
                        ),
                        Result(
                            ruleId="RULE-123",
                            message=Message(text="Another test finding"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(
                                            uri="src/example.py"
                                        ),
                                        region=Region(
                                            startLine=20,
                                            endLine=25,
                                        ),
                                    )
                                )
                            ],
                        ),
                    ],
                )
            ],
        )

        # Create a test plugin context with suppressions
        config = AshConfig(
            project_name="test-project",
            global_settings={
                "suppressions": [
                    Suppression(
                        rule_id="RULE-123",
                        file_path="src/example.py",
                        line_start=5,
                        line_end=15,
                        reason="Test suppression",
                    )
                ]
            },
        )

        plugin_context = PluginContext(
            source_dir=Path("/tmp/source"),
            output_dir=Path("/tmp/output"),
            config=config,
        )

        # Apply suppressions
        result = apply_suppressions_to_sarif(sarif_report, plugin_context)

        # Check that the first finding is suppressed
        assert result.runs[0].results[0].suppressions is not None
        assert len(result.runs[0].results[0].suppressions) == 1
        assert result.runs[0].results[0].suppressions[0].kind == "external"
        assert (
            "Test suppression"
            in result.runs[0].results[0].suppressions[0].justification
        )

        # Check that the second finding is not suppressed (different line range)
        assert (
            result.runs[0].results[1].suppressions is None
            or len(result.runs[0].results[1].suppressions) == 0
        )

    def test_apply_suppressions_to_sarif_with_ignore_suppressions_flag(self):
        """Test applying suppressions to SARIF report with ignore_suppressions flag."""
        # Create a test SARIF report
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="Test Scanner",
                            version="1.0.0",
                        )
                    ),
                    results=[
                        Result(
                            ruleId="RULE-123",
                            message=Message(text="Test finding"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(
                                            uri="src/example.py"
                                        ),
                                        region=Region(
                                            startLine=10,
                                            endLine=15,
                                        ),
                                    )
                                )
                            ],
                        ),
                    ],
                )
            ],
        )

        # Create a test plugin context with suppressions and ignore_suppressions flag
        config = AshConfig(
            project_name="test-project",
            global_settings={
                "suppressions": [
                    Suppression(
                        rule_id="RULE-123",
                        file_path="src/example.py",
                        reason="Test suppression",
                    )
                ]
            },
        )

        plugin_context = PluginContext(
            source_dir=Path("/tmp/source"),
            output_dir=Path("/tmp/output"),
            config=config,
            ignore_suppressions=True,
        )

        # Apply suppressions
        result = apply_suppressions_to_sarif(sarif_report, plugin_context)

        # Check that the finding is not suppressed due to ignore_suppressions flag
        assert (
            result.runs[0].results[0].suppressions is None
            or len(result.runs[0].results[0].suppressions) == 0
        )

    def test_apply_suppressions_to_sarif_with_ignore_paths_and_suppressions(self):
        """Test applying both ignore_paths and suppressions to SARIF report."""
        # Create a test SARIF report
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="Test Scanner",
                            version="1.0.0",
                        )
                    ),
                    results=[
                        Result(
                            ruleId="RULE-123",
                            message=Message(text="Test finding"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(
                                            uri="src/example.py"
                                        ),
                                        region=Region(
                                            startLine=10,
                                            endLine=15,
                                        ),
                                    )
                                )
                            ],
                        ),
                        Result(
                            ruleId="RULE-456",
                            message=Message(text="Another test finding"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(
                                            uri="src/ignored.py"
                                        ),
                                        region=Region(
                                            startLine=20,
                                            endLine=25,
                                        ),
                                    )
                                )
                            ],
                        ),
                    ],
                )
            ],
        )

        # Create a test plugin context with both ignore_paths and suppressions
        config = AshConfig(
            project_name="test-project",
            global_settings={
                "ignore_paths": [
                    IgnorePathWithReason(
                        path="src/ignored.py",
                        reason="Test ignore path",
                    )
                ],
                "suppressions": [
                    Suppression(
                        rule_id="RULE-123",
                        file_path="src/example.py",
                        reason="Test suppression",
                    )
                ],
            },
        )

        plugin_context = PluginContext(
            source_dir=Path("/tmp/source"),
            output_dir=Path("/tmp/output"),
            config=config,
        )

        # Apply suppressions
        result = apply_suppressions_to_sarif(sarif_report, plugin_context)

        # Check that the first finding is suppressed
        assert result.runs[0].results[0].suppressions is not None
        assert len(result.runs[0].results[0].suppressions) == 1
        assert result.runs[0].results[0].suppressions[0].kind == "external"
        assert (
            "Test suppression"
            in result.runs[0].results[0].suppressions[0].justification
        )

        # Check that the second finding is suppressed due to ignore_path
        assert result.runs[0].results[1].suppressions is not None
        assert len(result.runs[0].results[1].suppressions) == 1
        assert result.runs[0].results[1].suppressions[0].kind == "external"
        assert (
            "Test ignore path"
            in result.runs[0].results[1].suppressions[0].justification
        )
