"""Tests for SARIF suppression processing."""

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
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

    def test_apply_suppressions_to_sarif_with_rule_match(
        self, test_source_dir, test_output_dir
    ):
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
                    AshSuppression(
                        rule_id="RULE-123",
                        path="src/example.py",
                        reason="Test suppression",
                    )
                ]
            },
        )

        plugin_context = PluginContext(
            source_dir=test_source_dir,
            output_dir=test_output_dir,
            config=config,
        )

        # Apply suppressions
        result = apply_suppressions_to_sarif(sarif_report, plugin_context)

        # Check that the first finding is suppressed
        assert result.runs[0].results[0].suppressions is not None
        assert len(result.runs[0].results[0].suppressions) == 1
        assert result.runs[0].results[0].suppressions[0].kind == "inSource"
        assert (
            "Test suppression"
            in result.runs[0].results[0].suppressions[0].justification
        )

        # Check that the second finding is not suppressed
        assert (
            result.runs[0].results[1].suppressions is None
            or len(result.runs[0].results[1].suppressions) == 0
        )

    def test_apply_suppressions_to_sarif_with_file_and_line_match(
        self, test_source_dir, test_output_dir
    ):
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
                    AshSuppression(
                        rule_id="RULE-123",
                        path="src/example.py",
                        line_start=5,
                        line_end=15,
                        reason="Test suppression",
                    )
                ]
            },
        )

        plugin_context = PluginContext(
            source_dir=test_source_dir,
            output_dir=test_output_dir,
            config=config,
        )

        # Apply suppressions
        result = apply_suppressions_to_sarif(sarif_report, plugin_context)

        # Check that the first finding is suppressed
        assert result.runs[0].results[0].suppressions is not None
        assert len(result.runs[0].results[0].suppressions) == 1
        assert result.runs[0].results[0].suppressions[0].kind == "inSource"
        assert (
            "Test suppression"
            in result.runs[0].results[0].suppressions[0].justification
        )

        # Check that the second finding is not suppressed (different line range)
        assert (
            result.runs[0].results[1].suppressions is None
            or len(result.runs[0].results[1].suppressions) == 0
        )

    def test_apply_suppressions_to_sarif_with_ignore_suppressions_flag(
        self, test_source_dir, test_output_dir
    ):
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
                    AshSuppression(
                        rule_id="RULE-123",
                        path="src/example.py",
                        reason="Test suppression",
                    )
                ]
            },
        )

        plugin_context = PluginContext(
            source_dir=test_source_dir,
            output_dir=test_output_dir,
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

    def test_apply_suppressions_to_sarif_with_ignore_paths_and_suppressions(
        self, test_source_dir, test_output_dir
    ):
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
                    AshSuppression(
                        rule_id="RULE-123",
                        path="src/example.py",
                        reason="Test suppression",
                    )
                ],
            },
        )

        plugin_context = PluginContext(
            source_dir=test_source_dir,
            output_dir=test_output_dir,
            config=config,
        )

        # Apply suppressions
        result = apply_suppressions_to_sarif(sarif_report, plugin_context)

        # Check that only one result remains (the second one was removed due to ignore_path)
        assert len(result.runs[0].results) == 1

        # Check that the remaining finding (first one) is suppressed
        assert result.runs[0].results[0].suppressions is not None
        assert len(result.runs[0].results[0].suppressions) == 1
        assert result.runs[0].results[0].suppressions[0].kind == "inSource"
        assert (
            "Test suppression"
            in result.runs[0].results[0].suppressions[0].justification
        )

        # The second finding should be completely removed due to ignore_path
        # (not present in results at all)

    def test_apply_suppressions_with_absolute_uri(
        self, test_source_dir, test_output_dir
    ):
        """Suppression config with relative path must match absolute SARIF URIs."""
        abs_prefix = str(test_source_dir.resolve())
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="semgrep",
                            version="1.0.0",
                        )
                    ),
                    results=[
                        Result(
                            ruleId="run-shell-injection",
                            message=Message(text="Shell injection"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(
                                            uri=f"{abs_prefix}/.github/actions/run-scan-test/action.yml"
                                        ),
                                        region=Region(startLine=77, endLine=77),
                                    )
                                )
                            ],
                        ),
                    ],
                )
            ],
        )
        config = AshConfig(
            project_name="test-project",
            global_settings={
                "suppressions": [
                    AshSuppression(
                        rule_id="run-shell-injection",
                        path=".github/actions/run-scan-test/action.yml",
                        reason="inputs.* are author-defined, not attacker-controlled",
                    )
                ]
            },
        )
        plugin_context = PluginContext(
            source_dir=test_source_dir,
            output_dir=test_output_dir,
            config=config,
        )
        result = apply_suppressions_to_sarif(sarif_report, plugin_context)
        assert result.runs[0].results[0].suppressions is not None
        assert len(result.runs[0].results[0].suppressions) == 1
        assert result.runs[0].results[0].suppressions[0].kind == "inSource"

    def test_apply_suppressions_to_sarif_with_inline_comments_in_real_file(
        self, test_source_dir, test_output_dir
    ):
        """Integration test: inline comments in a real temp file suppress matching SARIF results.

        Verifies the full path from SARIF report (with relative URI) through
        source_dir resolution to inline suppression matching.
        """
        # Write a source file with an inline suppression comment on line 3
        src_subdir = test_source_dir / "app"
        src_subdir.mkdir(parents=True, exist_ok=True)
        source_file = src_subdir / "handler.py"
        source_file.write_text(
            "import os\n"
            "def get_key():\n"
            "    return os.environ['SECRET']  # ash-ignore: SEC-001 env var is safe in Lambda\n"
            "    # unrelated line\n"
        )

        # The SARIF URI is relative (as produced by sanitize_sarif_paths)
        relative_uri = "app/handler.py"

        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="SecretScanner",
                            version="1.0.0",
                        )
                    ),
                    results=[
                        Result(
                            ruleId="SEC-001",
                            message=Message(text="Potential secret in env var access"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(
                                            uri=relative_uri
                                        ),
                                        region=Region(
                                            startLine=3,
                                            endLine=3,
                                        ),
                                    )
                                )
                            ],
                        ),
                        Result(
                            ruleId="SEC-001",
                            message=Message(text="Another finding on different line"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(
                                            uri=relative_uri
                                        ),
                                        region=Region(
                                            startLine=1,
                                            endLine=1,
                                        ),
                                    )
                                )
                            ],
                        ),
                    ],
                )
            ],
        )

        # No config-level suppressions -- only inline should apply
        config = AshConfig(
            project_name="test-inline-integration",
            global_settings={},
        )
        plugin_context = PluginContext(
            source_dir=test_source_dir,
            output_dir=test_output_dir,
            config=config,
        )

        result = apply_suppressions_to_sarif(sarif_report, plugin_context)

        # Line 3 matches the inline comment -- should be suppressed
        suppressed_result = result.runs[0].results[0]
        assert suppressed_result.suppressions is not None
        assert len(suppressed_result.suppressions) == 1
        assert suppressed_result.suppressions[0].kind == "inSource"
        assert "(ASH inline)" in suppressed_result.suppressions[0].justification
        assert "env var is safe in Lambda" in suppressed_result.suppressions[0].justification

        # Line 1 has no inline comment -- should NOT be suppressed
        unsuppressed_result = result.runs[0].results[1]
        assert (
            unsuppressed_result.suppressions is None
            or len(unsuppressed_result.suppressions) == 0
        )
