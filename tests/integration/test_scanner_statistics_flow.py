"""Integration tests for the scanner statistics flow."""

import pytest
import json

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.core.unified_metrics import (
    get_unified_scanner_metrics,
    get_summary_metrics,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Result,
    Message,
    Location,
    PhysicalLocation,
    ArtifactLocation,
    Region,
    PropertyBag,
    Run,
    Tool,
    ToolComponent,
    SarifReport,
)


@pytest.mark.integration
class TestScannerStatisticsFlow:
    """Integration tests for the scanner statistics flow."""

    def create_test_model(self):
        """Create a test model with SARIF data for testing."""
        model = AshAggregatedResults()

        # Set up a config
        from automated_security_helper.config.default_config import get_default_config

        model.ash_config = get_default_config()

        # Create SARIF results with multiple scanners
        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                    results=[
                        # Scanner 1 findings
                        Result(
                            ruleId="RULE1",
                            level="error",
                            message=Message(text="Critical issue"),
                            properties=PropertyBag(scanner_name="scanner1"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation(
                                        artifactLocation=ArtifactLocation(
                                            uri="src/file1.py"
                                        ),
                                        region=Region(startLine=10),
                                    )
                                )
                            ],
                        ),
                        Result(
                            ruleId="RULE2",
                            level="warning",
                            message=Message(text="Medium issue"),
                            properties=PropertyBag(scanner_name="scanner1"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation(
                                        artifactLocation=ArtifactLocation(
                                            uri="src/file2.py"
                                        ),
                                        region=Region(startLine=20),
                                    )
                                )
                            ],
                        ),
                        # Scanner 2 findings
                        Result(
                            ruleId="RULE3",
                            level="error",
                            message=Message(text="Critical issue"),
                            properties=PropertyBag(scanner_name="scanner2"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation(
                                        artifactLocation=ArtifactLocation(
                                            uri="src/file3.py"
                                        ),
                                        region=Region(startLine=30),
                                    )
                                )
                            ],
                            suppressions=[
                                {
                                    "kind": "external",
                                    "justification": "Test suppression",
                                }
                            ],
                        ),
                        Result(
                            ruleId="RULE4",
                            level="note",
                            message=Message(text="Low issue"),
                            properties=PropertyBag(scanner_name="scanner2"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation(
                                        artifactLocation=ArtifactLocation(
                                            uri="src/file4.py"
                                        ),
                                        region=Region(startLine=40),
                                    )
                                )
                            ],
                        ),
                    ],
                )
            ],
        )

        return model

    def test_end_to_end_statistics_flow(self, test_plugin_context):
        """Test the end-to-end flow from SARIF data to displayed statistics."""
        model = self.create_test_model()

        # Step 1: Extract statistics from the SARIF data
        # We need to add scanner entries to scanner_results for the statistics to be extracted
        from automated_security_helper.models.asharp_model import ScannerStatusInfo

        model.scanner_results["scanner1"] = ScannerStatusInfo()
        model.scanner_results["scanner2"] = ScannerStatusInfo()

        scanner_stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)

        # Verify that statistics were extracted correctly
        assert "scanner1" in scanner_stats
        assert "scanner2" in scanner_stats
        assert scanner_stats["scanner1"]["critical"] == 1
        assert scanner_stats["scanner1"]["medium"] == 1
        assert scanner_stats["scanner2"]["suppressed"] == 1
        assert scanner_stats["scanner2"]["low"] == 1

        # Step 2: Generate unified metrics
        metrics = get_unified_scanner_metrics(model)

        # Verify that metrics were generated correctly
        assert len(metrics) == 2
        scanner1_metrics = next(m for m in metrics if m.scanner_name == "scanner1")
        scanner2_metrics = next(m for m in metrics if m.scanner_name == "scanner2")

        assert scanner1_metrics.critical == 1
        assert scanner1_metrics.medium == 1
        assert scanner1_metrics.status == "FAILED"

        assert scanner2_metrics.suppressed == 1
        assert scanner2_metrics.low == 1
        assert (
            scanner2_metrics.status == "PASSED"
        )  # Assuming MEDIUM threshold, only low findings

        # Step 3: Get summary metrics
        summary = get_summary_metrics(model)

        # Verify summary metrics
        assert summary["total_scanners"] == 2
        assert summary["total_findings"] == 3  # 1 critical, 1 medium, 1 low
        assert summary["total_suppressed"] == 1

        # Step 4: Test report content emitter
        emitter = ReportContentEmitter(model)
        scanner_results = emitter.get_scanner_results()

        # Verify that scanner results were generated correctly
        assert len(scanner_results) == 2
        assert any(r["scanner_name"] == "scanner1" for r in scanner_results)
        assert any(r["scanner_name"] == "scanner2" for r in scanner_results)

        # Step 5: Test different reporters for consistency

        # HTML Reporter
        html_reporter = HtmlReporter(context=test_plugin_context)
        html_output = html_reporter.report(model)

        # Verify HTML output contains scanner statistics
        assert "scanner1" in html_output
        assert "scanner2" in html_output
        assert "FAILED" in html_output
        assert "PASSED" in html_output

        # Text Reporter
        text_reporter = TextReporter(context=test_plugin_context)
        text_output = text_reporter.report(model)

        # Verify Text output contains scanner statistics
        assert "scanner1" in text_output
        assert "scanner2" in text_output

        # Markdown Reporter
        markdown_reporter = MarkdownReporter(context=test_plugin_context)
        markdown_output = markdown_reporter.report(model)

        # Verify Markdown output contains scanner statistics
        assert "scanner1" in markdown_output
        assert "scanner2" in markdown_output

        # JSON Reporter
        json_reporter = FlatJSONReporter(context=test_plugin_context)
        json_output = json_reporter.report(model)

        # Verify JSON output contains scanner statistics
        json_data = json.loads(json_output)
        assert "scanner_metrics" in json_data
        assert len(json_data["scanner_metrics"]) == 2

        # Verify consistency across all report formats
        for scanner_name in ["scanner1", "scanner2"]:
            # All formats should include both scanner names
            assert scanner_name in html_output
            assert scanner_name in text_output
            assert scanner_name in markdown_output
            assert any(
                m["scanner_name"] == scanner_name for m in json_data["scanner_metrics"]
            )

    def test_statistics_with_edge_cases(self, test_plugin_context):
        """Test statistics handling with edge cases like excluded scanners and missing dependencies."""
        model = self.create_test_model()

        # Add scanner status info for edge cases
        from automated_security_helper.models.asharp_model import ScannerStatusInfo

        # Add an excluded scanner
        model.scanner_results["excluded_scanner"] = ScannerStatusInfo(excluded=True)

        # Add a scanner with missing dependencies
        model.scanner_results["missing_deps_scanner"] = ScannerStatusInfo(
            dependencies_satisfied=False
        )

        # Generate unified metrics
        metrics = get_unified_scanner_metrics(model)

        # Verify that edge cases are handled correctly
        assert (
            len(metrics) == 2
        )  # Only the 2 edge cases are present since the regular scanners don't have entries in scanner_results

        excluded_metrics = next(
            m for m in metrics if m.scanner_name == "excluded_scanner"
        )
        missing_deps_metrics = next(
            m for m in metrics if m.scanner_name == "missing_deps_scanner"
        )

        assert excluded_metrics.status == "SKIPPED"
        assert excluded_metrics.excluded is True
        assert excluded_metrics.passed is True

        assert missing_deps_metrics.status == "MISSING"
        assert missing_deps_metrics.dependencies_missing is True
        assert missing_deps_metrics.passed is True

        # Test report content emitter with edge cases
        emitter = ReportContentEmitter(model)
        scanner_results = emitter.get_scanner_results()

        # Verify that scanner results include edge cases
        assert len(scanner_results) == 2  # Only the 2 edge cases are present
        assert any(
            r["scanner_name"] == "excluded_scanner" and r["status"] == "SKIPPED"
            for r in scanner_results
        )
        assert any(
            r["scanner_name"] == "missing_deps_scanner" and r["status"] == "MISSING"
            for r in scanner_results
        )

        # Test HTML reporter with edge cases
        html_reporter = HtmlReporter(context=test_plugin_context)
        html_output = html_reporter.report(model)

        # Verify HTML output contains edge cases
        assert "excluded_scanner" in html_output
        assert "missing_deps_scanner" in html_output
        assert "SKIPPED" in html_output
        assert "MISSING" in html_output

        # Test consistency across all report formats with edge cases
        text_reporter = TextReporter(context=test_plugin_context)
        text_output = text_reporter.report(model)

        markdown_reporter = MarkdownReporter(context=test_plugin_context)
        markdown_output = markdown_reporter.report(model)

        json_reporter = FlatJSONReporter(context=test_plugin_context)
        json_output = json_reporter.report(model)
        json_data = json.loads(json_output)

        # Verify that all report formats include the edge cases
        for scanner_name in ["excluded_scanner", "missing_deps_scanner"]:
            assert scanner_name in html_output, (
                f"{scanner_name} not found in HTML output"
            )
            assert scanner_name in text_output, (
                f"{scanner_name} not found in text output"
            )
            assert scanner_name in markdown_output, (
                f"{scanner_name} not found in markdown output"
            )
            assert any(
                m["scanner_name"] == scanner_name for m in json_data["scanner_metrics"]
            ), f"{scanner_name} not found in JSON output"
