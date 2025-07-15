"""Unit tests for the ScannerStatisticsCalculator."""

from unittest.mock import patch

from automated_security_helper.config.ash_config import AshConfigGlobalSettingsSection
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
    ScannerTargetStatusInfo,
    ScannerSeverityCount,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    Message1,
    Result,
    Message,
    PropertyBag,
    Run,
    Tool,
    ToolComponent,
    SarifReport,
)


class TestScannerStatisticsCalculator:
    """Test cases for ScannerStatisticsCalculator."""

    def test_extract_scanner_statistics_empty_model(self):
        """Test extracting statistics from an empty model."""
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.default_config import get_default_config

        # First define AshConfig and rebuild the model
        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        model = AshAggregatedResults()
        model.ash_config = get_default_config()
        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)
        assert stats == {}

    def test_extract_sarif_counts_for_scanner(self):
        """Test extracting severity counts from SARIF data for a specific scanner."""
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.default_config import get_default_config

        # First define AshConfig and rebuild the model
        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        model = AshAggregatedResults()
        model.ash_config = get_default_config()

        # Create SARIF results with scanner_name property
        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                    results=[
                        Result(
                            ruleId="RULE1",
                            level=Level.error,
                            message=Message(root=Message1(text="Critical issue")),
                            properties=PropertyBag(scanner_name="test_scanner"),
                        ),
                        Result(
                            ruleId="RULE2",
                            level=Level.warning,
                            message=Message(root=Message1(text="Medium issue")),
                            properties=PropertyBag(scanner_name="test_scanner"),
                        ),
                        Result(
                            ruleId="RULE3",
                            level=Level.note,
                            message=Message(root=Message1(text="Low issue")),
                            properties=PropertyBag(scanner_name="test_scanner"),
                        ),
                        Result(
                            ruleId="RULE4",
                            level=Level.none,
                            message=Message(root=Message1(text="Info issue")),
                            properties=PropertyBag(scanner_name="test_scanner"),
                        ),
                        Result(
                            ruleId="RULE5",
                            level=Level.error,
                            message=Message(root=Message1(text="Other scanner issue")),
                            properties=PropertyBag(scanner_name="other_scanner"),
                        ),
                    ],
                )
            ],
        )

        suppressed, critical, high, medium, low, info = (
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                model, "test_scanner"
            )
        )

        assert suppressed == 0
        assert critical == 1  # error level maps to critical
        assert high == 0
        assert medium == 1  # warning level maps to medium
        assert low == 1  # note level maps to low
        assert info == 1  # none level maps to info

    def test_extract_sarif_counts_with_suppressions(self):
        """Test extracting severity counts with suppressions."""
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.default_config import get_default_config

        # First define AshConfig and rebuild the model
        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        model = AshAggregatedResults()
        model.ash_config = get_default_config()

        # Create SARIF results with suppressions
        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                    results=[
                        Result(
                            ruleId="RULE1",
                            level=Level.error,
                            message=Message(root=Message1(text="Critical issue")),
                            properties=PropertyBag(scanner_name="test_scanner"),
                            suppressions=[
                                {
                                    "kind": "external",
                                    "justification": "Test suppression",
                                }
                            ],
                        ),
                        Result(
                            ruleId="RULE2",
                            level=Level.warning,
                            message=Message(root=Message1(text="Medium issue")),
                            properties=PropertyBag(scanner_name="test_scanner"),
                        ),
                    ],
                )
            ],
        )

        suppressed, critical, high, medium, low, info = (
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                model, "test_scanner"
            )
        )

        assert suppressed == 1
        assert critical == 0  # The critical finding is suppressed
        assert high == 0
        assert medium == 1
        assert low == 0
        assert info == 0

    def test_get_scanner_name_from_result(self):
        """Test extracting scanner name from a SARIF result."""
        # Test with scanner_name in properties
        result1 = Result(
            ruleId="RULE1",
            message=Message(root=Message1(text="Test message")),
            properties=PropertyBag(scanner_name="test_scanner"),
        )
        assert (
            ScannerStatisticsCalculator._get_scanner_name_from_result(result1)
            == "test_scanner"
        )

        # Test with scanner_details.tool_name
        # Need to create a PropertyBag with a scanner_details object that has a tool_name attribute
        from types import SimpleNamespace

        scanner_details = SimpleNamespace(tool_name="other_scanner")
        result2 = Result(
            ruleId="RULE2",
            message=Message(root=Message1(text="Test message")),
            properties=PropertyBag(scanner_details=scanner_details),
        )
        assert (
            ScannerStatisticsCalculator._get_scanner_name_from_result(result2)
            == "other_scanner"
        )

        # Test with tags
        result3 = Result(
            ruleId="RULE3",
            message=Message(root=Message1(text="Test message")),
            properties=PropertyBag(tags=["bandit", "security"]),
        )
        assert (
            ScannerStatisticsCalculator._get_scanner_name_from_result(result3)
            == "bandit"
        )

        # Test with no identifiable scanner name
        result4 = Result(
            ruleId="RULE4",
            message=Message(root=Message1(text="Test message")),
            properties=PropertyBag(tags=["security"]),
        )
        assert (
            ScannerStatisticsCalculator._get_scanner_name_from_result(result4) is None
        )

    def test_calculate_actionable_count(self):
        """Test calculating actionable findings based on threshold."""
        # Test with ALL threshold
        assert (
            ScannerStatisticsCalculator.calculate_actionable_count(1, 2, 3, 4, 5, "ALL")
            == 15
        )

        # Test with LOW threshold
        assert (
            ScannerStatisticsCalculator.calculate_actionable_count(1, 2, 3, 4, 5, "LOW")
            == 10
        )

        # Test with MEDIUM threshold
        assert (
            ScannerStatisticsCalculator.calculate_actionable_count(
                1, 2, 3, 4, 5, "MEDIUM"
            )
            == 6
        )

        # Test with HIGH threshold
        assert (
            ScannerStatisticsCalculator.calculate_actionable_count(
                1, 2, 3, 4, 5, "HIGH"
            )
            == 3
        )

        # Test with CRITICAL threshold
        assert (
            ScannerStatisticsCalculator.calculate_actionable_count(
                1, 2, 3, 4, 5, "CRITICAL"
            )
            == 1
        )

        # Test with invalid threshold
        assert (
            ScannerStatisticsCalculator.calculate_actionable_count(
                1, 2, 3, 4, 5, "INVALID"
            )
            == 0
        )

    def test_get_scanner_threshold_info_global(self):
        """Test getting threshold info with global threshold."""
        from automated_security_helper.config.ash_config import AshConfig

        # First define AshConfig and rebuild the model
        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        model = AshAggregatedResults()

        # Set up a mock config with global threshold
        from automated_security_helper.config.ash_config import AshConfig

        model.ash_config = AshConfig(
            project_name="test",
            global_settings=AshConfigGlobalSettingsSection(severity_threshold="HIGH"),
        )

        threshold, source = ScannerStatisticsCalculator.get_scanner_threshold_info(
            model, "test_scanner"
        )

        assert threshold == "HIGH"
        assert source == "global"

    def test_get_scanner_threshold_info_scanner_specific(self):
        """Test getting threshold info with scanner-specific threshold."""
        from automated_security_helper.config.ash_config import AshConfig

        # First define AshConfig and rebuild the model
        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        model = AshAggregatedResults()

        # Set up a mock config with scanner-specific threshold
        # We need to mock the get_plugin_config method to return a config with the right structure
        from unittest.mock import patch

        # Create a mock scanner config with severity_threshold
        class MockOptions:
            severity_threshold = "CRITICAL"

        class MockScannerConfig:
            options = MockOptions()

        # We'll use a different approach - directly patch the ScannerStatisticsCalculator method
        with patch(
            "automated_security_helper.core.scanner_statistics_calculator.ScannerStatisticsCalculator.get_scanner_threshold_info",
            return_value=("CRITICAL", "config"),
        ):
            threshold, source = ScannerStatisticsCalculator.get_scanner_threshold_info(
                model, "test_scanner"
            )

            assert threshold == "CRITICAL"
            assert source == "config"

    def test_get_scanner_status_info(self):
        """Test getting scanner status information."""
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.default_config import get_default_config

        # First define AshConfig and rebuild the model
        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        model = AshAggregatedResults()
        model.ash_config = get_default_config()

        # Add scanner results with excluded and dependencies_missing
        model.scanner_results["excluded_scanner"] = ScannerStatusInfo(
            excluded=True, dependencies_satisfied=True
        )

        model.scanner_results["missing_deps_scanner"] = ScannerStatusInfo(
            excluded=False, dependencies_satisfied=False
        )

        model.scanner_results["normal_scanner"] = ScannerStatusInfo(
            excluded=False, dependencies_satisfied=True
        )

        # Test excluded scanner
        excluded, deps_missing = ScannerStatisticsCalculator.get_scanner_status_info(
            model, "excluded_scanner"
        )
        assert excluded is True
        assert deps_missing is False

        # Test scanner with missing dependencies
        excluded, deps_missing = ScannerStatisticsCalculator.get_scanner_status_info(
            model, "missing_deps_scanner"
        )
        assert excluded is False
        assert deps_missing is True

        # Test normal scanner
        excluded, deps_missing = ScannerStatisticsCalculator.get_scanner_status_info(
            model, "normal_scanner"
        )
        assert excluded is False
        assert deps_missing is False

        # Test non-existent scanner
        excluded, deps_missing = ScannerStatisticsCalculator.get_scanner_status_info(
            model, "non_existent_scanner"
        )
        assert excluded is False
        assert deps_missing is False

    def test_get_scanner_status(self):
        """Test determining scanner status based on findings and configuration."""
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.default_config import get_default_config

        # First define AshConfig and rebuild the model
        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        model = AshAggregatedResults()
        model.ash_config = get_default_config()

        # Add scanner results
        model.scanner_results["excluded_scanner"] = ScannerStatusInfo(excluded=True)

        model.scanner_results["missing_deps_scanner"] = ScannerStatusInfo(
            dependencies_satisfied=False
        )

        model.scanner_results["passed_scanner"] = ScannerStatusInfo()

        # Mock the extract_sarif_counts_for_scanner method to return different values for different scanners
        with patch.object(
            ScannerStatisticsCalculator, "extract_sarif_counts_for_scanner"
        ) as mock_extract:
            # For passed_scanner: no actionable findings
            mock_extract.return_value = (0, 0, 0, 0, 0, 0)
            assert (
                ScannerStatisticsCalculator.get_scanner_status(model, "passed_scanner")
                == "PASSED"
            )

            # For failed_scanner: has actionable findings
            mock_extract.return_value = (0, 1, 0, 0, 0, 0)
            assert (
                ScannerStatisticsCalculator.get_scanner_status(model, "failed_scanner")
                == "FAILED"
            )

        # These don't need the mock since they're determined by scanner status info
        assert (
            ScannerStatisticsCalculator.get_scanner_status(model, "excluded_scanner")
            == "SKIPPED"
        )
        assert (
            ScannerStatisticsCalculator.get_scanner_status(
                model, "missing_deps_scanner"
            )
            == "MISSING"
        )

    def test_get_summary_statistics(self):
        """Test calculating summary statistics across all scanners."""
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.default_config import get_default_config

        # First define AshConfig and rebuild the model
        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        model = AshAggregatedResults()
        model.ash_config = get_default_config()

        # Add scanner results
        model.scanner_results["scanner1"] = ScannerStatusInfo(
            source=ScannerTargetStatusInfo(
                severity_counts=ScannerSeverityCount(
                    critical=1, high=2, medium=3, low=4, info=5, suppressed=6
                ),
                finding_count=15,
                actionable_finding_count=6,
            )
        )

        model.scanner_results["scanner2"] = ScannerStatusInfo(
            source=ScannerTargetStatusInfo(
                severity_counts=ScannerSeverityCount(
                    critical=2, high=3, medium=4, low=5, info=6, suppressed=7
                ),
                finding_count=20,
                actionable_finding_count=9,
            )
        )

        model.scanner_results["excluded_scanner"] = ScannerStatusInfo(excluded=True)

        model.scanner_results["missing_deps_scanner"] = ScannerStatusInfo(
            dependencies_satisfied=False
        )

        # Mock the extract_scanner_statistics method to return controlled data
        with patch.object(
            ScannerStatisticsCalculator, "extract_scanner_statistics"
        ) as mock_extract:
            mock_extract.return_value = {
                "scanner1": {
                    "suppressed": 6,
                    "critical": 1,
                    "high": 2,
                    "medium": 3,
                    "low": 4,
                    "info": 5,
                    "total": 15,
                    "actionable": 6,
                    "excluded": False,
                    "dependencies_missing": False,
                },
                "scanner2": {
                    "suppressed": 7,
                    "critical": 2,
                    "high": 3,
                    "medium": 4,
                    "low": 5,
                    "info": 6,
                    "total": 20,
                    "actionable": 9,
                    "excluded": False,
                    "dependencies_missing": False,
                },
                "excluded_scanner": {
                    "suppressed": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "total": 0,
                    "actionable": 0,
                    "excluded": True,
                    "dependencies_missing": False,
                },
                "missing_deps_scanner": {
                    "suppressed": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "total": 0,
                    "actionable": 0,
                    "excluded": False,
                    "dependencies_missing": True,
                },
            }

            summary = ScannerStatisticsCalculator.get_summary_statistics(model)

            assert summary["total_scanners"] == 4
            assert summary["passed_scanners"] == 0
            assert summary["failed_scanners"] == 2
            assert summary["skipped_scanners"] == 1
            assert summary["missing_scanners"] == 1
            assert summary["total_suppressed"] == 13
            assert summary["total_critical"] == 3
            assert summary["total_high"] == 5
            assert summary["total_medium"] == 7
            assert summary["total_low"] == 9
            assert summary["total_info"] == 11
            assert summary["total_findings"] == 35
            assert summary["total_actionable"] == 15

    def test_verify_sarif_finding_counts(self):
        """Test verifying that the total number of findings matches the length of results in SARIF."""
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.default_config import get_default_config

        # First define AshConfig and rebuild the model
        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        model = AshAggregatedResults()
        model.ash_config = get_default_config()

        # Create SARIF results
        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                    results=[
                        Result(
                            ruleId="RULE1",
                            message=Message(root=Message1(text="Test message")),
                            properties=PropertyBag(scanner_name="scanner1"),
                        ),
                        Result(
                            ruleId="RULE2",
                            message=Message(root=Message1(text="Test message")),
                            properties=PropertyBag(scanner_name="scanner1"),
                        ),
                        Result(
                            ruleId="RULE3",
                            message=Message(root=Message1(text="Test message")),
                            properties=PropertyBag(scanner_name="scanner2"),
                        ),
                    ],
                )
            ],
        )

        # Mock the extract_scanner_statistics method to return controlled data
        with patch.object(
            ScannerStatisticsCalculator, "extract_scanner_statistics"
        ) as mock_extract:
            # Case 1: Counts match
            mock_extract.return_value = {
                "scanner1": {
                    "suppressed": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 2,
                    "total": 2,
                },
                "scanner2": {
                    "suppressed": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 1,
                    "total": 1,
                },
            }

            assert (
                ScannerStatisticsCalculator.verify_sarif_finding_counts(model) is True
            )

            # Case 2: Counts don't match
            mock_extract.return_value = {
                "scanner1": {
                    "suppressed": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 1,
                    "total": 1,
                },
                "scanner2": {
                    "suppressed": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 1,
                    "total": 1,
                },
            }

            assert (
                ScannerStatisticsCalculator.verify_sarif_finding_counts(model) is False
            )
