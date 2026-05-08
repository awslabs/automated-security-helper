"""Tests for ScanResultsContainer factory methods and determine_status(),
plus idempotency regression test for AshAggregatedResults.to_flat_vulnerabilities().
"""

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.scan_results_container import ScanResultsContainer


class TestScanResultsContainerFactories:
    """Factory classmethod coverage for ScanResultsContainer."""

    def test_for_excluded_sets_skipped_and_excluded(self):
        container = ScanResultsContainer.for_excluded("bandit")
        assert container.scanner_name == "bandit"
        assert container.status == ScannerStatus.SKIPPED
        assert container.excluded is True

    def test_for_missing_deps_sets_missing_and_unsatisfied(self):
        container = ScanResultsContainer.for_missing_deps("semgrep")
        assert container.scanner_name == "semgrep"
        assert container.status == ScannerStatus.MISSING
        assert container.dependencies_satisfied is False

    def test_for_failure_without_errors(self):
        container = ScanResultsContainer.for_failure("checkov")
        assert container.scanner_name == "checkov"
        assert container.status == ScannerStatus.FAILED

    def test_for_failure_stores_errors(self):
        errors = ["boom", "kaboom"]
        container = ScanResultsContainer.for_failure("checkov", errors=errors)
        assert container.status == ScannerStatus.FAILED
        for err in errors:
            assert err in container.errors

    def test_for_failure_stores_exception(self):
        exc = RuntimeError("explode")
        container = ScanResultsContainer.for_failure("checkov", exception=exc)
        assert container.status == ScannerStatus.FAILED
        assert container.exception is not None
        assert "explode" in container.exception


class TestDetermineStatus:
    """Coverage for ScanResultsContainer.determine_status(threshold)."""

    def _container(self, **counts) -> ScanResultsContainer:
        c = ScanResultsContainer(scanner_name="test")
        for key, value in counts.items():
            c.severity_counts[key] = value
        return c

    def test_critical_over_critical_threshold_is_failed(self):
        c = self._container(critical=1)
        assert c.determine_status("CRITICAL") == ScannerStatus.FAILED

    def test_high_over_high_threshold_is_failed(self):
        c = self._container(high=2)
        assert c.determine_status("HIGH") == ScannerStatus.FAILED

    def test_high_below_critical_threshold_is_passed(self):
        # high=3 but threshold is only critical → PASSED
        c = self._container(high=3)
        assert c.determine_status("CRITICAL") == ScannerStatus.PASSED

    def test_all_zero_is_passed(self):
        c = self._container()
        assert c.determine_status("HIGH") == ScannerStatus.PASSED

    def test_medium_over_medium_threshold_is_failed(self):
        c = self._container(medium=5)
        assert c.determine_status("MEDIUM") == ScannerStatus.FAILED

    def test_medium_below_high_threshold_is_passed(self):
        c = self._container(medium=5)
        assert c.determine_status("HIGH") == ScannerStatus.PASSED

    def test_info_only_counted_at_all_threshold(self):
        c = self._container(info=1)
        assert c.determine_status("ALL") == ScannerStatus.FAILED
        assert c.determine_status("LOW") == ScannerStatus.PASSED


class TestToFlatVulnerabilitiesIdempotent:
    """Regression test: to_flat_vulnerabilities() must not mutate state on repeat calls.

    The bug: the method used to bump summary_stats.suppressed and update
    scanner_results on every call. Two consecutive calls therefore produced
    different list lengths / state. The fix must make the method idempotent.
    """

    def test_calling_twice_returns_same_length(self):
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.schemas.sarif_schema_model import (
            Message,
            PropertyBag,
            Result,
            Run,
            SarifReport,
            Suppression,
            Tool,
            ToolComponent,
        )

        sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="bandit",
                            version="1.0.0",
                        )
                    ),
                    results=[
                        Result(
                            ruleId="B101",
                            level="error",
                            message=Message(text="assert used"),
                        ),
                        Result(
                            ruleId="B102",
                            level="warning",
                            message=Message(text="some issue"),
                            suppressions=[
                                Suppression(
                                    kind="external",
                                    justification="false positive",
                                )
                            ],
                        ),
                    ],
                    properties=PropertyBag(),
                )
            ],
        )

        agg = AshAggregatedResults(sarif=sarif)

        first = agg.to_flat_vulnerabilities()
        second = agg.to_flat_vulnerabilities()

        assert len(first) == len(second), (
            f"to_flat_vulnerabilities is not idempotent: "
            f"first call → {len(first)} items, second call → {len(second)} items"
        )

    def test_calling_twice_does_not_double_suppressed_count(self):
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.schemas.sarif_schema_model import (
            Message,
            PropertyBag,
            Result,
            Run,
            SarifReport,
            Suppression,
            Tool,
            ToolComponent,
        )

        sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="bandit",
                            version="1.0.0",
                        )
                    ),
                    results=[
                        Result(
                            ruleId="B101",
                            level="error",
                            message=Message(text="suppressed one"),
                            suppressions=[
                                Suppression(
                                    kind="external",
                                    justification="known",
                                )
                            ],
                        ),
                    ],
                    properties=PropertyBag(),
                )
            ],
        )

        agg = AshAggregatedResults(sarif=sarif)

        agg.to_flat_vulnerabilities()
        first_suppressed = agg.metadata.summary_stats.suppressed
        agg.to_flat_vulnerabilities()
        second_suppressed = agg.metadata.summary_stats.suppressed

        assert first_suppressed == second_suppressed, (
            f"summary_stats.suppressed grew on repeat call: "
            f"{first_suppressed} → {second_suppressed}"
        )
