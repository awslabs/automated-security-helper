"""Regression tests for C5: hasattr-on-dict bugs in issue_severity extraction.

These tests pin down the behavior that was silently broken:
1. sarif_utils.get_severity_metrics_from_sarif: `hasattr(dict, "issue_severity")`
   always returned False, so issue_severity was never honored — everything fell
   through to the SARIF-level mapping.
2. scanner_statistics_calculator.extract_sarif_counts_for_scanner:
   `hasattr(PropertyBag, "get")` also returned False, so the same issue_severity
   branch was dead.

Scenario: Bandit emits SARIF with level=warning and properties.issue_severity=HIGH.
After the fix, a HIGH issue_severity MUST take priority over level=warning
(which would otherwise map to medium).
"""

from pathlib import Path
from unittest.mock import MagicMock

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    PhysicalLocation,
    PropertyBag,
    ArtifactLocation,
    Location,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import (
    get_severity_metrics_from_sarif,
)


def _build_sarif_report(results: list[Result], tool_name: str = "bandit") -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name=tool_name)),
                results=results,
            )
        ],
    )


def _build_result(
    level: str,
    issue_severity: str | None = None,
    scanner_name: str = "bandit",
    scanner_details: dict | None = None,
) -> Result:
    props_data: dict = {"tags": []}
    if issue_severity is not None:
        props_data["issue_severity"] = issue_severity
    if scanner_details is None:
        scanner_details = {"tool_name": scanner_name}
    props_data["scanner_details"] = scanner_details
    props_data["scanner_name"] = scanner_name

    return Result(
        ruleId="TEST001",
        level=level,
        message=Message(text="test finding"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri="file.py"),
                    region=Region(startLine=1),
                )
            )
        ],
        properties=PropertyBag(**props_data),
    )


def _plugin_context(tmp_path: Path) -> PluginContext:
    ctx = MagicMock(spec=PluginContext)
    ctx.source_dir = tmp_path / "src"
    ctx.output_dir = tmp_path / "out"
    return ctx


class TestGetSeverityMetricsFromSarif:
    """Tests for automated_security_helper.utils.sarif_utils.get_severity_metrics_from_sarif."""

    def test_issue_severity_high_overrides_level_warning(self, tmp_path):
        """A finding with level=warning but issue_severity=HIGH must count as high."""
        sarif = _build_sarif_report(
            [_build_result(level="warning", issue_severity="HIGH")]
        )
        counts = get_severity_metrics_from_sarif(sarif, _plugin_context(tmp_path))
        assert counts.high == 1, (
            f"Expected issue_severity=HIGH to win over level=warning; got {counts!r}"
        )
        assert counts.medium == 0, (
            f"Must not fall back to level=warning mapping; got {counts!r}"
        )

    def test_issue_severity_critical_counted_as_critical(self, tmp_path):
        sarif = _build_sarif_report(
            [_build_result(level="warning", issue_severity="CRITICAL")]
        )
        counts = get_severity_metrics_from_sarif(sarif, _plugin_context(tmp_path))
        assert counts.critical == 1
        assert counts.medium == 0

    def test_issue_severity_low_counted_as_low(self, tmp_path):
        sarif = _build_sarif_report(
            [_build_result(level="warning", issue_severity="LOW")]
        )
        counts = get_severity_metrics_from_sarif(sarif, _plugin_context(tmp_path))
        assert counts.low == 1
        assert counts.medium == 0

    def test_no_issue_severity_falls_back_to_level(self, tmp_path):
        """Without issue_severity, the SARIF level mapping still applies."""
        sarif = _build_sarif_report([_build_result(level="warning")])
        counts = get_severity_metrics_from_sarif(sarif, _plugin_context(tmp_path))
        assert counts.medium == 1

    def test_invalid_issue_severity_falls_back_to_level(self, tmp_path):
        """Unknown issue_severity values must not silently drop the finding."""
        sarif = _build_sarif_report(
            [_build_result(level="error", issue_severity="BOGUS")]
        )
        counts = get_severity_metrics_from_sarif(sarif, _plugin_context(tmp_path))
        assert counts.critical == 1


class TestExtractSarifCountsForScanner:
    """Tests for ScannerStatisticsCalculator.extract_sarif_counts_for_scanner."""

    def _wrap(self, results: list[Result]) -> MagicMock:
        mock_model = MagicMock()
        mock_model.sarif = _build_sarif_report(results)
        return mock_model

    def test_issue_severity_high_overrides_level_warning(self):
        model = self._wrap([_build_result(level="warning", issue_severity="HIGH")])
        suppressed, critical, high, medium, low, info = (
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                model, "bandit"
            )
        )
        assert high == 1, (
            "Expected HIGH from issue_severity, not medium from level=warning"
        )
        assert medium == 0
        assert suppressed == 0

    def test_issue_severity_critical_counted(self):
        model = self._wrap(
            [_build_result(level="warning", issue_severity="CRITICAL")]
        )
        _, critical, _, medium, _, _ = (
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                model, "bandit"
            )
        )
        assert critical == 1
        assert medium == 0

    def test_no_issue_severity_uses_level_mapping(self):
        model = self._wrap([_build_result(level="warning")])
        _, _, _, medium, _, _ = (
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                model, "bandit"
            )
        )
        assert medium == 1

    def test_suppressed_finding_not_double_counted(self):
        """Suppressed findings increment suppressed, never a severity bucket."""
        from automated_security_helper.schemas.sarif_schema_model import (
            Kind1,
            Suppression,
        )

        result = _build_result(level="warning", issue_severity="HIGH")
        result.suppressions = [Suppression(kind=Kind1.external)]
        model = self._wrap([result])
        suppressed, _, high, _, _, _ = (
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                model, "bandit"
            )
        )
        assert suppressed == 1
        assert high == 0
