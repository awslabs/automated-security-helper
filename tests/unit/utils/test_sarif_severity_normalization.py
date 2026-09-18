"""Tests for normalizing rule-level SARIF severity onto results."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    PropertyBag,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import (
    _resolve_result_severity,
    get_severity_metrics_from_sarif,
    normalize_sarif_result_severities,
)


def _report(
    score: object,
    *,
    rule_id: str = "CVE-TEST",
    result_rule_id: str | None = "CVE-TEST",
    rule_index: int = -1,
    issue_severity: str | None = None,
) -> SarifReport:
    result_properties = (
        PropertyBag(issue_severity=issue_severity)
        if issue_severity is not None
        else None
    )
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(
                    driver=ToolComponent(
                        name="grype",
                        rules=[
                            ReportingDescriptor(
                                id=rule_id,
                                properties=PropertyBag(**{"security-severity": score}),
                            )
                        ],
                    )
                ),
                results=[
                    Result(
                        ruleId=result_rule_id,
                        ruleIndex=rule_index,
                        level="error",
                        message=Message(text="test finding"),
                        properties=result_properties,
                    )
                ],
            )
        ],
    )


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.1, "LOW"),
        (3.9, "LOW"),
        (4.0, "MEDIUM"),
        (6.9, "MEDIUM"),
        (7.0, "HIGH"),
        ("8.2", "HIGH"),
        (9.0, "CRITICAL"),
        (10.0, "CRITICAL"),
    ],
)
def test_normalizes_cvss_boundaries(score, expected):
    report = normalize_sarif_result_severities(_report(score))

    assert report.runs[0].results[0].properties.issue_severity == expected


def test_uses_rule_index_when_rule_id_is_missing():
    report = normalize_sarif_result_severities(
        _report("7.5", result_rule_id=None, rule_index=0)
    )

    assert report.runs[0].results[0].properties.issue_severity == "HIGH"


def test_preserves_existing_issue_severity():
    report = normalize_sarif_result_severities(_report("9.8", issue_severity="HIGH"))

    assert report.runs[0].results[0].properties.issue_severity == "HIGH"


@pytest.mark.parametrize("score", [0, None, "unknown", -0.1, 10.1, float("nan")])
def test_ignores_invalid_security_severity(score):
    report = normalize_sarif_result_severities(_report(score))

    assert report.runs[0].results[0].properties is None


def test_score_zero_does_not_downgrade_an_error_level_finding():
    """A rule security-severity of 0 must not fail open.

    npm-audit defaults its rule security-severity to 0 for advisories that
    ship no CVSS number. Mapping that to INFO would drop a critical/high
    finding under any severity threshold, so normalization leaves the result
    untouched and the SARIF level (error -> critical) decides the severity.
    """
    report = normalize_sarif_result_severities(_report(0))
    result = report.runs[0].results[0]

    assert result.properties is None
    assert _resolve_result_severity(result) == "critical"


def test_ignores_a_result_without_a_matching_rule():
    report = normalize_sarif_result_severities(_report("8.2", result_rule_id="OTHER"))

    assert report.runs[0].results[0].properties is None


def test_scan_result_processor_preserves_grype_severity_through_aggregation(
    tmp_path,
):
    context = MagicMock()
    context.source_dir = tmp_path / "source"
    context.output_dir = tmp_path / "output"
    context.ignore_suppressions = True
    context.source_dir.mkdir()

    processor = ScanResultProcessor(
        plugin_context=context,
        validation_manager=MagicMock(),
    )
    container = ScanResultsContainer(
        scanner_name="grype",
        report_type="sarif",
        target=context.source_dir,
        target_type="source",
        raw_results=_report("8.2"),
    )

    aggregated_sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ASH"), extensions=[]),
                results=[],
            )
        ],
    )
    aggregate = SimpleNamespace(
        additional_reports={},
        used_suppressions=set(),
        sarif=aggregated_sarif,
        cyclonedx=None,
    )

    aggregated = processor.process_container(container, aggregate)
    result = aggregated.sarif.runs[0].results[0]

    assert result.properties.issue_severity == "HIGH"
    counts = get_severity_metrics_from_sarif(aggregated.sarif, context)
    assert counts.high == 1
    assert counts.critical == 0
