"""Unit tests for aggregation functionality."""

import pytest
from datetime import datetime, timedelta
from automated_security_helper.models.core import Location, Scanner, BaseFinding
from automated_security_helper.models.aggregation import (
    FindingAggregator,
    TrendAnalyzer,
)


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    scanner = Scanner(
        name="test_scanner", version="1.0.0", rule_id="RULE-001", type="SAST"
    )
    location = Location(file_path="/path/to/file", start_line=10, end_line=20)
    return BaseFinding(
        id="TEST-001",
        title="Test Finding",
        description="This is a test finding",
        severity="HIGH",
        scanner=scanner,
        location=location,
    )


def test_finding_aggregator_add(sample_finding):
    """Test adding findings to aggregator."""
    aggregator = FindingAggregator()
    aggregator.add_finding(sample_finding)
    assert len(aggregator.findings) == 1


def test_finding_aggregator_deduplicate(sample_finding):
    """Test deduplication of findings."""
    aggregator = FindingAggregator()
    # Create duplicate finding with same attributes
    finding2 = BaseFinding(
        id=f"TEST-{round(datetime.now().timestamp())}",
        title=sample_finding.title,
        description=sample_finding.description,
        severity=sample_finding.severity,
        scanner=sample_finding.scanner,
        location=sample_finding.location,
    )
    aggregator.add_finding(sample_finding)
    aggregator.add_finding(finding2)
    deduplicated = aggregator.deduplicate()
    assert len(deduplicated) == 1


def test_finding_aggregator_group_by_type(sample_finding):
    """Test grouping findings by type."""
    aggregator = FindingAggregator()
    # Create second finding with different rule
    finding2 = BaseFinding(
        id=f"TEST-{round(datetime.now().timestamp())}",
        title=sample_finding.title,
        description=sample_finding.description,
        severity=sample_finding.severity,
        scanner=Scanner(
            name="test_scanner", version="1.0.0", rule_id="RULE-002", type="SAST"
        ),
        location=sample_finding.location,
    )
    aggregator.add_finding(sample_finding)
    aggregator.add_finding(finding2)
    grouped = aggregator.group_by_type()
    assert len(grouped) == 2


def test_finding_aggregator_group_by_severity(sample_finding):
    """Test grouping findings by severity."""
    aggregator = FindingAggregator()
    # Create second finding with different severity
    finding2 = BaseFinding(
        id=f"TEST-{round(datetime.now().timestamp())}",
        title=sample_finding.title,
        description=sample_finding.description,
        severity="MEDIUM",
        scanner=sample_finding.scanner,
        location=sample_finding.location,
    )
    aggregator.add_finding(sample_finding)
    aggregator.add_finding(finding2)
    grouped = aggregator.group_by_severity()
    assert len(grouped) == 2
    assert len(grouped["HIGH"]) == 1
    assert len(grouped["MEDIUM"]) == 1


def test_trend_analyzer(sample_finding):
    """Test trend analysis functionality."""
    analyzer = TrendAnalyzer()
    first_scan_time = datetime.now() - timedelta(days=1)
    second_scan_time = datetime.now()

    # Add findings from two different scans
    analyzer.add_scan_findings(first_scan_time, [sample_finding])

    # Create a new finding for second scan
    finding2 = BaseFinding(
        id=f"TEST-{round(datetime.now().timestamp())}",
        title="New Finding",
        description="A new test finding",
        severity="MEDIUM",
        scanner=Scanner(
            name="test_scanner", version="1.0.0", rule_id="RULE-002", type="SAST"
        ),
        location=Location(file_path="/path/to/other/file", start_line=15, end_line=25),
    )
    analyzer.add_scan_findings(second_scan_time, [finding2])

    # Test finding counts over time
    counts = analyzer.get_finding_counts_over_time()
    assert len(counts) == 2
    assert counts[first_scan_time] == 1
    assert counts[second_scan_time] == 1

    # Test severity trends
    trends = analyzer.get_severity_trends()
    assert "HIGH" in trends
    assert "MEDIUM" in trends
    # Removed duplicate implementation

    new_findings = analyzer.get_new_findings(first_scan_time, second_scan_time)
    assert len(new_findings) == 1  # Should be 1 since we added a different finding

    # Test resolved findings detection
    resolved = analyzer.get_resolved_findings(first_scan_time, second_scan_time)
    assert len(resolved) == 1  # First finding is resolved in second scan
