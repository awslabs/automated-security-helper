"""Unit tests for dynamic analysis functionality."""

import pytest
from datetime import datetime, timezone
from automated_security_helper.models.core import Location, Scanner
from automated_security_helper.models.dynamic_analysis import (
    DynamicAnalysisFinding,
    DynamicAnalysisReport,
)


@pytest.fixture
def sample_scanner():
    """Create a sample scanner for testing."""
    return Scanner(
        name="dynamic_scanner", version="1.0.0", rule_id="DAST-001", type="DAST"
    )


@pytest.fixture
def sample_location():
    """Create a sample location for testing."""
    return Location(
        file_path="/api/users",
        start_line=0,  # Not always applicable for dynamic analysis
        end_line=0,
    )


@pytest.fixture
def sample_finding(sample_scanner, sample_location):
    """Create a sample dynamic analysis finding for testing."""
    return DynamicAnalysisFinding(
        id="sql-1",
        endpoint="postgres://postres.cloud",
        title="SQL Injection",
        description="Potential SQL injection vulnerability detected",
        severity="HIGH",
        scanner=sample_scanner,
        location=sample_location,
        timestamp=datetime.now(),
        request_method="POST",
        request_url="/api/users",
        request_headers={"Content-Type": "application/json"},
        request_body='{"id": "1 OR 1=1"}',
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"data": [...]}',
        proof_of_concept="curl -X POST -H 'Content-Type: application/json' -d '{\"id\": \"1 OR 1=1\"}' /api/users",
    )


def test_dynamic_analysis_finding_creation(sample_scanner, sample_location):
    """Test creation of DynamicAnalysisFinding objects."""
    finding = DynamicAnalysisFinding(
        id="sql-1",
        endpoint="postgres://postres.cloud",
        title="SQL Injection",
        description="Potential SQL injection vulnerability detected",
        severity="HIGH",
        scanner=sample_scanner,
        location=sample_location,
        timestamp=datetime.now(),
        request_method="POST",
        request_url="/api/users",
        request_headers={"Content-Type": "application/json"},
        request_body='{"id": "1 OR 1=1"}',
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"data": [...]}',
        proof_of_concept="curl -X POST -H 'Content-Type: application/json' -d '{\"id\": \"1 OR 1=1\"}' /api/users",
    )
    assert finding.title == "SQL Injection"
    assert finding.severity == "HIGH"
    assert finding.request_method == "POST"
    assert finding.request_url == "/api/users"
    assert finding.response_status == 200
    assert "Content-Type" in finding.request_headers
    assert "Content-Type" in finding.response_headers


def test_dynamic_analysis_finding_inheritance(sample_finding):
    """Test that DynamicAnalysisFinding inherits correctly from BaseFinding."""
    assert hasattr(sample_finding, "title")
    assert hasattr(sample_finding, "description")
    assert hasattr(sample_finding, "severity")
    assert hasattr(sample_finding, "scanner")
    assert hasattr(sample_finding, "location")
    assert hasattr(sample_finding, "timestamp")


def test_dynamic_analysis_finding_invalid_request_method(
    sample_scanner, sample_location
):
    """Test that invalid request method raises ValidationError."""
    with pytest.raises(ValueError):
        DynamicAnalysisFinding(
            title="SQL Injection",
            description="Test vulnerability",
            severity="HIGH",
            scanner=sample_scanner,
            location=sample_location,
            timestamp=datetime.now(),
            request_method="INVALID",  # Invalid HTTP method
            request_url="/api/users",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="",
            proof_of_concept="",
        )


def test_dynamic_analysis_report_creation(sample_finding):
    """Test creation of DynamicAnalysisReport objects."""
    report = DynamicAnalysisReport(
        scanner_name="DynaScan",
        target_url="https://example.com",
        scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%M-%d"),
        findings=[sample_finding],
        scan_coverage={
            "endpoints_tested": 50,
            "auth_tested": True,
            "input_vectors_tested": ["path", "query", "body"],
        },
    )
    assert report.target_url == "https://example.com"
    assert len(report.findings) == 1
    assert report.findings[0] == sample_finding
    assert report.scan_coverage.endpoints_tested == 50
    assert report.scan_coverage.auth_tested is True


def test_dynamic_analysis_report_empty():
    """Test creation of empty DynamicAnalysisReport."""
    report = DynamicAnalysisReport(
        scanner_name="DynaScan",
        target_url="https://example.com",
        scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%M-%d"),
        findings=[],
        scan_coverage={
            "endpoints_tested": 0,
            "auth_tested": False,
            "input_vectors_tested": [],
        },
    )
    assert report.target_url == "https://example.com"
    assert len(report.findings) == 0
    assert report.scan_coverage.endpoints_tested == 0


def test_dynamic_analysis_report_multiple_findings(sample_finding):
    """Test DynamicAnalysisReport with multiple findings."""
    finding2 = DynamicAnalysisFinding(
        id="xss-1",
        endpoint="https://myapp-is-secure.com",
        title="XSS Vulnerability",
        description="Cross-site scripting vulnerability detected",
        severity="MEDIUM",
        scanner=sample_finding.scanner,
        location=sample_finding.location,
        timestamp=datetime.now(),
        request_method="GET",
        request_url="/api/comments",
        request_headers={},
        request_body="",
        response_status=200,
        response_headers={"Content-Type": "text/html"},
        response_body="<script>alert('xss')</script>",
        proof_of_concept="curl '/api/comments?input=<script>alert(1)</script>'",
    )

    report = DynamicAnalysisReport(
        scanner_name="DynaScan",
        target_url="https://example.com",
        scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%M-%d"),
        findings=[sample_finding, finding2],
        scan_coverage={
            "endpoints_tested": 100,
            "auth_tested": True,
            "input_vectors_tested": ["path", "query", "body", "header"],
        },
    )
    assert len(report.findings) == 2
    assert any(f.severity == "HIGH" for f in report.findings)
    assert any(f.severity == "MEDIUM" for f in report.findings)
    assert any(f.request_method == "POST" for f in report.findings)
    assert any(f.request_method == "GET" for f in report.findings)
