"""Unit tests for static analysis functionality."""

import pytest
from datetime import datetime, timezone
from automated_security_helper.models.core import Location, Scanner
from automated_security_helper.models.static_analysis import (
    StaticAnalysisFinding,
    StaticAnalysisReport,
    StaticAnalysisStatistics,
)


@pytest.fixture
def sample_scanner():
    """Create a sample scanner for testing."""
    return Scanner(
        name="static_analyzer", version="1.0.0", rule_id="SAST-001", type="SAST"
    )


@pytest.fixture
def sample_location():
    """Create a sample location for testing."""
    return Location(file_path="/app/main.py", start_line=45, end_line=48)


@pytest.fixture
def sample_finding(sample_scanner, sample_location):
    """Create a sample static analysis finding for testing."""
    return StaticAnalysisFinding(
        id=f"SAST-{round(datetime.now().timestamp())}",
        title="Insecure Deserialization",
        description="Unsafe pickle.loads() usage detected",
        severity="HIGH",
        source_file="myfile.py",
        scanner=sample_scanner,
        location=sample_location,
        finding_type="security",
        code_snippet="data = pickle.loads(user_input)",
        line_number=46,
        column_start=5,
        column_end=35,
        affected_parameters=["user_input"],
        data_flow=[
            {
                "source": {"file": "routes.py", "line": 23, "value": "request.data"},
                "sink": {"file": "main.py", "line": 46, "function": "process_data"},
            }
        ],
        fix_recommendation="Use safe deserialization methods like json.loads()",
    )


def test_static_analysis_finding_creation(sample_scanner, sample_location):
    """Test creation of StaticAnalysisFinding objects."""
    finding = StaticAnalysisFinding(
        id=f"SAST-{round(datetime.now().timestamp())}",
        title="Insecure Deserialization",
        description="Unsafe pickle.loads() usage detected",
        severity="HIGH",
        scanner=sample_scanner,
        source_file="myfile.py",
        location=sample_location,
        timestamp=datetime.now(),
        finding_type="security",
        code_snippet="data = pickle.loads(user_input)",
        line_number=46,
        column_start=5,
        column_end=35,
        affected_parameters=["user_input"],
        data_flow=[
            {
                "source": {"file": "routes.py", "line": 23, "value": "request.data"},
                "sink": {"file": "main.py", "line": 46, "function": "process_data"},
            }
        ],
        fix_recommendation="Use safe deserialization methods like json.loads()",
    )
    assert finding.title == "Insecure Deserialization"
    assert finding.severity == "HIGH"
    assert finding.finding_type == "security"
    assert finding.code_snippet == "data = pickle.loads(user_input)"
    assert finding.line_number == 46
    assert finding.column_start == 5
    assert finding.column_end == 35
    assert "user_input" in finding.affected_parameters
    assert len(finding.data_flow) == 1
    assert (
        finding.fix_recommendation
        == "Use safe deserialization methods like json.loads()"
    )


def test_static_analysis_finding_inheritance(sample_finding):
    """Test that StaticAnalysisFinding inherits correctly from BaseFinding."""
    assert hasattr(sample_finding, "title")
    assert hasattr(sample_finding, "description")
    assert hasattr(sample_finding, "severity")
    assert hasattr(sample_finding, "scanner")
    assert hasattr(sample_finding, "location")
    assert hasattr(sample_finding, "timestamp")


def test_static_analysis_finding_invalid_finding_type(sample_scanner, sample_location):
    """Test that invalid finding type raises ValidationError."""
    with pytest.raises(ValueError):
        StaticAnalysisFinding(
            title="Test Finding",
            description="Test description",
            severity="HIGH",
            scanner=sample_scanner,
            source_file="myfile.py",
            location=sample_location,
            timestamp=datetime.now(),
            finding_type="invalid",  # Invalid finding type
            code_snippet="test code",
            line_number=1,
            column_start=1,
            column_end=10,
            affected_parameters=[],
            data_flow=[],
            fix_recommendation="",
        )


def test_static_analysis_report_creation(sample_finding):
    """Test creation of StaticAnalysisReport objects."""
    report = StaticAnalysisReport(
        project_name="test-project",
        scan_timestamp=datetime.now(timezone.utc).strftime('%Y-%M-%d'),
        scanner_name="test",
        findings=[sample_finding],
        scan_config={
            "rules": ["security", "performance", "style"],
            "ignored_paths": ["tests/", "docs/"],
            "max_line_length": 100,
        },
        statistics={
            "files_scanned": 50,
            "lines_of_code": 5000,
            "findings_by_type": {"security": 1, "performance": 0, "style": 0},
        },
    )
    assert report.project_name == "test-project"
    assert len(report.findings) == 1
    assert report.findings[0] == sample_finding
    assert "security" in report.scan_config.rules
    assert report.statistics.files_scanned == 50
    assert report.statistics.findings_by_type["security"] == 1


def test_static_analysis_report_empty():
    """Test creation of empty StaticAnalysisReport."""
    report = StaticAnalysisReport(
        project_name="test-project",
        scan_timestamp=datetime.now(timezone.utc).strftime('%Y-%M-%d'),
        scanner_name="test",
        findings=[],
        scan_config={
            "rules": ["security"],
            "ignored_paths": [],
            "max_line_length": 100,
        },
        statistics=StaticAnalysisStatistics(
            files_scanned=0,
            lines_of_code=0,
            findings_by_type={"security": 0},
        ),
    )
    assert report.project_name == "test-project"
    assert len(report.findings) == 0
    assert report.statistics.findings_by_type["security"] == 0


def test_static_analysis_report_multiple_findings(sample_finding):
    """Test StaticAnalysisReport with multiple findings."""
    finding2 = StaticAnalysisFinding(
        id=f"SAST-{round(datetime.now().timestamp())}",
        title="SQL Injection Risk",
        description="Possible SQL injection in query construction",
        severity="MEDIUM",
        scanner=sample_finding.scanner,
        source_file="myfile.py",
        location=sample_finding.location,
        timestamp=datetime.now(),
        finding_type="security",
        code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
        line_number=50,
        column_start=1,
        column_end=50,
        affected_parameters=["user_id"],
        data_flow=[
            {
                "source": {
                    "file": "routes.py",
                    "line": 30,
                    "value": "request.args.get('id')",
                },
                "sink": {"file": "main.py", "line": 50, "function": "get_user"},
            }
        ],
        fix_recommendation="Use parameterized queries with cursor.execute()",
    )

    report = StaticAnalysisReport(
        project_name="test-project",
        scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%M-%d"),
        scanner_name="test",
        findings=[sample_finding, finding2],
        scan_config={
            "rules": ["security", "performance", "style"],
            "ignored_paths": ["tests/", "docs/"],
            "max_line_length": 100,
        },
        statistics=StaticAnalysisStatistics(
            files_scanned=50,
            lines_of_code=5000,
            findings_by_type={"security": 2, "performance": 0, "style": 0},
        ),
    )
    assert len(report.findings) == 2
    assert any(f.severity == "HIGH" for f in report.findings)
    assert any(f.severity == "MEDIUM" for f in report.findings)
    assert report.statistics.findings_by_type["security"] == 2


def test_static_analysis_report_by_file():
    """Test grouping findings by file functionality."""
    findings = [
        StaticAnalysisFinding(
            id=f"{i}",
            title=f"Finding {i}",
            description=f"Description {i}",
            severity="HIGH",
            scanner=Scanner(
                name="test", version="1.0", type="SAST", rule_id=f"RULE-{i}"
            ),
            source_file=f"file{i}.py",
            location=Location(file_path=f"file{i}.py", start_line=i, end_line=i),
            timestamp=datetime.now(),
            finding_type="security",
            code_snippet=f"code_{i}",
            line_number=i,
            column_start=1,
            column_end=10,
            affected_parameters=[],
            data_flow=[],
            fix_recommendation="",
        )
        for i in range(1, 4)
    ]

    # Add duplicate file finding
    findings.append(
        StaticAnalysisFinding(
            id="dupe",
            title="Duplicate File Finding",
            description="Another finding in file1.py",
            severity="MEDIUM",
            scanner=Scanner(name="test", version="1.0", type="SAST", rule_id="RULE-4"),
            source_file="file1.py",
            location=Location(file_path="file1.py", start_line=10, end_line=10),
            timestamp=datetime.now(),
            finding_type="security",
            code_snippet="duplicate_code",
            line_number=10,
            column_start=1,
            column_end=10,
            affected_parameters=[],
            data_flow=[],
            fix_recommendation="",
        )
    )

    report = StaticAnalysisReport(
        project_name="test-project",
        scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%M-%d"),
        scanner_name="test",
        findings=findings,
        scan_config={"rules": ["security"]},
        statistics=StaticAnalysisStatistics(
            files_scanned=3,
            lines_of_code=300,
            findings_by_type={"security": 4},
        ),
    )

    by_file = report.group_findings_by_file()
    assert len(by_file) == 3  # Should have 3 unique files
    assert len(by_file["file1.py"]) == 2  # Should have 2 findings
    assert all(
        len(findings) == 1 for file, findings in by_file.items() if file != "file1.py"
    )
