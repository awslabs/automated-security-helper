import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ReportMetadata,
    SummaryStats,
    ScannerStatusInfo,
    ScannerTargetStatusInfo,
    ConverterStatusInfo,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
    Run,
    Tool,
    ToolComponent,
    Result,
    Message,
    PropertyBag,
)


def test_report_metadata_initialization():
    """Test ReportMetadata initialization with default values."""
    metadata = ReportMetadata(project_name="Test Project")

    assert metadata.project_name == "Test Project"
    assert metadata.generated_at is not None
    assert metadata.report_id is not None
    assert metadata.report_id.startswith("ASH-")
    assert isinstance(metadata.summary_stats, SummaryStats)


def test_summary_stats_bump():
    """Test SummaryStats bump method."""
    stats = SummaryStats()

    # Initial values should be zero
    assert stats.critical == 0
    assert stats.high == 0
    assert stats.total == 0

    # Test bumping values
    stats.bump("critical")
    assert stats.critical == 1

    stats.bump("high", 2)
    assert stats.high == 2

    stats.bump("total", 3)
    assert stats.total == 3


def test_scanner_status_info_initialization():
    """Test ScannerStatusInfo initialization."""
    status_info = ScannerStatusInfo()

    assert status_info.dependencies_satisfied is True
    assert status_info.excluded is False
    assert isinstance(status_info.source, ScannerTargetStatusInfo)
    assert isinstance(status_info.converted, ScannerTargetStatusInfo)


def test_converter_status_info_initialization():
    """Test ConverterStatusInfo initialization."""
    converter_info = ConverterStatusInfo()

    assert converter_info.dependencies_satisfied is True
    assert converter_info.excluded is False
    assert converter_info.converted_paths == []


def test_ash_aggregated_results_initialization():
    """Test AshAggregatedResults initialization with default values."""
    results = AshAggregatedResults()

    assert results.name == "ASH Scan Report"
    assert results.description == "Automated Security Helper - Aggregated Report"
    assert isinstance(results.metadata, ReportMetadata)
    assert isinstance(results.sarif, SarifReport)
    assert results.scanner_results == {}
    assert results.converter_results == {}
    assert results.additional_reports == {}


def test_ash_aggregated_results_to_simple_dict():
    """Test AshAggregatedResults to_simple_dict method."""
    results = AshAggregatedResults(
        name="Test Report",
        description="Test Description",
        scanner_results={
            "bandit": ScannerStatusInfo(
                status=ScannerStatus.PASSED,
                source=ScannerTargetStatusInfo(finding_count=5),
            )
        },
        converter_results={
            "archive": ConverterStatusInfo(converted_paths=["test.zip"])
        },
    )

    simple_dict = results.to_simple_dict()

    assert simple_dict["name"] == "Test Report"
    assert simple_dict["description"] == "Test Description"
    assert "scanner_results" in simple_dict
    assert "bandit" in simple_dict["scanner_results"]
    assert simple_dict["scanner_results"]["bandit"]["source"]["finding_count"] == 5
    assert "converter_results" in simple_dict
    assert "archive" in simple_dict["converter_results"]
    assert simple_dict["converter_results"]["archive"]["converted_paths"] == [
        "test.zip"
    ]


@patch("pathlib.Path.mkdir")
@patch("pathlib.Path.write_text")
def test_ash_aggregated_results_save_model(mock_write_text, mock_mkdir):
    """Test AshAggregatedResults save_model method."""
    results = AshAggregatedResults(name="Test Report", description="Test Description")

    output_dir = Path("/test/output")
    results.save_model(output_dir)

    # Check that directories were created
    mock_mkdir.assert_called_with(parents=True, exist_ok=True)

    # Check that the file was written
    mock_write_text.assert_called_once()

    # Verify the content of the written file
    args, _ = mock_write_text.call_args
    content = args[0]
    assert "Test Report" in content
    assert "Test Description" in content


@patch("builtins.open", new_callable=MagicMock)
@patch("json.load")
@patch("pathlib.Path.exists", return_value=True)
def test_ash_aggregated_results_load_model(mock_exists, mock_json_load, mock_open):
    """Test AshAggregatedResults load_model method."""
    # Mock the JSON data that would be loaded
    mock_json_load.return_value = {
        "name": "Test Report",
        "description": "Test Description",
        "metadata": {
            "project_name": "Test Project",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_id": "ASH-20230101",
        },
    }

    # Call the load_model method
    json_path = Path("/test/ash_aggregated_results.json")
    result = AshAggregatedResults.load_model(json_path)

    # Verify the result
    assert result is not None
    assert result.name == "Test Report"
    assert result.description == "Test Description"
    assert result.metadata.project_name == "Test Project"

    # Verify that the file was opened
    mock_open.assert_called_once_with(json_path)


@patch("pathlib.Path.exists", return_value=False)
def test_ash_aggregated_results_load_model_nonexistent_file(mock_exists):
    """Test AshAggregatedResults load_model method with a nonexistent file."""
    json_path = Path("/test/nonexistent.json")
    result = AshAggregatedResults.load_model(json_path)

    assert result is None


def test_ash_aggregated_results_from_json_string():
    """Test AshAggregatedResults from_json method with a JSON string."""
    json_str = json.dumps(
        {
            "name": "Test Report",
            "description": "Test Description",
            "metadata": {
                "project_name": "Test Project",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "report_id": "ASH-20230101",
            },
        }
    )

    result = AshAggregatedResults.from_json(json_str)

    assert result.name == "Test Report"
    assert result.description == "Test Description"
    assert result.metadata.project_name == "Test Project"


def test_ash_aggregated_results_from_json_dict():
    """Test AshAggregatedResults from_json method with a dictionary."""
    json_dict = {
        "name": "Test Report",
        "description": "Test Description",
        "metadata": {
            "project_name": "Test Project",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_id": "ASH-20230101",
        },
    }

    result = AshAggregatedResults.from_json(json_dict)

    assert result.name == "Test Report"
    assert result.description == "Test Description"
    assert result.metadata.project_name == "Test Project"


def test_ash_aggregated_results_to_flat_vulnerabilities_empty():
    """Test AshAggregatedResults to_flat_vulnerabilities method with empty results."""
    results = AshAggregatedResults()

    flat_vulns = results.to_flat_vulnerabilities()

    assert isinstance(flat_vulns, list)
    assert len(flat_vulns) == 0


def test_ash_aggregated_results_to_flat_vulnerabilities_with_sarif():
    """Test AshAggregatedResults to_flat_vulnerabilities method with SARIF results."""
    # Create a SARIF report with a finding
    sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="TestScanner", version="1.0.0")),
                results=[
                    Result(
                        ruleId="TEST001",
                        level="error",
                        message=Message(text="Test finding"),
                        locations=[
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "test.py"},
                                    "region": {"startLine": 10, "endLine": 15},
                                }
                            }
                        ],
                        properties=PropertyBag(tags=["security", "test"]),
                    )
                ],
            )
        ],
    )

    results = AshAggregatedResults(sarif=sarif)

    flat_vulns = results.to_flat_vulnerabilities()

    assert len(flat_vulns) == 1
    assert flat_vulns[0].title == "TEST001"
    assert flat_vulns[0].description == "Test finding"
    assert flat_vulns[0].severity == "HIGH"
