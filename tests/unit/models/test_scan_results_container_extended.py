from datetime import datetime
from pathlib import Path
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.core.enums import ScannerStatus


def test_scan_results_container_add_error():
    """Test adding errors to a ScanResultsContainer."""
    container = ScanResultsContainer(scanner_name="test_scanner")

    # Add an error
    container.add_error("Test error")
    assert "Test error" in container.errors
    assert len(container.errors) == 1

    # Add the same error again (should not duplicate)
    container.add_error("Test error")
    assert len(container.errors) == 1

    # Add a different error
    container.add_error("Another error")
    assert len(container.errors) == 2
    assert "Another error" in container.errors


def test_scan_results_container_set_exception():
    """Test setting an exception in a ScanResultsContainer."""
    container = ScanResultsContainer(scanner_name="test_scanner")

    # Create a test exception
    try:
        raise ValueError("Test exception")
    except ValueError as e:
        container.set_exception(e)

    # Check that the exception was set correctly
    assert container.exception == "Test exception"
    assert container.stack_trace is not None
    assert "Test exception" in container.errors
    assert container.status == ScannerStatus.FAILED


def test_scan_results_container_with_target():
    """Test creating a ScanResultsContainer with a target path."""
    target_path = Path("/path/to/target")
    container = ScanResultsContainer(
        scanner_name="test_scanner", target=target_path, target_type="file"
    )

    assert container.target == target_path
    assert container.target_type == "file"


def test_scan_results_container_with_timing():
    """Test ScanResultsContainer with timing information."""
    start_time = datetime.now()
    container = ScanResultsContainer(scanner_name="test_scanner", start_time=start_time)

    # Set end time and duration
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    container.end_time = end_time
    container.duration = duration

    assert container.start_time == start_time
    assert container.end_time == end_time
    assert container.duration == duration


def test_scan_results_container_severity_counts():
    """Test ScanResultsContainer severity counts."""
    container = ScanResultsContainer(scanner_name="test_scanner")

    # Default severity counts
    assert container.severity_counts["critical"] == 0
    assert container.severity_counts["high"] == 0
    assert container.severity_counts["medium"] == 0
    assert container.severity_counts["low"] == 0
    assert container.severity_counts["info"] == 0
    assert container.severity_counts["suppressed"] == 0
    assert container.severity_counts["total"] == 0

    # Update severity counts
    container.severity_counts["critical"] = 1
    container.severity_counts["high"] = 2
    container.severity_counts["total"] = 3

    assert container.severity_counts["critical"] == 1
    assert container.severity_counts["high"] == 2
    assert container.severity_counts["total"] == 3
