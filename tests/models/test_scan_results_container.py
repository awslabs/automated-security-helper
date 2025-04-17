"""Unit tests for scan results container."""

from automated_security_helper.models.scan_results_container import ScanResultsContainer


def test_scan_results_container_initialization():
    """Test ScanResultsContainer initialization."""
    container = ScanResultsContainer()
    assert container.metadata == {}
    assert container.raw_results is None
    assert container.path is None


def test_scan_results_container_add_metadata():
    """Test adding metadata to container."""
    container = ScanResultsContainer()
    container.add_metadata("version", "1.0.0")
    container.add_metadata("scanner", "test_scanner")
    assert container.metadata == {"version": "1.0.0", "scanner": "test_scanner"}


def test_scan_results_container_set_raw_results():
    """Test setting raw results."""
    raw_results = {"findings": [], "metadata": {}}
    container = ScanResultsContainer(
        raw_results=raw_results,
    )
    assert container.raw_results == raw_results
