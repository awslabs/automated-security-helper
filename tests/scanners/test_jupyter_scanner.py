"""Unit tests for jupyter scanner module."""

from importlib.metadata import version
from pathlib import Path


from automated_security_helper.scanners.jupyter_scanner import JupyterScanner


def test_jupyter_scanner_initialization(test_source_dir: Path, test_output_dir: Path):
    """Test basic initialization of JupyterScanner."""
    scanner = JupyterScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    assert scanner._default_config.type == "SAST"
    assert scanner.tool_version == version("automated_security_helper")


def test_jupyter_scanner_scan(test_source_dir: Path, test_output_dir: Path):
    """Test JupyterScanner scan method."""
    scanner = JupyterScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    result = scanner.scan(test_source_dir, test_output_dir)

    # Verify structure of returned results
    assert isinstance(result, dict)
    assert "findings" in result
    assert "metadata" in result
    assert isinstance(result["findings"], list)
    assert isinstance(result["metadata"], dict)
