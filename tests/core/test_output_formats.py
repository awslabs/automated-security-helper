"""Test cases for output format handling."""

import pytest
from pathlib import Path

from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.core.exceptions import ASHValidationError


def test_valid_output_formats():
    """Test valid output formats are accepted."""
    orchestrator = ASHScanOrchestrator(
        source_dir=Path("."),
        output_dir=Path("./output"),
        scan_output_formats=["json", "html", "sarif"],
    )
    assert orchestrator.scan_output_formats == ["json", "html", "sarif"]


def test_invalid_output_formats():
    """Test invalid output formats raise error."""
    with pytest.raises(ASHValidationError) as exc:
        ASHScanOrchestrator(
            source_dir=Path("."),
            output_dir=Path("./output"),
            scan_output_formats=["json", "invalid", "html"],
        )
    assert "Invalid output formats" in str(exc.value)


def test_cli_formats_override_config():
    """Test CLI formats override config file formats."""
    config_yaml = """
    project_name: test
    output:
        formats:
            - json
            - html
    """
    config_path = Path("test_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_yaml)

    try:
        orchestrator = ASHScanOrchestrator(
            source_dir=Path("."),
            output_dir=Path("./output"),
            config_path=config_path,
            scan_output_formats=["sarif", "csv"],
        )
        assert orchestrator.scan_output_formats == ["sarif", "csv"]
        assert orchestrator.config.output.formats == ["sarif", "csv"]
    finally:
        config_path.unlink()


def test_empty_formats_use_default():
    """Test empty formats list uses default json format."""
    orchestrator = ASHScanOrchestrator(
        source_dir=Path("."), output_dir=Path("./output"), scan_output_formats=[]
    )
    assert orchestrator.scan_output_formats == ["json"]
