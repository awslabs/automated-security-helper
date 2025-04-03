"""Unit tests for orchestrator module."""

import os
import tempfile
import pytest
import yaml
from automated_security_helper.orchestrator import ASHScanOrchestrator


@pytest.fixture
def default_config():
    """Fixture to create a default configuration file."""
    config = {
        "scanners": {
            "bandit": {"enabled": True, "config": "bandit.yaml"},
            "cfn": {"enabled": True},
        },
        "parsers": {},
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.safe_dump(config, f)
        yield f.name
    os.unlink(f.name)


@pytest.fixture
def source_dir():
    """Fixture to create a temporary source directory."""
    with tempfile.TemporaryDirectory() as d:
        # Create a dummy Python file to scan
        with open(os.path.join(d, "test.py"), "w") as f:
            f.write("print('hello world')")
        yield d


@pytest.fixture
def output_dir():
    """Fixture to create a temporary output directory."""
    with tempfile.TemporaryDirectory() as d:
        yield d


def test_execute_scan_with_config(default_config, source_dir, output_dir):
    """Test executing scan with configuration file."""
    orchestrator = ASHScanOrchestrator(
        source_dir=source_dir, output_dir=output_dir, config_path=default_config
    )
    result = orchestrator.execute_scan()
    assert isinstance(result, dict)
    assert "scanners" in result
    assert "metadata" in result


def test_execute_scan_no_config(source_dir, output_dir):
    """Test executing scan without configuration file."""
    orchestrator = ASHScanOrchestrator(
        source_dir=source_dir, output_dir=output_dir, config_path=None
    )
    result = orchestrator.execute_scan()
    assert isinstance(result, dict)
    assert "scanners" in result
    assert "metadata" in result


def test_execute_scan_nonexistent_config(source_dir, output_dir):
    """Test executing scan with non-existent configuration file."""
    orchestrator = ASHScanOrchestrator(
        source_dir=source_dir, output_dir=output_dir, config_path="nonexistent.yaml"
    )
    with pytest.raises(FileNotFoundError):
        orchestrator.execute_scan()


def test_execute_scan_invalid_config(source_dir, output_dir):
    """Test executing scan with invalid configuration file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("invalid: yaml: content: :")
        f.flush()
        orchestrator = ASHScanOrchestrator(
            source_dir=source_dir, output_dir=output_dir, config_path=f.name
        )
        with pytest.raises(yaml.YAMLError):
            orchestrator.execute_scan()
