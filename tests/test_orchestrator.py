"""Tests for orchestrator module."""

import os
import tempfile
import pytest
import yaml

from automated_security_helper.orchestrator import ASHScanOrchestrator


@pytest.fixture
def default_config():
    """Create a temporary configuration file."""
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        # Create minimal config that gets transformed to ASHConfig
        config = {
            "project_name": "test-project",
            "sast": {
                "scanners": [
                    {
                        "type": "bandit",
                        "enabled": True,
                        "name": "bandit",
                        "command": "bandit",
                        "config": "bandit.yaml",
                    }
                ]
            },
        }
        yaml.safe_dump(config, f, default_flow_style=False)
        f.flush()
        yield f.name
        os.unlink(f.name)


def test_execute_scan_with_config(default_config, source_dir, output_dir):
    """Test executing scan with configuration file."""
    orchestrator = ASHScanOrchestrator(
        source_dir=source_dir, output_dir=output_dir, config_path=default_config
    )
    result = orchestrator.execute_scan()
    assert isinstance(result, dict)
    assert "scanners" in result


def test_execute_scan_no_config(source_dir, output_dir):
    """Test executing scan without configuration file."""
    orchestrator = ASHScanOrchestrator(
        source_dir=source_dir, output_dir=output_dir, config_path=None
    )
    result = orchestrator.execute_scan()
    assert isinstance(result, dict)
    assert "scanners" in result
