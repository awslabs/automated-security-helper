"""Tests for orchestrator module."""

import json
import os
from pathlib import Path
import tempfile
import pytest
import yaml

from automated_security_helper.config.default_config import DEFAULT_ASH_CONFIG
from automated_security_helper.orchestrator import ASHScanOrchestrator


@pytest.fixture
def default_config():
    """Create a temporary configuration file."""
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        # Create minimal config that gets transformed to ASHConfig
        DEFAULT_ASH_CONFIG
        yaml.safe_dump(json.loads(DEFAULT_ASH_CONFIG.model_dump_json()), f)
        f.flush()
        yield f.name
        os.unlink(f.name)


def test_execute_scan_with_config(test_source_dir: Path, test_output_dir: Path):
    """Test executing scan with configuration file."""
    # Create minimal config that gets transformed to ASHConfig
    try:
        with open(test_source_dir.joinpath("ash.yaml"), "w") as f:
            config_to_dump: dict = json.loads(DEFAULT_ASH_CONFIG.model_dump_json())
            with open(f.name, "w") as f:
                yaml.safe_dump(config_to_dump, f)

        orchestrator = ASHScanOrchestrator(
            source_dir=test_source_dir.as_posix(),
            output_dir=test_output_dir.as_posix(),
            config_path=f.name,
        )
        result = orchestrator.execute_scan()
        assert isinstance(result, dict)
        assert "scanners" in result
    finally:
        pass
        os.unlink(f.name)


def test_execute_scan_no_config(test_source_dir: Path, test_output_dir: Path):
    """Test executing scan whout configuration file."""
    orchestrator = ASHScanOrchestrator(
        source_dir=str(test_source_dir),
        output_dir=str(test_output_dir),
        config_path=None,
    )
    result = orchestrator.execute_scan()
    assert isinstance(result, dict)
    assert "scanners" in result
