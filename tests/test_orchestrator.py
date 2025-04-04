"""Tests for orchestrator module."""

import json
import logging
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


@pytest.fixture
def source_dir():
    """Create a temporary source directory."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def output_dir():
    """Create a temporary output directory."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


def test_execute_scan_with_config(source_dir, output_dir):
    """Test executing scan with configuration file."""
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        # Create minimal config that gets transformed to ASHConfig
        try:
            config_to_dump: dict = json.loads(
                json.dumps(DEFAULT_ASH_CONFIG.model_dump(), default=str)
            )
            logging.Logger(__file__).warning(config_to_dump)
            f.flush()
            with open(f.name, "w") as f:
                yaml.safe_dump(config_to_dump, f)
            orchestrator = ASHScanOrchestrator(
                source_dir=source_dir,
                output_dir=output_dir,
                work_dir=output_dir.joinpath("work"),
                config_path=f.name,
            )
            result = orchestrator.execute_scan()
            assert isinstance(result, dict)
            assert "scanners" in result
        finally:
            os.unlink(f.name)


def test_execute_scan_no_config(source_dir, output_dir):
    """Test executing scan without configuration file."""
    orchestrator = ASHScanOrchestrator(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=output_dir.joinpath("work"),
        config_path=None,
    )
    result = orchestrator.execute_scan()
    assert isinstance(result, dict)
    assert "scanners" in result
