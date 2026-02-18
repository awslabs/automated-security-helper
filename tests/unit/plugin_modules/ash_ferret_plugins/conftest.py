# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for Ferret Scan plugin tests."""

import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScannerConfig,
    FerretScannerConfigOptions,
)

# Rebuild models to resolve forward references
AshConfig.model_rebuild()


@pytest.fixture
def mock_plugin_context(tmp_path):
    """Create a mock plugin context for testing."""
    context = MagicMock(spec=PluginContext)
    context.source_dir = tmp_path / "source"
    context.output_dir = tmp_path / "output"
    context.work_dir = tmp_path / "work"
    context.source_dir.mkdir(exist_ok=True)
    context.output_dir.mkdir(exist_ok=True)
    context.work_dir.mkdir(exist_ok=True)
    context.global_ignore_paths = []
    return context


@pytest.fixture
def default_ferret_config():
    """Create default Ferret scanner configuration."""
    return FerretScannerConfig()


@pytest.fixture
def custom_ferret_config():
    """Create custom Ferret scanner configuration."""
    return FerretScannerConfig(
        enabled=True,
        options=FerretScannerConfigOptions(
            confidence_levels="high,medium",
            checks="CREDIT_CARD,SECRETS,SSN",
            recursive=True,
            profile="security-audit",
            show_match=False,
            enable_preprocessors=True,
        )
    )


@pytest.fixture
def mock_sarif_response():
    """Create a mock SARIF response from Ferret Scan."""
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ferret-scan",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/awslabs/ferret-scan"
                    }
                },
                "results": [
                    {
                        "ruleId": "CREDIT_CARD",
                        "level": "warning",
                        "message": {
                            "text": "Potential credit card number detected"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "test_file.txt"
                                    },
                                    "region": {
                                        "startLine": 10
                                    }
                                }
                            }
                        ]
                    },
                    {
                        "ruleId": "SECRETS",
                        "level": "error",
                        "message": {
                            "text": "Potential API key detected"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "config.py"
                                    },
                                    "region": {
                                        "startLine": 5
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }


@pytest.fixture
def mock_empty_sarif_response():
    """Create a mock empty SARIF response from Ferret Scan."""
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ferret-scan",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/awslabs/ferret-scan"
                    }
                },
                "results": []
            }
        ]
    }


@pytest.fixture
def mock_target_directory(tmp_path):
    """Create a mock target directory with some files."""
    target_dir = tmp_path / "test_project"
    target_dir.mkdir()

    # Create some test files that ferret-scan would analyze
    (target_dir / "config.py").write_text('SETTING = "placeholder"')
    (target_dir / "data.txt").write_text("Some text with potential PII")
    (target_dir / "README.md").write_text("# Test Project")

    return target_dir


@pytest.fixture
def mock_empty_directory(tmp_path):
    """Create an empty directory for testing."""
    empty_dir = tmp_path / "empty_project"
    empty_dir.mkdir()
    return empty_dir


@pytest.fixture
def mock_results_directory(tmp_path):
    """Create a mock results directory structure."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    source_dir = results_dir / "source"
    source_dir.mkdir()

    return results_dir, source_dir


@pytest.fixture
def mock_ferret_config_file(tmp_path):
    """Create a mock Ferret configuration file."""
    config_content = """
defaults:
  format: sarif
  confidence_levels: all
  checks: all
  recursive: true

profiles:
  quick:
    confidence_levels: high
    checks: SECRETS,CREDIT_CARD
"""
    config_file = tmp_path / "source" / "ferret.yaml"
    config_file.parent.mkdir(exist_ok=True)
    config_file.write_text(config_content)
    return config_file
