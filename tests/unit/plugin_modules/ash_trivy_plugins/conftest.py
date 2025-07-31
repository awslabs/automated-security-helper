# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for Trivy plugin tests."""

import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

# Rebuild models to resolve forward references
AshConfig.model_rebuild()


@pytest.fixture
def mock_plugin_context(tmp_path):
    """Create a mock plugin context for testing."""
    context = MagicMock(spec=PluginContext)
    context.source_dir = tmp_path / "source"
    context.output_dir = tmp_path / "output"
    context.source_dir.mkdir(exist_ok=True)
    context.output_dir.mkdir(exist_ok=True)
    context.global_ignore_paths = []
    return context


@pytest.fixture
def default_trivy_config():
    """Create default Trivy scanner configuration."""
    return TrivyRepoScannerConfig()


@pytest.fixture
def custom_trivy_config():
    """Create custom Trivy scanner configuration."""
    return TrivyRepoScannerConfig(
        enabled=True,
        options=TrivyRepoScannerConfigOptions(
            scanners=["vuln", "secret"],
            license_full=False,
            ignore_unfixed=False,
            disable_telemetry=True,
        )
    )


@pytest.fixture
def mock_sarif_response():
    """Create a mock SARIF response from Trivy."""
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Trivy",
                        "version": "0.45.0",
                        "informationUri": "https://github.com/aquasecurity/trivy"
                    }
                },
                "results": [
                    {
                        "ruleId": "CVE-2023-1234",
                        "level": "error",
                        "message": {
                            "text": "High severity vulnerability found"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "package.json"
                                    },
                                    "region": {
                                        "startLine": 1
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
    """Create a mock empty SARIF response from Trivy."""
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Trivy",
                        "version": "0.45.0",
                        "informationUri": "https://github.com/aquasecurity/trivy"
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
    
    # Create some test files
    (target_dir / "package.json").write_text('{"name": "test"}')
    (target_dir / "requirements.txt").write_text("requests==2.28.0")
    (target_dir / "Dockerfile").write_text("FROM ubuntu:20.04")
    
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