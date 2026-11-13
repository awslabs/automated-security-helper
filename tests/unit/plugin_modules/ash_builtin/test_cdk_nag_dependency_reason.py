# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cdk-nag says why it cannot run, on the plugin, not only in a log line.

``validate_plugin_dependencies`` returned a bare False when Node.js was missing,
and only logged a warning when the CDK packages were, so the MISSING row carried
no reason: ``dependency_unavailable_reason`` stayed None and every report built
from it said nothing about the cause.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cdk_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScanner,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def scanner(tmp_path):
    output_dir = tmp_path / "output"
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir(parents=True)
    (tmp_path / "source").mkdir()
    return CdkNagScanner(
        context=PluginContext(
            source_dir=tmp_path / "source",
            output_dir=output_dir,
            work_dir=work_dir,
            config=AshConfig(project_name="test"),
        )
    )


def _node(monkeypatch, path):
    monkeypatch.setattr(
        cdk_nag_scanner,
        "find_executable",
        lambda name: path if name == "node" else f"/usr/bin/{name}",
    )


def test_node_missing_is_recorded_as_the_reason(scanner, monkeypatch):
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    _node(monkeypatch, None)
    assert scanner.validate_plugin_dependencies() is False
    assert scanner.dependency_unavailable_reason is not None
    assert "Node.js not found on PATH" in scanner.dependency_unavailable_reason


def test_missing_cdk_packages_are_recorded_as_the_reason(scanner, monkeypatch):
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_MISSING_DISTRIBUTIONS", ["aws-cdk-lib"])
    _node(monkeypatch, "/usr/bin/node")
    assert scanner.validate_plugin_dependencies() is False
    reason = scanner.dependency_unavailable_reason or ""
    assert "aws-cdk-lib unavailable" in reason
    assert "ash dependencies install --tool cdk-nag" in reason


def test_a_runnable_cdk_nag_has_no_reason(scanner, monkeypatch):
    """Positive control: neither message is recorded when both are present."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    _node(monkeypatch, "/usr/bin/node")
    assert scanner.validate_plugin_dependencies() is True
    assert scanner.dependency_unavailable_reason is None


def test_the_installer_knows_cdk_nag_needs_node():
    """``ash dependencies install`` reads this to judge cdk-nag after installing."""
    assert "node" in CdkNagScanner.external_executables
