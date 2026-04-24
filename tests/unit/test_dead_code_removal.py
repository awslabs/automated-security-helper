"""Regression tests: dead code files must remain deleted."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_uv_tool_installation_module_removed():
    dead_file = REPO_ROOT / "automated_security_helper" / "models" / "uv_tool_installation.py"
    assert not dead_file.exists(), f"{dead_file} should have been removed"


def test_scan_tracking_modified_module_removed():
    dead_file = (
        REPO_ROOT
        / "automated_security_helper"
        / "core"
        / "resource_management"
        / "scan_tracking_modified.py"
    )
    assert not dead_file.exists(), f"{dead_file} should have been removed"
