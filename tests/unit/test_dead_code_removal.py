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


def test_tools_install_dependencies_script_removed():
    # Superseded by cli/dependencies.py, which exposes the same install_dependencies
    # entry point and is the one the `ash` console script reaches. The tools/ copy
    # was never imported, never declared in [project.scripts], and never touched
    # after the v3 release. It also sat in a directory with no __init__.py, so
    # coverage's source discovery skipped it and its 72 statements never appeared
    # in any report -- deleting it removes both the dead code and the blind spot.
    dead_file = (
        REPO_ROOT / "automated_security_helper" / "tools" / "install_dependencies.py"
    )
    assert not dead_file.exists(), f"{dead_file} should have been removed"
