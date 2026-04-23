"""Regression tests for low-severity bug fixes and dead code removal."""

import io
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_uv_tool_installation_module_removed():
    """models/uv_tool_installation.py is dead code and must be deleted."""
    dead_file = REPO_ROOT / "automated_security_helper" / "models" / "uv_tool_installation.py"
    assert not dead_file.exists(), f"{dead_file} should have been removed as dead code"


def test_scan_tracking_modified_module_removed():
    """core/resource_management/scan_tracking_modified.py is empty and must be deleted."""
    dead_file = (
        REPO_ROOT
        / "automated_security_helper"
        / "core"
        / "resource_management"
        / "scan_tracking_modified.py"
    )
    assert not dead_file.exists(), f"{dead_file} should have been removed as dead code"


@pytest.mark.asyncio
async def test_get_scan_summary_does_not_print_debug_to_stderr():
    """get_scan_summary must not emit debug banner lines to stderr."""
    from automated_security_helper.cli import mcp_server

    ctx = MagicMock()
    ctx.info = AsyncMock()

    captured = io.StringIO()
    original_stderr = sys.stderr
    sys.stderr = captured
    try:
        with patch.object(
            mcp_server,
            "mcp_get_scan_results",
            new=AsyncMock(return_value={"error": "no results"}),
        ):
            await mcp_server.get_scan_summary(ctx=ctx, output_dir="/tmp/nonexistent")
    finally:
        sys.stderr = original_stderr

    stderr_output = captured.getvalue()
    assert "DEBUG:" not in stderr_output
    assert "get_scan_summary FUNCTION CALLED" not in stderr_output
    assert "=" * 80 not in stderr_output


def test_inspect_findings_split_uses_call_not_subscript():
    """inspect_findings_app.py must use split('.') not split['.'] for file extension."""
    source_path = (
        REPO_ROOT
        / "automated_security_helper"
        / "cli"
        / "inspect"
        / "inspect_findings_app.py"
    )
    source = source_path.read_text()

    # The bug was: .split["."] (subscript instead of method call)
    assert '.split["."]' not in source, "split[\".\"] is subscript syntax, should be split(\".\")"
    assert ".split['.']" not in source, "split['.'] is subscript syntax, should be split('.')"

    # Correct form must be present
    assert '.split(".")[-1]' in source or ".split('.')[-1]" in source, (
        "Expected split(\".\")[-1] or split('.')[-1] for extracting file extension"
    )
