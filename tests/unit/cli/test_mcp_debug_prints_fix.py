"""Regression test: get_scan_summary has no debug prints to stderr (L1)."""

import io
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_get_scan_summary_does_not_print_debug_to_stderr():
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
            await mcp_server.get_scan_summary(
                ctx=ctx,
                output_dir=str(Path(tempfile.gettempdir()) / "nonexistent"),
            )
    finally:
        sys.stderr = original_stderr

    stderr_output = captured.getvalue()
    assert "DEBUG:" not in stderr_output
    assert "get_scan_summary FUNCTION CALLED" not in stderr_output
    assert "=" * 80 not in stderr_output
