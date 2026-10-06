# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every registered MCP tool has result snapshots, and no snapshot names a ghost.

Read from the stored snapshots rather than from a list kept in this file. Every
result snapshot is a ``record()``, which stores the tool's name under ``'tool'``,
so the set of names in tests/snapshot/mcp/__snapshots__/*.ambr is the set of tools
whose results are actually pinned. A hand-kept list would drift the way README's
tool table once did (see tests/unit/cli/mcp/test_tool_surface_parity.py): a new
``@mcp.tool()`` would ship with its results unpinned and nothing would say so.

The other direction catches a tool that was removed or renamed while its
snapshots were left behind. syrupy reports an unused snapshot too, but only on a
run that collects the whole module; this check does not depend on that.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

SNAPSHOT_DIR = Path(__file__).resolve().parent / "__snapshots__"

# Amber renders a record's name line as `    'tool': 'run_ash_scan',`.
_TOOL_LINE = re.compile(r"^\s*'tool': '([a-z_][a-z0-9_]*)',$", re.MULTILINE)


def _snapshotted_tools() -> dict:
    found: dict = {}
    for path in sorted(SNAPSHOT_DIR.glob("*.ambr")):
        for name in _TOOL_LINE.findall(path.read_text(encoding="utf-8")):
            found[name] = found.get(name, 0) + 1
    return found


def _registered_tools() -> set:
    from automated_security_helper.cli.mcp_server import mcp

    return {tool.name for tool in asyncio.run(mcp.list_tools())}


def test_the_snapshot_directory_is_read():
    """Guard the guard: an empty or moved snapshot directory reads as zero tools."""
    assert len(_snapshotted_tools()) >= 14, (
        f"Found result snapshots for {sorted(_snapshotted_tools())} in "
        f"{SNAPSHOT_DIR}. If the snapshots moved or record() changed shape, fix "
        "SNAPSHOT_DIR or _TOOL_LINE here rather than deleting this check."
    )


def test_every_registered_tool_has_result_snapshots():
    missing = _registered_tools() - set(_snapshotted_tools())
    assert not missing, (
        f"These MCP tools are registered but no result snapshot records them: "
        f"{sorted(missing)}. Add a test under tests/snapshot/mcp that calls each "
        "through cli/mcp_server.py and asserts record(...) == snapshot, covering "
        "its success payload and the refusals a client can trigger."
    )


def test_no_snapshot_records_a_tool_that_is_not_registered():
    ghosts = set(_snapshotted_tools()) - _registered_tools()
    assert not ghosts, (
        f"Result snapshots record tools the server no longer registers: "
        f"{sorted(ghosts)}. Remove or rename those tests and their snapshots."
    )
