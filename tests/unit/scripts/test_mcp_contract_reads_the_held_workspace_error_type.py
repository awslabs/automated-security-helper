# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP contract reader reads the error type of a held session workspace.

Why this file exists
--------------------
``resolve_ash_workspace`` and ``run_ash_workspace_scan`` answer a session
workspace that another request holds for the sweep's removal as a hold, under
``session_workspace_busy`` with exit 1. The helper that builds that answer took
the type from an attribute of its own parameter (``error.error_type``).
``scripts/_mcp_contract.py`` reads an ``error_type`` from a string constant, an
enum value, a class name or the attribute of a caught exception inside an
``except`` handler. An attribute of a function parameter is none of these, so the
reader reported the site as unread, ``generate_mcp_tool_reference.py --check``
exited 1 naming the line, and the generated tool reference could not be
refreshed.

What it pins
------------
Run on the source of this checkout, the reader lists ``session_workspace_busy``
among both workspace tools' error types and reports no unread error type for
either. Nothing is executed: the reader parses the source.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"

WORKSPACE_TOOLS = ("resolve_ash_workspace", "run_ash_workspace_scan")
HELD_WORKSPACE_ERROR_TYPE = "session_workspace_busy"


@pytest.fixture(scope="module")
def contracts(script_loader):
    return script_loader("_mcp_contract").tool_contracts(PACKAGE)


@pytest.mark.parametrize("tool", WORKSPACE_TOOLS)
def test_the_held_workspace_error_type_is_read_for_each_workspace_tool(
    contracts, tool: str
):
    contract = contracts[tool]
    assert HELD_WORKSPACE_ERROR_TYPE in contract.error_types, (
        f"{tool} lists {contract.error_types}"
    )


@pytest.mark.parametrize("tool", WORKSPACE_TOOLS)
def test_no_error_type_of_a_workspace_tool_is_left_unread(contracts, tool: str):
    assert contracts[tool].error_types_unread == ()
