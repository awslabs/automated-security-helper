# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Stub out the `mcp` package before any test module in this directory is collected,
so that modules importing `mcp.server.fastmcp` can be imported in the test venv
even when the real `mcp` package is not installed.
"""

import sys
import types
from unittest.mock import MagicMock


def _install_mcp_stub() -> None:
    if "mcp.server.fastmcp" in sys.modules:
        return

    class _FakeContext:
        pass

    fastmcp_mod = types.ModuleType("mcp.server.fastmcp")
    fastmcp_mod.Context = _FakeContext  # type: ignore[attr-defined]
    fastmcp_mod.FastMCP = MagicMock()  # type: ignore[attr-defined]

    server_mod = types.ModuleType("mcp.server")
    server_mod.fastmcp = fastmcp_mod  # type: ignore[attr-defined]

    mcp_mod = sys.modules.get("mcp") or types.ModuleType("mcp")
    mcp_mod.server = server_mod  # type: ignore[attr-defined]

    sys.modules.setdefault("mcp", mcp_mod)
    sys.modules["mcp.server"] = server_mod
    sys.modules["mcp.server.fastmcp"] = fastmcp_mod


_install_mcp_stub()
