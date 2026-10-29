# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash mcp`` never runs a tool from inside a scanned tree, whatever the environment.

An MCP client chooses what is scanned, including trees it delivers, so the
operator's opt-in (ASH_ALLOW_IN_TREE_TOOLS) is not honored there. The decision point
is ``cli/mcp_server.MCP_HONORS_IN_TREE_OPT_IN``; both of its values are tested, and
the server is shown to apply it on start, before any transport runs.
"""

from __future__ import annotations

import inspect
import os
import sys

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    find_executable,
    in_tree_refusal,
    scanning_tree,
)

pytestmark = pytest.mark.unit


def _serving_with(serve):
    """``mcp.run_stdio_async`` replaced: the serving is ``serve``, run once."""

    async def run_stdio_async() -> None:
        serve()

    return run_stdio_async


@pytest.fixture
def in_tree_tool(tmp_path, monkeypatch):
    tree = tmp_path / "delivered"
    bin_dir = tree / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    tool = bin_dir / ("tool.exe" if sys.platform == "win32" else "tool")
    tool.write_text("#!/bin/sh\nexit 0\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("ASH_ALLOW_IN_TREE_TOOLS", "1")
    monkeypatch.setattr(
        subprocess_utils, "path_independent_dirs", lambda: [tmp_path / "ash-bin"]
    )
    subprocess_utils.clear_find_executable_cache()
    yield tree, tool
    subprocess_utils.clear_find_executable_cache()


def test_the_server_refuses_in_tree_tools_with_the_opt_in_set(
    in_tree_tool, monkeypatch
):
    tree, _ = in_tree_tool
    seen = {}

    def serve():
        with scanning_tree(tree):
            seen["found"] = find_executable("tool")
            seen["reason"] = in_tree_refusal("tool")

    # run_mcp_server serves through _serve_stdio, which awaits
    # mcp.run_stdio_async; the real transport would read the worker's stdin.
    monkeypatch.setattr(mcp_server.mcp, "run_stdio_async", _serving_with(serve))
    monkeypatch.setattr(mcp_server, "_stdout_is_fd_1", lambda: False)

    mcp_server.run_mcp_server()

    assert seen["found"] is None
    assert "--allow-in-tree-tools" not in seen["reason"], (
        "the reason must not offer an opt-in the server ignores"
    )


@pytest.mark.parametrize("honored", [True, False])
def test_the_decision_point_both_ways(honored, in_tree_tool, monkeypatch):
    tree, tool = in_tree_tool
    monkeypatch.setattr(mcp_server, "MCP_HONORS_IN_TREE_OPT_IN", honored)
    seen = {}

    def serve():
        with scanning_tree(tree):
            seen["found"] = find_executable("tool")

    # run_mcp_server serves through _serve_stdio, which awaits
    # mcp.run_stdio_async; the real transport would read the worker's stdin.
    monkeypatch.setattr(mcp_server.mcp, "run_stdio_async", _serving_with(serve))
    monkeypatch.setattr(mcp_server, "_stdout_is_fd_1", lambda: False)

    mcp_server.run_mcp_server()

    assert seen["found"] == (os.fspath(tool) if honored else None)


def test_every_transport_applies_it_before_starting():
    """``mcp_command`` sets it ahead of every transport's start, not only for stdio."""
    from automated_security_helper.cli import mcp as mcp_package

    source = inspect.getsource(mcp_package.mcp_command)
    applied = source.index("honor_in_tree_opt_in(MCP_HONORS_IN_TREE_OPT_IN)")
    starts = ["run_mcp_server()", "build_streamable_http_app(", "build_sse_app("]
    for start in starts:
        assert applied < source.index(start), start
