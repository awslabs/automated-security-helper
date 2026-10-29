#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The filesystem root as a scan target keeps its own remedy.

A target of ``/`` (or a drive root) is reached most often by omitting the
directory, so its refusal tells the caller to pass the directory explicitly.
That judgment runs before the session workspace gate, which would otherwise
describe the root as a tree that contains the workspace area.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.sandbox import (
    ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
    ASH_MCP_ALLOWED_ROOTS_ENV,
    ASH_MCP_TRANSPORT_ENV,
    session_sandbox,
    shared_workspace_root,
    validate_scan_target_in_sandbox,
)

pytestmark = pytest.mark.unit

OWN = "session-a"

ROOT_REMEDY = (
    "Pass the directory to scan explicitly; the default is the server's "
    "working directory, which here is the filesystem root."
)


@pytest.fixture(autouse=True)
def _workspace_root_under_tmp_path(monkeypatch, tmp_path):
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, raising=False)
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "home" / "mcp"))


def _delivered(session_id: str) -> Path:
    source = session_sandbox(session_id).source_dir
    source.mkdir(parents=True, exist_ok=True)
    return source


def test_the_filesystem_root_keeps_the_explicit_directory_remedy(tmp_path):
    """The root above an existing workspace root is refused with its own remedy."""
    _delivered(OWN)
    shared = shared_workspace_root()
    assert shared is not None
    filesystem_root = Path(tmp_path.anchor)
    assert filesystem_root.parent == filesystem_root

    refusal = validate_scan_target_in_sandbox(filesystem_root, session_id=OWN)

    assert refusal is not None
    message = str(refusal)
    assert ROOT_REMEDY in message, message
    assert "session workspace" not in message, message
