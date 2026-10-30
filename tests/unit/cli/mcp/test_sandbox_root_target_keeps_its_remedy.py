#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The filesystem root as a scan target keeps its own remedy.

A target of ``/`` (or a drive root) is reached most often by omitting the
directory, so its refusal tells the caller to pass the directory explicitly.
That judgment runs before the session workspace gate, which would otherwise
describe the root as a tree that contains the workspace area.

The workspace gate itself refuses an ancestor of the workspace root by path,
whether or not the root is on disk yet, and its remedy names the setting that
moves the workspace area, since no grant admits such a target.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.sandbox import (
    ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
    ASH_MCP_ALLOWED_ROOTS_ENV,
    ASH_MCP_TRANSPORT_ENV,
    ASH_MCP_WORKSPACE_ROOT_ENV,
    _sibling_refusal,
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


def test_a_home_above_a_workspace_root_not_yet_on_disk_is_refused_by_path(
    tmp_path,
):
    """The root is judged by path: a home above a root not yet created is refused
    as one above a created root is, and with the same remedy."""
    home = tmp_path / "home"
    home.mkdir()
    shared = shared_workspace_root()
    assert shared is not None
    assert not shared.exists()

    refusal = _sibling_refusal(session_sandbox(OWN), home, home.resolve())

    assert refusal is not None
    message = str(refusal)
    assert ASH_MCP_WORKSPACE_ROOT_ENV in message, message
    assert "permitted roots" not in message, message
    assert refusal.context["resolved_path"] == str(home.resolve())


def test_a_home_above_an_existing_workspace_root_names_the_root_setting(tmp_path):
    """Root on disk: the home is refused, and the remedy names the setting that
    moves the workspace area, not the one that grants roots."""
    _delivered(OWN)
    home = tmp_path / "home"
    assert home.is_dir()

    refusal = _sibling_refusal(session_sandbox(OWN), home, home.resolve())

    assert refusal is not None
    message = str(refusal)
    assert ASH_MCP_WORKSPACE_ROOT_ENV in message, message
    assert "permitted roots" not in message, message
    assert refusal.context["resolved_path"] == str(home.resolve())
