#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan target above the shared workspace root is refused however it is reached.

The gate refuses a target the shared workspace root is inside (its parent, the
home directory, a tree granted above it), because a scan of it would read every
session's delivered source. A link that leads to such a directory is not the
exact text of the root's parent, so it is judged by the path it resolves to, and
must meet the same refusal as the plain spelling.
"""

from __future__ import annotations

import os

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

CONTAINS = "contains the MCP session workspace area"


@pytest.fixture(autouse=True)
def _workspace_root_under_tmp_path(monkeypatch, tmp_path):
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, raising=False)
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "home" / "mcp"))


def _shared_root():
    source = session_sandbox(OWN).source_dir
    source.mkdir(parents=True, exist_ok=True)
    shared = shared_workspace_root()
    assert shared is not None
    return shared


def test_a_link_to_the_parent_is_refused(tmp_path):
    """The link is resolved, and what it leads to is the parent of the root."""
    shared = _shared_root()
    link = tmp_path / "up"
    link.symlink_to(shared.parent, target_is_directory=True)

    refusal = validate_scan_target_in_sandbox(link, session_id=OWN)

    assert refusal is not None, f"{link} leads to a directory holding every session"
    assert CONTAINS in str(refusal)
    assert refusal.context["directory_path"] == str(link)
    assert refusal.context["resolved_path"] == os.path.realpath(shared.parent)


def test_a_link_to_a_directory_beside_the_root_is_not_taken_for_the_parent(
    monkeypatch, tmp_path
):
    """Control: a link whose target holds nothing of the root is judged as before.

    The directory is granted, since a caller with a session id is a network caller
    that reaches a directory outside its own sandbox only through the grant; what
    admits it is the gate not firing.
    """
    _shared_root()
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    link = tmp_path / "to-checkout"
    link.symlink_to(checkout, target_is_directory=True)
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(checkout))

    assert validate_scan_target_in_sandbox(link, session_id=OWN) is None
