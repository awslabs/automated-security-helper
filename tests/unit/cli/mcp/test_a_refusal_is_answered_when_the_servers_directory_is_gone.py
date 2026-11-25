# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A sandbox refusal is still a refusal when the server's working directory was deleted.

Every refusal in the sandbox carries a context that named ``Path.cwd()``, and
``os.getcwd`` raises ``FileNotFoundError`` once the directory the server was
started in is gone. With it gone, every refusal (sibling session, config
directory, grant, denylist) raised instead of returning, so a remote caller that
named a forbidden path was answered with an internal error, not the
``INVALID_PATH`` refusal it was owed. The codebase handles a deleted working
directory on purpose elsewhere; the refusal context now does too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config import mcp_sandbox

pytestmark = pytest.mark.unit


def _the_working_directory_is_gone(monkeypatch):
    def cwd():
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(Path, "cwd", staticmethod(cwd))


def test_control_the_context_names_the_working_directory():
    context = mcp_sandbox._refusal_context("/x", Path("/x"))

    assert context["cwd"] == str(Path.cwd())
    assert context["directory_path"] == "/x"


def test_the_context_is_built_when_the_working_directory_is_gone(monkeypatch):
    """Red at the base: ``FileNotFoundError`` from the context."""
    _the_working_directory_is_gone(monkeypatch)

    context = mcp_sandbox._refusal_context("/x", Path("/x"))

    assert context["cwd"] == "<unavailable>"
    assert context["resolved_path"] == str(Path("/x"))
    assert context["error_category"]


def test_a_forbidden_target_is_refused_not_raised_with_the_directory_gone(
    tmp_path, monkeypatch
):
    from automated_security_helper.cli.mcp.scan_target import validate_scan_target

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(allowed))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    _the_working_directory_is_gone(monkeypatch)

    refusal = validate_scan_target(outside)

    assert refusal is not None
