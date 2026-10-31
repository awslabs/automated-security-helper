# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config answers the workspace hold as a refusal with its exit code.

A config the client delivered is resolved against the session's bound profile,
written again when its copy is gone. While another request holds the session's
workspace (the TTL sweep removing it, a clear, the end of the session) the copy
is not written again under that removal, and the call is refused with
``error_type`` ``session_workspace_busy``. The other refusals of the tool carry
``exit_code`` and ``exit_code_meaning``; this one did not, and named its type
by a constant instead of the error's own.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SESSION = "session-held"


@pytest.fixture(autouse=True)
def _isolated_session_state(monkeypatch, tmp_path):
    from automated_security_helper.cli.mcp import profile_registry, sessions

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    sessions.reset_default_registry_for_tests()
    yield
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    sessions.reset_default_registry_for_tests()


@pytest.fixture
def delivered(tmp_path) -> Path:
    """A registered profile bound to SESSION with its copy removed, and a
    config the client delivered. Returns the delivered config."""
    from automated_security_helper.cli.mcp.profile_registry import (
        register_profiles,
        set_profile_registry,
    )
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    operator_dir = tmp_path / "operator-profiles"
    operator_dir.mkdir()
    profile = operator_dir / "strict.ash.yaml"
    profile.write_text("project_name: strict-profile\n", encoding="utf-8")
    set_profile_registry(register_profiles([f"strict={profile}"]))
    selected = mcp_select_profile("strict", session_id=SESSION)
    assert selected["success"] is True, selected
    Path(selected["config_path"]).unlink()

    source = tmp_path / "mcp-workspaces" / SESSION / "source"
    source.mkdir(parents=True)
    config = source / ".ash.yaml"
    config.write_text("project_name: delivered\n", encoding="utf-8")
    return config


def test_the_hold_is_refused_with_the_internal_refusal_exit_code(delivered) -> None:
    """Red at the base: the answer had no exit_code or exit_code_meaning."""
    from automated_security_helper.cli.mcp.sessions import get_default_registry
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    session = get_default_registry().session_for(SESSION)
    assert session.try_begin_change() is None
    try:
        result = mcp_get_config(config_path=str(delivered), session_id=SESSION)
    finally:
        session.end_change()

    assert result["success"] is False, result
    assert result["error_type"] == "session_workspace_busy", result
    assert result["operation"] == "get_config", result
    assert result["exit_code"] == 1, result
    assert result["exit_code_meaning"], result


def test_the_busy_type_is_the_errors_own() -> None:
    """The answer reads ``error_type`` off the exception it caught, so a type the
    error carries is the type the client is told."""
    from automated_security_helper.cli.mcp.sessions import (
        SESSION_WORKSPACE_BUSY,
        SessionWorkspaceBusyError,
    )

    assert SessionWorkspaceBusyError("held").error_type == SESSION_WORKSPACE_BUSY
