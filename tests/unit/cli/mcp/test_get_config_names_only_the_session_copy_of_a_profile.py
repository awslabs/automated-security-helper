# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config on a client's config never names the operator's profile file.

When a session has bound a profile with ``select_profile`` and asks
``get_config`` about a config it delivered, the bound profile is the trusted
base the delivered config is resolved against. A bound profile that cannot be
loaded refuses the call, and the refusal names a path. That path is the
session's own copy of the profile, which ``select_profile`` materialized in the
session's ``config/`` directory and already returned as ``config_path``; it is
never the file the operator registered with ``--profile``.

A copy that is gone is not an error: ``resolve_session_config_path`` reports no
binding, and the delivered config resolves against the defaults, as for an
unbound session.
"""

from __future__ import annotations

from pathlib import Path

import pytest

SESSION = "session-a"


@pytest.fixture(autouse=True)
def _isolated_session_state(monkeypatch, tmp_path):
    from automated_security_helper.cli.mcp import profile_registry

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()
    yield
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()


@pytest.fixture
def bound(tmp_path):
    """A registered profile, bound to SESSION, and a config the client delivered.

    Returns (the operator's profile file, the session copy select_profile
    returned, the delivered config).
    """
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
    session_copy = Path(selected["config_path"])

    source = tmp_path / "mcp-workspaces" / SESSION / "source"
    source.mkdir(parents=True)
    delivered = source / ".ash.yaml"
    delivered.write_text("project_name: delivered\n", encoding="utf-8")
    return profile, session_copy, delivered


def _get_config(delivered: Path):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    return mcp_get_config(config_path=str(delivered), session_id=SESSION)


def test_the_delivered_config_is_resolved_against_the_bound_profile(bound):
    """Control: the setup reaches the trusted-base path at all."""
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    _, session_copy, delivered = bound

    assert config_is_client_supplied(delivered)
    assert not config_is_client_supplied(session_copy)
    result = _get_config(delivered)
    assert result.get("project_name") == "delivered", result


def test_an_unloadable_bound_profile_names_only_the_session_copy(bound):
    profile, session_copy, delivered = bound
    # Both unloadable, so a resolution that read the operator's file would fail
    # naming it.
    session_copy.write_text("project_name: [unclosed\n", encoding="utf-8")
    profile.write_text("project_name: [unclosed\n", encoding="utf-8")

    result = _get_config(delivered)

    assert result["success"] is False, result
    assert result["error_category"] == "invalid_format"
    text = str(result)
    assert session_copy.as_posix() in text, text
    assert str(profile) not in text
    assert profile.parent.name not in text


def test_a_bound_profile_copy_that_is_gone_is_no_binding(bound):
    _, session_copy, delivered = bound
    session_copy.unlink()

    result = _get_config(delivered)

    assert result.get("project_name") == "delivered", result
