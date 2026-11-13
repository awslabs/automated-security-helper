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

A copy that is gone is not an error, and not the end of the binding either:
``resolve_session_config_path`` writes the bound profile's file again from the
registered profile, and that file is the trusted base the delivered config is
checked against, as it was before the copy went. The base gives the delivered
file its grants, not its values: a delivered file replaces the profile rather
than overlaying it (``client_config_policy``, "Rejected alternatives"), so a
field the file leaves out returns to its default. (A profile that is no longer
registered, or a workspace that cannot be written, is the session's own
refusal; the tests at the end pin those.)
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SESSION = "session-a"


def _default_threshold() -> str:
    from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL

    return ASH_DEFAULT_SEVERITY_LEVEL


#: The profile's threshold: never the default's, whatever the environment sets
#: it to, so the answer cannot match both.
_PROFILE_THRESHOLD = "LOW" if _default_threshold() == "CRITICAL" else "CRITICAL"


@pytest.fixture(autouse=True)
def _isolated_session_state(monkeypatch, tmp_path):
    from automated_security_helper.cli.mcp import profile_registry

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    yield
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()


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
    # A field the delivered config does not set, and a value that is not the
    # default's: the rewritten copy's text shows the profile was written again,
    # and the answer shows which of the two the delivered config resolved to.
    profile.write_text(
        "project_name: strict-profile\n"
        f"global_settings:\n  severity_threshold: {_PROFILE_THRESHOLD}\n",
        encoding="utf-8",
    )
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


def test_a_bound_profile_copy_that_is_gone_is_written_again(bound):
    """The copy is gone while the profile stays registered: the call writes it
    again and resolves the delivered config against it. ``project_name`` alone
    could not tell a rewritten base from the defaults (the delivered file sets
    it either way); the profile's threshold can.

    The answer's threshold is pinned to the default itself, not to "anything
    but the profile's". This test used to expect the profile's threshold; that
    expectation failed on a correct answer, because a delivered file replaces
    the profile, and the decision recorded for it is that the answer is the
    default (the value ``ASH_DEFAULT_SEVERITY_LEVEL`` gives the field)."""
    _, session_copy, delivered = bound
    session_copy.unlink()

    result = _get_config(delivered)

    assert result.get("project_name") == "delivered", result
    assert session_copy.is_file(), "the bound profile's copy was not written again"
    assert re.search(
        rf"severity_threshold:\s*['\"]?{_PROFILE_THRESHOLD}",
        session_copy.read_text("utf-8"),
    ), "the rewritten copy does not hold the profile's threshold"
    assert result["global_settings"]["severity_threshold"] == _default_threshold(), (
        result
    )


def test_a_bound_profile_that_cannot_be_written_again_is_the_sessions_refusal(
    bound,
):
    """The copy is gone and the profile is no longer registered, so the trusted
    base cannot be written again. That is the session's state, not the delivered
    file's: the answer is the refusal run_ash_scan gives (bound_profile_unavailable,
    exit code 3, naming select_profile), never a load failure that blames the
    file the client asked about, and the delivered file is not named as the one
    that could not be loaded."""
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_profile_registry,
    )

    _, session_copy, delivered = bound
    session_copy.unlink()
    clear_profile_registry()

    result = _get_config(delivered)

    assert result["success"] is False, result
    assert result["error_type"] == "bound_profile_unavailable", result
    assert result["exit_code"] == 3, result
    assert "select_profile" in result["error"], result
    assert "cannot be loaded" not in result["error"], result
    assert delivered.as_posix() not in result["error"], result


def test_a_bound_profile_gone_while_the_workspace_is_being_removed_is_busy(bound):
    """The copy is gone and another request holds the session's workspace (its
    removal), so the trusted base is not written again under that removal: the
    answer is the hold's own refusal, as select_profile gives it, never a load
    failure of the delivered file and never an internal error."""
    from automated_security_helper.cli.mcp.sessions import get_default_registry

    _, session_copy, delivered = bound
    session_copy.unlink()
    session = get_default_registry().session_for(SESSION)
    assert session.try_begin_change() is None
    try:
        result = _get_config(delivered)
    finally:
        session.end_change()

    assert result["success"] is False, result
    assert result["error_type"] == "session_workspace_busy", result
    # The refusal carries the exit code every refusal of this tool carries.
    assert result["exit_code"] == 1, result
    assert result["exit_code_meaning"], result
    assert not session_copy.exists(), "the profile was written under the removal"
