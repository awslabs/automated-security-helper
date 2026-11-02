# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config tells an unregistered profile from a workspace that cannot be written.

``get_config`` on a config the client delivered resolves it against the
session's bound profile, written again when its copy is gone. The write can
fail for two reasons, and ``run_ash_scan`` already answers them apart: the
profile is no longer registered, which is a config refusal (exit 3), or the
session's workspace cannot be written, which is the server's own failure
(exit 1, the cause's category, a warning for the operator). ``get_config``
answered both as the config refusal and logged nothing, so a workspace
permission read as the caller's own fault.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

SESSION = "session-b"


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
    """A registered profile bound to SESSION, its copy removed, and a delivered config.

    Returns (the session copy select_profile returned, the delivered config).
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
    session_copy.unlink()

    source = tmp_path / "mcp-workspaces" / SESSION / "source"
    source.mkdir(parents=True)
    delivered = source / ".ash.yaml"
    delivered.write_text("project_name: delivered\n", encoding="utf-8")
    return session_copy, delivered


def _get_config(delivered: Path):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    return mcp_get_config(config_path=str(delivered), session_id=SESSION)


def test_a_workspace_that_cannot_be_written_is_the_servers_failure(
    bound, monkeypatch, caplog
):
    """Red at the base: answered as the config refusal, exit 3, file_not_found,
    with nothing logged."""
    from automated_security_helper.cli.mcp import profile_registry

    _, delivered = bound

    def cannot_write(sid, config, patched):
        raise PermissionError(13, "Permission denied", "config")

    monkeypatch.setattr(profile_registry, "materialize_session_binding", cannot_write)

    with caplog.at_level(logging.WARNING, logger=ASH_LOGGER.name):
        result = _get_config(delivered)

    assert result["success"] is False, result
    assert result["error_type"] == "bound_profile_unavailable", result
    assert result["exit_code"] == 1, result
    assert result["error_category"] == "permission_denied", result
    assert "Permission denied" in result["error"], result
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("could not be written" in text for text in warnings), warnings


def test_a_writer_failure_that_is_not_a_permission_is_unexpected(bound, monkeypatch):
    """The category follows the cause: an OSError that is not a PermissionError
    is the unexpected kind, still the server's failure."""
    from automated_security_helper.cli.mcp import profile_registry

    _, delivered = bound

    def cannot_write(sid, config, patched):
        raise OSError(28, "No space left on device", "config")

    monkeypatch.setattr(profile_registry, "materialize_session_binding", cannot_write)

    result = _get_config(delivered)

    assert result["success"] is False, result
    assert result["error_type"] == "bound_profile_unavailable", result
    assert result["exit_code"] == 1, result
    assert result["error_category"] == "unexpected_error", result


def test_an_unregistered_profile_keeps_the_config_refusal(bound):
    """Control: the other cause is unchanged. No chained error, so the profile
    that is no longer registered is still the caller's config refusal, exit 3."""
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_profile_registry,
    )

    _, delivered = bound
    clear_profile_registry()

    result = _get_config(delivered)

    assert result["success"] is False, result
    assert result["error_type"] == "bound_profile_unavailable", result
    assert result["exit_code"] == 3, result
    assert result["error_category"] == "file_not_found", result
