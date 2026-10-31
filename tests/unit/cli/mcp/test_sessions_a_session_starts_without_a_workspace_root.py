# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A session is handed out, and ended, while the workspace root cannot be resolved.

``source_delivery.resolve_workspace_root`` raises ``RuntimeError`` on a host with
no home directory and no ``ASH_MCP_WORKSPACE_ROOT``. ``MCPSessionRegistry.session_for``
promises to create nothing on disk, so that a scan of a directory the operator
granted starts anyway; it resolved the session's directory eagerly and let the
error out, so every session-bearing scan failed on such a host. ``get_or_create``,
which does need the directory, resolves it and raises. ``end_session`` cleared
neither the bound profile nor the registry entry there, because the error escaped
the workspace removal's ``except ValueError``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import profile_registry, sessions
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.session_paths import SESSION_MARKER
from automated_security_helper.cli.mcp.sessions import MCPSessionRegistry
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit

SESSION = "granted-scan"


def _no_root_can_be_resolved() -> Path:
    raise RuntimeError("a planted host with no home directory")


@pytest.fixture
def no_root(monkeypatch):
    monkeypatch.setattr(sd, "resolve_workspace_root", _no_root_can_be_resolved)
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    profile_registry.clear_all_session_state()
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()
    yield
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()
    profile_registry.clear_all_session_state()


def test_session_for_hands_out_a_session_with_no_workspace_root(no_root) -> None:
    registry = MCPSessionRegistry()

    session = registry.session_for(SESSION)

    assert session.workspace_root is None
    assert session.try_claim_scan()
    session.release_scan()
    assert registry.session_for(SESSION) is session


def test_get_or_create_raises_what_resolving_the_root_raised(no_root) -> None:
    registry = MCPSessionRegistry()
    registry.session_for(SESSION)

    with pytest.raises(RuntimeError, match="no home directory"):
        registry.get_or_create(SESSION)


def test_get_or_create_fills_in_the_workspace_once_the_root_resolves(
    no_root, tmp_path, monkeypatch
) -> None:
    registry = MCPSessionRegistry()
    session = registry.session_for(SESSION)
    assert session.workspace_root is None, "control: the root resolved too early"
    root = tmp_path / "ws"
    monkeypatch.setattr(sd, "resolve_workspace_root", lambda: root)

    created = registry.get_or_create(SESSION)

    assert created is session
    assert session.workspace_root == root / SESSION
    assert (session.workspace_root / SESSION_MARKER).is_file()


def test_ending_a_session_clears_its_profile_and_entry_with_no_root(no_root) -> None:
    registry = sessions.get_default_registry()
    registry.session_for(SESSION)
    profile_registry.bind_session_config(
        SESSION, config=AshConfig(), profile_name="strict"
    )
    assert profile_registry.session_has_binding(SESSION), "control: not bound"

    ended = sessions.end_session(SESSION)

    assert ended is True
    assert not profile_registry.session_has_binding(SESSION)
    assert registry.get(SESSION) is None
